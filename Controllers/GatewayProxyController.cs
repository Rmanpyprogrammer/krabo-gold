using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using krabo_gold.Services.Gateway;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace krabo_gold.Controllers;

[ApiController]
[Authorize]
[Route("api/proxy/{service}/{**path}")]
public sealed class GatewayProxyController : ControllerBase
{
    private const int MaxRequestBytes = 1_048_576;       // 1 MB
    private const int MaxResponseBytes = 10_485_760;     // 10 MB

    private readonly IHttpClientFactory _clients;
    private readonly IConfiguration _configuration;
    private readonly ILogger<GatewayProxyController> _logger;

    public GatewayProxyController(
        IHttpClientFactory clients,
        IConfiguration configuration,
        ILogger<GatewayProxyController> logger)
    {
        _clients = clients;
        _configuration = configuration;
        _logger = logger;
    }

    [AcceptVerbs(
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS"
    )]
    public Task Forward(
        string service,
        string? path,
        CancellationToken ct)
        => ForwardCore(service, path, requireUser: true, ct: ct);

    // Public GET follows the same prefix allowlist and backend forwarding logic.
    // It does NOT require or forward a user's JWT identity.
    [AllowAnonymous]
    [HttpGet("~/api/proxy-public/{service}/{**path}")]
    public Task ForwardPublicGet(
        string service,
        string? path,
        CancellationToken ct)
        => ForwardCore(service, path, requireUser: false, ct: ct);

    private async Task ForwardCore(
        string service,
        string? path,
        bool requireUser,
        CancellationToken ct)
    {
        // ---------------------------------------------------------
        // 1. Load backend configuration
        // ---------------------------------------------------------
        var section = _configuration.GetSection($"Backends:{service}");
        var options = section.Get<BackendOptions>();

        if (options is null ||
            string.IsNullOrWhiteSpace(options.BaseUrl) ||
            !Uri.TryCreate(
                options.BaseUrl,
                UriKind.Absolute,
                out var baseUri) ||
            (
                baseUri.Scheme != Uri.UriSchemeHttps &&
                !(
                    HttpContext.RequestServices
                        .GetRequiredService<IHostEnvironment>()
                        .IsDevelopment()
                    &&
                    baseUri.Scheme == Uri.UriSchemeHttp
                )
            ) ||
            string.IsNullOrWhiteSpace(options.ServiceToken))
        {
            Response.StatusCode = StatusCodes.Status404NotFound;

            await Response.WriteAsJsonAsync(
                new
                {
                    error = "backend_not_found"
                },
                ct
            );

            return;
        }


        // ---------------------------------------------------------
        // 2. Get authenticated user id from JWT
        // ---------------------------------------------------------
        string? userId = null;

        if (requireUser)
        {
            userId =
                User.FindFirstValue(ClaimTypes.NameIdentifier)
                ?? User.FindFirstValue("sub")
                ?? User.FindFirstValue("user_id");

            if (string.IsNullOrWhiteSpace(userId))
            {
                Response.StatusCode = StatusCodes.Status401Unauthorized;

                await Response.WriteAsJsonAsync(
                    new { error = "user_id_missing" }, ct);

                return;
            }
        }


        // ---------------------------------------------------------
        // 3. Normalize requested proxy path
        //
        // Swagger may send:
        // api%2Fwallet
        //
        // We normalize it to:
        // api/wallet
        // ---------------------------------------------------------
        var rawPath = (path ?? string.Empty)
            .Trim()
            .TrimStart('/');

        string relative;

        try
        {
            relative = Uri
                .UnescapeDataString(rawPath)
                .Trim()
                .TrimStart('/');
        }
        catch
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;

            await Response.WriteAsJsonAsync(
                new
                {
                    error = "invalid_path_encoding"
                },
                ct
            );

            return;
        }


        // ---------------------------------------------------------
        // 4. Validate path
        // ---------------------------------------------------------
        if (string.IsNullOrWhiteSpace(relative) ||
            relative.Contains(
                "..",
                StringComparison.Ordinal) ||
            relative.Contains('\\') ||
            relative.StartsWith(
                "//",
                StringComparison.Ordinal))
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;

            await Response.WriteAsJsonAsync(
                new
                {
                    error = "invalid_path"
                },
                ct
            );

            return;
        }


        // ---------------------------------------------------------
        // 5. Check AllowedPathPrefixes
        //
        // Config:
        // "AllowedPathPrefixes": [
        //     "api/"
        // ]
        //
        // Allows:
        // api/wallet
        // api/orders
        // api/orders/123
        //
        // Rejects:
        // admin/users
        // private/test
        // ---------------------------------------------------------
        var pathOnly = "/" + relative;

        if (options.AllowedPathPrefixes is null ||
            options.AllowedPathPrefixes.Length == 0 ||
            !options.AllowedPathPrefixes.Any(prefixValue =>
            {
                if (string.IsNullOrWhiteSpace(prefixValue))
                    return false;

                var prefix =
                    "/" + prefixValue.Trim().Trim('/');

                return pathOnly.Equals(
                           prefix,
                           StringComparison.OrdinalIgnoreCase)
                       ||
                       pathOnly.StartsWith(
                           prefix + "/",
                           StringComparison.OrdinalIgnoreCase);
            }))
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;

            await Response.WriteAsJsonAsync(
                new
                {
                    error = "proxy_path_forbidden",
                    path = relative
                },
                ct
            );

            return;
        }


        // ---------------------------------------------------------
        // 6. HTTP method
        // ---------------------------------------------------------
        var method = new HttpMethod(Request.Method);

        var hasBody =
            method == HttpMethod.Post ||
            method == HttpMethod.Put ||
            method.Method.Equals(
                "PATCH",
                StringComparison.OrdinalIgnoreCase);


        // ---------------------------------------------------------
        // 7. Read and validate request body
        // ---------------------------------------------------------
        HttpContent? content = null;

        if (hasBody)
        {
            if (Request.ContentLength is > MaxRequestBytes)
            {
                Response.StatusCode =
                    StatusCodes.Status413PayloadTooLarge;

                await Response.WriteAsJsonAsync(
                    new
                    {
                        error = "request_too_large"
                    },
                    ct
                );

                return;
            }

            if (Request.ContentLength is > 0)
            {
                var contentType =
                    Request.ContentType?
                        .Split(';')[0]
                        .Trim();

                if (!string.Equals(
                        contentType,
                        "application/json",
                        StringComparison.OrdinalIgnoreCase))
                {
                    Response.StatusCode =
                        StatusCodes.Status415UnsupportedMediaType;

                    await Response.WriteAsJsonAsync(
                        new
                        {
                            error = "json_content_type_required"
                        },
                        ct
                    );

                    return;
                }
            }

            using var ms = new MemoryStream();

            var buffer = new byte[81920];

            int read;

            while ((read =
                       await Request.Body.ReadAsync(
                           buffer,
                           ct)) > 0)
            {
                if (ms.Length + read > MaxRequestBytes)
                {
                    Response.StatusCode =
                        StatusCodes.Status413PayloadTooLarge;

                    await Response.WriteAsJsonAsync(
                        new
                        {
                            error = "request_too_large"
                        },
                        ct
                    );

                    return;
                }

                await ms.WriteAsync(
                    buffer.AsMemory(0, read),
                    ct
                );
            }

            var bytes = ms.ToArray();

            if (bytes.Length > 0)
            {
                try
                {
                    using var _ = JsonDocument.Parse(
                        bytes,
                        new JsonDocumentOptions
                        {
                            MaxDepth = 32,
                            CommentHandling =
                                JsonCommentHandling.Disallow,
                            AllowTrailingCommas = false
                        }
                    );
                }
                catch (JsonException)
                {
                    Response.StatusCode =
                        StatusCodes.Status400BadRequest;

                    await Response.WriteAsJsonAsync(
                        new
                        {
                            error = "invalid_json_body"
                        },
                        ct
                    );

                    return;
                }

                content = new ByteArrayContent(bytes);

                content.Headers.ContentType =
                    new MediaTypeHeaderValue(
                        "application/json"
                    );
            }
        }


        // ---------------------------------------------------------
        // 8. Build backend URL
        //
        // BaseUrl:
        // https://python.krabo.gold
        //
        // relative:
        // api/wallet
        //
        // Result:
        // https://python.krabo.gold/api/wallet
        // ---------------------------------------------------------
        var baseUrl =
            options.BaseUrl.TrimEnd('/');

        var targetUrl =
            $"{baseUrl}/{relative}{Request.QueryString}";

        if (!Uri.TryCreate(
                targetUrl,
                UriKind.Absolute,
                out var target))
        {
            Response.StatusCode =
                StatusCodes.Status400BadRequest;

            await Response.WriteAsJsonAsync(
                new
                {
                    error = "invalid_target_url"
                },
                ct
            );

            return;
        }


        // ---------------------------------------------------------
        // 9. Create upstream request
        // ---------------------------------------------------------
        using var message =
            new HttpRequestMessage(
                method,
                target
            )
            {
                Content = content
            };


        // ---------------------------------------------------------
        // 10. Forward safe request headers
        // ---------------------------------------------------------
        foreach (var header in new[]
                 {
                     "Accept",
                     "If-Match",
                     "If-None-Match"
                 })
        {
            if (Request.Headers.TryGetValue(
                    header,
                    out var values))
            {
                message.Headers.TryAddWithoutValidation(
                    header,
                    values.ToArray()
                );
            }
        }


        // ---------------------------------------------------------
        // 11. Add trusted Gateway headers
        //
        // These values are NOT taken from frontend.
        // ---------------------------------------------------------
        message.Headers.Remove(
            "X-Gateway-Service-Token");

        message.Headers.Remove(
            "X-Gateway-User-Id");

        message.Headers.Remove(
            "X-User-Id");

        message.Headers.Remove(
            "USER_ID");


        message.Headers.TryAddWithoutValidation(
            "X-Gateway-Service-Token",
            options.ServiceToken
        );

        if (requireUser && userId is not null)
        {
            message.Headers.TryAddWithoutValidation(
                "X-Gateway-User-Id",
                userId
            );

            message.Headers.TryAddWithoutValidation(
                "X-User-Id",
                userId
            );

            message.Headers.TryAddWithoutValidation(
                "USER_ID",
                userId
            );

            // -----------------------------------------------------
            // 12. Add mobile if present in JWT
            // -----------------------------------------------------
            var mobile = User.FindFirstValue(ClaimTypes.MobilePhone);

            if (!string.IsNullOrWhiteSpace(mobile))
            {
                message.Headers.TryAddWithoutValidation(
                    "X-Gateway-User-Mobile",
                    mobile
                );
            }
        }


        // ---------------------------------------------------------
        // 13. Gateway request id
        // ---------------------------------------------------------
        var requestId =
            HttpContext.TraceIdentifier;

        message.Headers.TryAddWithoutValidation(
            "X-Gateway-Request-Id",
            requestId
        );

        Response.Headers[
            "X-Gateway-Request-Id"
        ] = requestId;


        _logger.LogInformation(
            "Proxying {Method} request. Service: {Service}, Path: {Path}, Target: {Target}",
            Request.Method,
            service,
            relative,
            target
        );


        try
        {
            // -----------------------------------------------------
            // 14. Send request to backend
            // -----------------------------------------------------
            using var upstream =
                await _clients
                    .CreateClient(
                        "GatewayBackend")
                    .SendAsync(
                        message,
                        HttpCompletionOption
                            .ResponseHeadersRead,
                        ct
                    );


            // -----------------------------------------------------
            // 15. Check backend response size
            // -----------------------------------------------------
            if (upstream.Content.Headers.ContentLength
                is > MaxResponseBytes)
            {
                Response.StatusCode =
                    StatusCodes.Status502BadGateway;

                await Response.WriteAsJsonAsync(
                    new
                    {
                        error =
                            "backend_response_too_large"
                    },
                    ct
                );

                return;
            }


            // -----------------------------------------------------
            // 16. Return backend HTTP status to frontend
            //
            // Backend 200 -> frontend 200
            // Backend 400 -> frontend 400
            // Backend 404 -> frontend 404
            // Backend 500 -> frontend 500
            // -----------------------------------------------------
            Response.StatusCode =
                (int)upstream.StatusCode;


            // -----------------------------------------------------
            // 17. Return backend content-type
            // -----------------------------------------------------
            if (upstream.Content.Headers.ContentType
                is not null)
            {
                Response.ContentType =
                    upstream.Content.Headers
                        .ContentType
                        .ToString();
            }


            // -----------------------------------------------------
            // 18. Forward safe response headers
            // -----------------------------------------------------
            CopyResponseHeader(
                upstream,
                "Cache-Control");

            CopyResponseHeader(
                upstream,
                "ETag");

            CopyResponseHeader(
                upstream,
                "Last-Modified");

            CopyResponseHeader(
                upstream,
                "Retry-After");

            CopyResponseHeader(
                upstream,
                "Location");

            CopyResponseHeader(
                upstream,
                "Content-Disposition");


            // -----------------------------------------------------
            // 19. HEAD / 204 have no body
            // -----------------------------------------------------
            if (method == HttpMethod.Head ||
                upstream.StatusCode ==
                HttpStatusCode.NoContent)
            {
                return;
            }


            // -----------------------------------------------------
            // 20. Stream backend response directly to frontend
            // -----------------------------------------------------
            await using var stream =
                await upstream.Content
                    .ReadAsStreamAsync(ct);

            var bufferOut =
                new byte[81920];

            int n;

            long total = 0;

            while ((n =
                       await stream.ReadAsync(
                           bufferOut,
                           ct)) > 0)
            {
                total += n;

                if (total > MaxResponseBytes)
                {
                    if (!Response.HasStarted)
                    {
                        Response.StatusCode =
                            StatusCodes
                                .Status502BadGateway;

                        await Response
                            .WriteAsJsonAsync(
                                new
                                {
                                    error =
                                        "backend_response_too_large"
                                },
                                ct
                            );
                    }
                    else
                    {
                        HttpContext.Abort();
                    }

                    return;
                }

                await Response.Body.WriteAsync(
                    bufferOut.AsMemory(
                        0,
                        n),
                    ct
                );
            }
        }
        catch (OperationCanceledException)
            when (!ct.IsCancellationRequested)
        {
            _logger.LogWarning(
                "Backend proxy request timed out. Service: {Service}, Target: {Target}",
                service,
                target
            );

            if (!Response.HasStarted)
            {
                Response.StatusCode =
                    StatusCodes.Status504GatewayTimeout;

                await Response.WriteAsJsonAsync(
                    new
                    {
                        error = "backend_timeout"
                    },
                    CancellationToken.None
                );
            }
        }
        catch (OperationCanceledException)
            when (ct.IsCancellationRequested)
        {
            // Client disconnected/cancelled.
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(
                ex,
                "Backend proxy request failed. Service: {Service}, Target: {Target}",
                service,
                target
            );

            if (!Response.HasStarted)
            {
                Response.StatusCode =
                    StatusCodes.Status502BadGateway;

                await Response.WriteAsJsonAsync(
                    new
                    {
                        error = "backend_unavailable"
                    },
                    ct
                );
            }
        }
    }


    private void CopyResponseHeader(
        HttpResponseMessage upstream,
        string name)
    {
        if (upstream.Headers.TryGetValues(
                name,
                out var values) ||
            upstream.Content.Headers.TryGetValues(
                name,
                out values))
        {
            Response.Headers[name] =
                values.ToArray();
        }
    }
}


