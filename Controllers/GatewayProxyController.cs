using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;
using krabo_gold.Services.Gateway;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace krabo_gold.Controllers;

[ApiController]
[Authorize]
[Route("api/proxy/{service}/{**path}")]
public sealed class GatewayProxyController : ControllerBase
{
    private const int MaxRequestBytes = 1_048_576;
    private const int MaxResponseBytes = 10_485_760;
    private readonly IHttpClientFactory _clients;
    private readonly IConfiguration _configuration;
    private readonly ILogger<GatewayProxyController> _logger;

    public GatewayProxyController(IHttpClientFactory clients, IConfiguration configuration, ILogger<GatewayProxyController> logger)
    { _clients = clients; _configuration = configuration; _logger = logger; }

    [AcceptVerbs("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")]
    public async Task Forward(string service, string? path, CancellationToken ct)
    {
        var section = _configuration.GetSection($"Backends:{service}");
        var options = section.Get<BackendOptions>();
        if (options is null || !Uri.TryCreate(options.BaseUrl, UriKind.Absolute, out var baseUri) ||
            (baseUri.Scheme != Uri.UriSchemeHttps && !(HttpContext.RequestServices.GetRequiredService<IHostEnvironment>().IsDevelopment() && baseUri.Scheme == Uri.UriSchemeHttp)) ||
            string.IsNullOrWhiteSpace(options.ServiceToken))
        { Response.StatusCode = 404; await Response.WriteAsJsonAsync(new { error = "backend_not_found" }, ct); return; }

        var relative = (path ?? string.Empty).TrimStart('/');
        if (relative.Contains("..", StringComparison.Ordinal) || relative.Contains('\\') || relative.StartsWith("//", StringComparison.Ordinal))
        { Response.StatusCode = 400; await Response.WriteAsJsonAsync(new { error = "invalid_path" }, ct); return; }
        var pathOnly = "/" + relative;
        if (options.AllowedPathPrefixes.Length == 0 || !options.AllowedPathPrefixes.Any(p =>
        {
            var prefix = "/" + p.Trim('/');
            return pathOnly.Equals(prefix, StringComparison.OrdinalIgnoreCase) || pathOnly.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase);
        }))
        { Response.StatusCode = 403; await Response.WriteAsJsonAsync(new { error = "proxy_path_forbidden" }, ct); return; }

        var method = new HttpMethod(Request.Method);
        var hasBody = method == HttpMethod.Post || method == HttpMethod.Put || method.Method == "PATCH";
        HttpContent? content = null;
        if (hasBody)
        {
            if (Request.ContentLength is > MaxRequestBytes) { Response.StatusCode = 413; return; }
            if (Request.ContentLength is > 0 && !string.Equals(Request.ContentType?.Split(';')[0].Trim(), "application/json", StringComparison.OrdinalIgnoreCase))
            { Response.StatusCode = 415; await Response.WriteAsJsonAsync(new { error = "json_content_type_required" }, ct); return; }
            using var ms = new MemoryStream();
            var buffer = new byte[81920]; int read;
            while ((read = await Request.Body.ReadAsync(buffer, ct)) > 0)
            {
                if (ms.Length + read > MaxRequestBytes) { Response.StatusCode = 413; return; }
                await ms.WriteAsync(buffer.AsMemory(0, read), ct);
            }
            var bytes = ms.ToArray();
            if (bytes.Length > 0)
            {
                try { using var _ = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32, CommentHandling = JsonCommentHandling.Disallow, AllowTrailingCommas = false }); }
                catch (JsonException) { Response.StatusCode = 400; await Response.WriteAsJsonAsync(new { error = "invalid_json_body" }, ct); return; }
                content = new ByteArrayContent(bytes); content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }
        }

        var target = new Uri(baseUri.ToString().TrimEnd('/') + "/" + relative + Request.QueryString);
        using var message = new HttpRequestMessage(method, target) { Content = content };
        foreach (var header in new[] { "Accept", "If-Match", "If-None-Match" })
            if (Request.Headers.TryGetValue(header, out var values)) message.Headers.TryAddWithoutValidation(header, values.ToArray());
        message.Headers.TryAddWithoutValidation("X-Gateway-Service-Token", options.ServiceToken);
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? User.FindFirstValue("sub");
        if (!string.IsNullOrWhiteSpace(userId)) message.Headers.TryAddWithoutValidation("X-Gateway-User-Id", userId);
        var mobile = User.FindFirstValue(ClaimTypes.MobilePhone);
        if (!string.IsNullOrWhiteSpace(mobile)) message.Headers.TryAddWithoutValidation("X-Gateway-User-Mobile", mobile);
        message.Headers.TryAddWithoutValidation("X-Gateway-Request-Id", HttpContext.TraceIdentifier);

        try
        {
            using var upstream = await _clients.CreateClient("GatewayBackend").SendAsync(message, HttpCompletionOption.ResponseHeadersRead, ct);
            Response.StatusCode = (int)upstream.StatusCode;
            if (upstream.Content.Headers.ContentType is not null) Response.ContentType = upstream.Content.Headers.ContentType.ToString();
            foreach (var header in new[] { "Cache-Control", "ETag", "Last-Modified", "Retry-After" })
                if (upstream.Headers.TryGetValues(header, out var values) || upstream.Content.Headers.TryGetValues(header, out values)) Response.Headers[header] = values.ToArray();
            if (method == HttpMethod.Head || upstream.StatusCode == HttpStatusCode.NoContent) return;
            await using var stream = await upstream.Content.ReadAsStreamAsync(ct);
            var bufferOut = new byte[81920]; int n; long total = 0;
            while ((n = await stream.ReadAsync(bufferOut, ct)) > 0)
            {
                total += n;
                if (total > MaxResponseBytes) { HttpContext.Abort(); return; }
                await Response.Body.WriteAsync(bufferOut.AsMemory(0, n), ct);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "Backend proxy request failed for service {Service}.", service);
            if (!Response.HasStarted) { Response.StatusCode = 502; await Response.WriteAsJsonAsync(new { error = "backend_unavailable" }, ct); }
        }
    }
}
