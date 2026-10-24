
using System.Globalization;
using System.Net;
using Microsoft.Extensions.Configuration;
using StackExchange.Redis;

namespace krabo_gold.Middleware;

public sealed class GlobalRateLimitMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<GlobalRateLimitMiddleware> _logger;
    private readonly IDatabase _redis;
    private readonly HashSet<string> _trustedServiceIps;
    private readonly int _limit;

    private const int WindowSeconds = 60;

    private const string IncrementScript = """
        local count = redis.call('INCR', KEYS[1])

        if count == 1 then
            redis.call('EXPIRE', KEYS[1], ARGV[1])
        end

        return count
        """;

    public GlobalRateLimitMiddleware(
        RequestDelegate next,
        IConnectionMultiplexer redis,
        ILogger<GlobalRateLimitMiddleware> logger,
        IConfiguration configuration)
    {
        _next = next;
        _logger = logger;
        _redis = redis.GetDatabase();

        _limit = configuration.GetValue<int>(
            "RateLimiting:RequestsPerMinute", 120);

        if (_limit <= 0)
        {
            throw new InvalidOperationException(
                "RateLimiting:RequestsPerMinute must be greater than zero.");
        }

        var configuredIps = configuration
            .GetSection("RateLimiting:TrustedServiceIps")
            .Get<string[]>() ?? [];

        _trustedServiceIps = configuredIps
            .Select(NormalizeIp)
            .Where(ip => ip.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var remoteAddress = context.Connection.RemoteIpAddress;
        var ip = NormalizeIp(remoteAddress?.ToString());

        if (ip.Length == 0)
        {
            context.Response.StatusCode =
                StatusCodes.Status400BadRequest;

            await context.Response.WriteAsJsonAsync(new
            {
                error = "client_ip_unavailable",
                message = "Client IP address could not be determined."
            });

            return;
        }

        // Trusted service IPs bypass this global IP-based limit.
        // Authentication and authorization are still required.
        if (_trustedServiceIps.Contains(ip))
        {
            await _next(context);
            return;
        }

        var unixSeconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var window = unixSeconds / WindowSeconds;

        var key = $"ratelimit:global:{ip}:{window}";

        long count;

        try
        {
            var result = await _redis.ScriptEvaluateAsync(
                IncrementScript,
                new RedisKey[] { key },
                new RedisValue[] { WindowSeconds });

            count = (long)result;
        }
        catch (RedisException ex)
        {
            _logger.LogError(
                ex,
                "Redis failed while checking global rate limit for {ClientIp}.",
                ip);

            context.Response.StatusCode =
                StatusCodes.Status503ServiceUnavailable;

            await context.Response.WriteAsJsonAsync(new
            {
                error = "rate_limit_service_unavailable",
                message = "Request processing is temporarily unavailable."
            });

            return;
        }

        var remaining = Math.Max(0, _limit - count);

        context.Response.Headers["X-RateLimit-Limit"] =
            _limit.ToString(CultureInfo.InvariantCulture);

        context.Response.Headers["X-RateLimit-Remaining"] =
            remaining.ToString(CultureInfo.InvariantCulture);

        if (count > _limit)
        {
            var secondsUntilNextWindow =
                WindowSeconds -
                (int)(unixSeconds % WindowSeconds);

            context.Response.StatusCode =
                StatusCodes.Status429TooManyRequests;

            context.Response.Headers.RetryAfter =
                secondsUntilNextWindow.ToString(
                    CultureInfo.InvariantCulture);

            await context.Response.WriteAsJsonAsync(new
            {
                error = "rate_limit_exceeded",
                message = "Too many requests. Please try again later.",
                retryAfterSeconds = secondsUntilNextWindow
            });

            return;
        }

        await _next(context);
    }

    private static string NormalizeIp(string? value)
    {
        if (!IPAddress.TryParse(value, out var address))
        {
            return string.Empty;
        }

        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        return address.ToString();
    }
}
