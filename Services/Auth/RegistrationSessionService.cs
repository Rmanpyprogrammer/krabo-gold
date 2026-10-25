using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using StackExchange.Redis;

namespace krabo_gold.Services.Auth;

public sealed class RegistrationOptions
{
    public int LifetimeSeconds { get; set; } = 600;
}

public sealed record RegistrationSession(string Token, int ExpiresInSeconds);

public interface IRegistrationSessionService
{
    Task<RegistrationSession> CreateAsync(string mobile, CancellationToken ct);
    Task<string?> GetMobileAsync(string token, CancellationToken ct);
    Task ConsumeAsync(string token, CancellationToken ct);
}

public sealed class RegistrationSessionService : IRegistrationSessionService
{
    private readonly IDatabase _redis;
    private readonly RegistrationOptions _options;

    public RegistrationSessionService(
        IConnectionMultiplexer redis,
        IOptions<RegistrationOptions> options)
    {
        _redis = redis.GetDatabase();
        _options = options.Value;
    }

    public async Task<RegistrationSession> CreateAsync(string mobile, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        var token = Base64Url(RandomNumberGenerator.GetBytes(48));
        var lifetime = Math.Clamp(_options.LifetimeSeconds, 60, 3600);

        await _redis.StringSetAsync(
            Key(token),
            mobile,
            TimeSpan.FromSeconds(lifetime));

        return new RegistrationSession(token, lifetime);
    }

    public async Task<string?> GetMobileAsync(string token, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(token) || token.Length > 256)
            return null;

        var value = await _redis.StringGetAsync(Key(token));
        return value.HasValue ? value.ToString() : null;
    }

    public async Task ConsumeAsync(string token, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(token) || token.Length > 256)
            return;

        await _redis.KeyDeleteAsync(Key(token));
    }

    private static string Key(string token)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(token));
        return $"auth:registration:{Convert.ToHexString(hash)}";
    }

    private static string Base64Url(byte[] bytes)
        => Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
