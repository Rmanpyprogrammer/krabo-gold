using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using StackExchange.Redis;
using krabo_gold.Services.Security;
using krabo_gold.Services.Sms;

namespace krabo_gold.Services.Auth;

public sealed class OtpOptions
{
    public int LifetimeSeconds { get; set; } = 180;
    public int MaxAttempts { get; set; } = 5;
    public int PhoneRequestsPerWindow { get; set; } = 3;
    public int IpRequestsPerWindow { get; set; } = 10;
    public int RateWindowSeconds { get; set; } = 600;
}

public enum OtpRequestResult { Sent, InvalidCaptcha, RateLimited, InvalidMobile }
public enum OtpVerifyResult { Valid, Invalid, Expired, RateLimited }

public interface IOtpService
{
    Task<OtpRequestResult> RequestAsync(string mobile, string captchaId, string captchaAnswer, string ip, CancellationToken ct);
    Task<OtpVerifyResult> VerifyAsync(string mobile, string code, CancellationToken ct);
}

public sealed class OtpService : IOtpService
{
    private readonly IDatabase _redis;
    private readonly ICaptchaService _captcha;
    private readonly ISmsSender _sms;
    private readonly OtpOptions _options;
    private readonly ILogger<OtpService> _logger;

    private const string RateScript = """
        local a = redis.call('INCR', KEYS[1]); if a == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
        local b = redis.call('INCR', KEYS[2]); if b == 1 then redis.call('EXPIRE', KEYS[2], ARGV[1]) end
        if a > tonumber(ARGV[2]) or b > tonumber(ARGV[3]) then return 0 end
        return 1
        """;

    private const string VerifyScript = """
        local stored = redis.call('GET', KEYS[1])
        if not stored then return -1 end
        local attempts = tonumber(redis.call('GET', KEYS[2]) or '0')
        if attempts >= tonumber(ARGV[2]) then redis.call('DEL', KEYS[1], KEYS[2]); return -2 end
        if stored == ARGV[1] then redis.call('DEL', KEYS[1], KEYS[2]); return 1 end
        attempts = redis.call('INCR', KEYS[2])
        if attempts == 1 then redis.call('EXPIRE', KEYS[2], ARGV[3]) end
        if attempts >= tonumber(ARGV[2]) then redis.call('DEL', KEYS[1], KEYS[2]); return -2 end
        return 0
        """;

    public OtpService(IConnectionMultiplexer redis, ICaptchaService captcha, ISmsSender sms,
        IOptions<OtpOptions> options, ILogger<OtpService> logger)
    { _redis = redis.GetDatabase(); _captcha = captcha; _sms = sms; _options = options.Value; _logger = logger; }

    public async Task<OtpRequestResult> RequestAsync(string mobile, string captchaId, string captchaAnswer, string ip, CancellationToken ct)
    {
        var normalized = MobileNormalizer.NormalizeIranianMobile(mobile);
        if (normalized is null) return OtpRequestResult.InvalidMobile;
        var phoneKey = HashKey(normalized);
        var ipHash = HashKey(string.IsNullOrWhiteSpace(ip) ? "unknown" : ip);
        var rate = await _redis.ScriptEvaluateAsync(RateScript,
            new RedisKey[] { $"otp:rate:phone:{phoneKey}", $"otp:rate:ip:{ipHash}" },
            new RedisValue[] { _options.RateWindowSeconds, _options.PhoneRequestsPerWindow, _options.IpRequestsPerWindow });
        if ((long)rate != 1) return OtpRequestResult.RateLimited;

        if (!await _captcha.VerifyAsync(captchaId, captchaAnswer, ct)) return OtpRequestResult.InvalidCaptcha;

        var code = RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");
        var otpKey = $"otp:code:{phoneKey}";
        var attemptsKey = $"otp:attempts:{phoneKey}";
        var hash = HashCode(normalized, code);
        await _redis.StringSetAsync(otpKey, hash, TimeSpan.FromSeconds(_options.LifetimeSeconds));
        await _redis.KeyDeleteAsync(attemptsKey);
        try
        {
            await _sms.SendOtpAsync(normalized, code, ct);
            return OtpRequestResult.Sent;
        }
        catch
        {
            await _redis.KeyDeleteAsync(otpKey);
            _logger.LogWarning("OTP SMS send failed for a mobile number ending in {LastFour}.", normalized[^4..]);
            throw;
        }
    }

    public async Task<OtpVerifyResult> VerifyAsync(string mobile, string code, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        var normalized = MobileNormalizer.NormalizeIranianMobile(mobile);
        if (normalized is null || code.Length != 6 || !code.All(char.IsAsciiDigit)) return OtpVerifyResult.Invalid;
        var phoneKey = HashKey(normalized);
        var result = (long)await _redis.ScriptEvaluateAsync(VerifyScript,
            new RedisKey[] { $"otp:code:{phoneKey}", $"otp:attempts:{phoneKey}" },
            new RedisValue[] { HashCode(normalized, code), _options.MaxAttempts, _options.LifetimeSeconds });
        return result switch { 1 => OtpVerifyResult.Valid, -1 => OtpVerifyResult.Expired, -2 => OtpVerifyResult.RateLimited, _ => OtpVerifyResult.Invalid };
    }

    private static string HashKey(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static string HashCode(string mobile, string code) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"krabo-otp-v1:{mobile}:{code}")));
}
