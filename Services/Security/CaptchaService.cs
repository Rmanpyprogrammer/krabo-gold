using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using krabo_gold.Services.Security;
using StackExchange.Redis;

namespace krabo_gold.Services.Security;

public sealed class CaptchaService : ICaptchaService
{
    private const string Alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    private static readonly TimeSpan CaptchaLifetime =
        TimeSpan.FromMinutes(2);

    private readonly IDatabase _redis;

    public CaptchaService(IConnectionMultiplexer redis)
    {
        _redis = redis.GetDatabase();
    }

    public async Task<CaptchaChallenge> CreateAsync(
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var captchaId = Convert.ToHexString(
            RandomNumberGenerator.GetBytes(24)
        );

        var answer = GenerateAnswer();
        var answerHash = HashAnswer(captchaId, answer);

        var answerKey = $"captcha:{captchaId}:answer";
        var attemptsKey = $"captcha:{captchaId}:attempts";

        await _redis.StringSetAsync(
            answerKey,
            answerHash,
            CaptchaLifetime
        );

        await _redis.StringSetAsync(
            attemptsKey,
            "0",
            CaptchaLifetime
        );

        return new CaptchaChallenge(
            captchaId,
            CreateSvg(answer)
        );
    }

    public async Task<bool> VerifyAsync(
        string captchaId,
        string answer,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(captchaId) ||
            captchaId.Length != 48 ||
            !Regex.IsMatch(captchaId, @"\A[0-9A-Fa-f]{48}\z") ||
            string.IsNullOrWhiteSpace(answer) ||
            answer.Length > 10)
        {
            return false;
        }

        var answerKey = $"captcha:{captchaId}:answer";
        var attemptsKey = $"captcha:{captchaId}:attempts";
        var submittedHash = HashAnswer(captchaId, answer);

        const string script = """
            local stored = redis.call('GET', KEYS[1])

            if not stored then
                return 0
            end

            local attempts = tonumber(redis.call('GET', KEYS[2]) or '0')

            if attempts >= 5 then
                redis.call('DEL', KEYS[1], KEYS[2])
                return 0
            end

            if stored == ARGV[1] then
                redis.call('DEL', KEYS[1], KEYS[2])
                return 1
            end

            attempts = redis.call('INCR', KEYS[2])

            if attempts == 1 then
                redis.call('EXPIRE', KEYS[2], 120)
            end

            if attempts >= 5 then
                redis.call('DEL', KEYS[1], KEYS[2])
            end

            return 0
            """;

        var result = await _redis.ScriptEvaluateAsync(
            script,
            new RedisKey[] { answerKey, attemptsKey },
            new RedisValue[] { submittedHash }
        );

        return (long)result == 1;
    }

    private static string GenerateAnswer()
    {
        return string.Concat(
            Enumerable.Range(0, 6)
                .Select(_ => Alphabet[
                    RandomNumberGenerator.GetInt32(Alphabet.Length)
                ])
        );
    }

    private static string HashAnswer(
        string captchaId,
        string answer)
    {
        var normalized = answer.Trim().ToUpperInvariant();
        var bytes = Encoding.UTF8.GetBytes(
            $"{captchaId}:{normalized}"
        );

        return Convert.ToHexString(SHA256.HashData(bytes));
    }

    private static string CreateSvg(string answer)
    {
        var sb = new StringBuilder();

        sb.Append("""
            <svg xmlns="http://www.w3.org/2000/svg"
                 width="240" height="80" viewBox="0 0 240 80">
              <rect width="240" height="80" rx="8" fill="#f1f3f5"/>
            """);

        for (var i = 0; i < 8; i++)
        {
            var x1 = RandomNumberGenerator.GetInt32(0, 240);
            var y1 = RandomNumberGenerator.GetInt32(0, 80);
            var x2 = RandomNumberGenerator.GetInt32(0, 240);
            var y2 = RandomNumberGenerator.GetInt32(0, 80);

            sb.Append(
                $"<line x1=\"{x1}\" y1=\"{y1}\" " +
                $"x2=\"{x2}\" y2=\"{y2}\" " +
                "stroke=\"#a0a7b0\" stroke-width=\"1.2\"/>"
            );
        }

        for (var i = 0; i < answer.Length; i++)
        {
            var x = 22 + i * 37;
            var y = RandomNumberGenerator.GetInt32(43, 62);
            var angle = RandomNumberGenerator.GetInt32(-22, 23);

            sb.Append(
                $"<text x=\"{x}\" y=\"{y}\" " +
                $"transform=\"rotate({angle} {x} {y})\" " +
                "font-family=\"monospace\" font-size=\"27\" " +
                "font-weight=\"bold\" fill=\"#202a44\">"
            );

            // کاراکترها از الفبای ثابت داخلی هستند.
            sb.Append(answer[i]);
            sb.Append("</text>");
        }

        sb.Append("</svg>");

        return sb.ToString();
    }
}