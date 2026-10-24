using System.Net.Http.Json;
using krabo_gold.Services.Auth;
using Microsoft.Extensions.Options;

namespace krabo_gold.Services.Sms;

public sealed class SabaNovinSmsSender : ISmsSender
{
    private readonly HttpClient _httpClient;
    private readonly SabaNovinOptions _options;
    private readonly ILogger<SabaNovinSmsSender> _logger;
    public SabaNovinSmsSender(HttpClient httpClient, IOptions<SabaNovinOptions> options, ILogger<SabaNovinSmsSender> logger)
    { _httpClient = httpClient; _options = options.Value; _logger = logger; }

    public async Task SendOtpAsync(string mobile, string code, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(_options.Token) || _options.Gateway <= 0)
            throw new InvalidOperationException("SabaNovin settings are missing.");
        var normalized = MobileNormalizer.NormalizeIranianMobile(mobile);
        if (normalized is null || code.Length != 6 || !code.All(char.IsAsciiDigit))
            throw new ArgumentException("Invalid mobile or OTP.");
        var url = $"https://api.sabanovin.com/v1/{_options.Token}/sms/send_array.json";
        var payload = new { gateway = _options.Gateway, to = new[] { normalized }, text = new[] { $"کد ورود شما به کرابو: {code}" } };
        using var response = await _httpClient.PostAsJsonAsync(url, payload, cancellationToken);
        var responseText = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError("SabaNovin HTTP request failed with status {StatusCode}.", (int)response.StatusCode);
            throw new HttpRequestException("SMS provider request failed.");
        }
        // The provider's JSON success/error schema was not included in the project bundle.
        // Do not log responseText: it may contain provider details or personal data.
        if (string.IsNullOrWhiteSpace(responseText))
            throw new HttpRequestException("SMS provider returned an empty response.");
        _logger.LogInformation("SabaNovin returned HTTP success for an OTP request.");
    }
}
