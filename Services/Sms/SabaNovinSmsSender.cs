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

    public async Task SendOtpAsync(
    string mobile,
    string code,
    CancellationToken cancellationToken = default)
{
    if (string.IsNullOrWhiteSpace(_options.Token) || _options.Gateway <= 0)
        throw new InvalidOperationException("SabaNovin settings are missing.");

    var normalized = MobileNormalizer.NormalizeIranianMobile(mobile);

    if (normalized is null || code.Length != 6 || !code.All(char.IsAsciiDigit))
        throw new ArgumentException("Invalid mobile or OTP.");

    var url =
        $"https://api.sabanovin.com/v1/{_options.Token}/sms/send_array.json";

    var payload = new
    {
        gateway = _options.Gateway,
        to = new[] { normalized },
        text = new[] { $"کد ورود شما به کرابو: {code} \n لغو۱۱" }
    };

    using var response = await _httpClient.PostAsJsonAsync(
        url,
        payload,
        cancellationToken
    );

    var responseBody = await response.Content.ReadAsStringAsync(
        cancellationToken
    );

    _logger.LogInformation(
        "SabaNovin SMS Response - StatusCode: {StatusCode}, IsSuccess: {IsSuccess}, Body: {ResponseBody}",
        (int)response.StatusCode,
        response.IsSuccessStatusCode,
        responseBody
    );

    if (!response.IsSuccessStatusCode)
    {
        throw new HttpRequestException(
            $"SabaNovin request failed with HTTP {(int)response.StatusCode}."
        );
    }

    if (string.IsNullOrWhiteSpace(responseBody))
    {
        throw new HttpRequestException(
            "SabaNovin returned an empty response."
        );
    }
}

}
