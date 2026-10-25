using System.ComponentModel.DataAnnotations;

namespace krabo_gold.DTOs;

public sealed class RequestOtpDto
{
    [Required, StringLength(32, MinimumLength = 10)]
    public string Mobile { get; init; } = string.Empty;

    [Required, StringLength(48, MinimumLength = 48)]
    public string CaptchaId { get; init; } = string.Empty;

    [Required, StringLength(10, MinimumLength = 1)]
    public string CaptchaAnswer { get; init; } = string.Empty;
}

public sealed class VerifyOtpDto
{
    [Required, StringLength(32, MinimumLength = 10)]
    public string Mobile { get; init; } = string.Empty;

    [Required, RegularExpression("^[0-9]{6}$")]
    public string Code { get; init; } = string.Empty;
}

public sealed record AuthResponse(string AccessToken, string TokenType, int ExpiresInSeconds, string UserId, string? Name, string Mobile);

public sealed record RegistrationRequiredResponse(
    bool RequiresRegistration,
    string RegistrationToken,
    int RegistrationExpiresInSeconds,
    string Mobile);

public sealed record MessageResponse(string Message);
