namespace krabo_gold.Services.Security;

public sealed record CaptchaChallenge(
    string CaptchaId,
    string ImageSvg
);

public interface ICaptchaService
{
    Task<CaptchaChallenge> CreateAsync(
        CancellationToken cancellationToken = default
    );

    Task<bool> VerifyAsync(
        string captchaId,
        string answer,
        CancellationToken cancellationToken = default
    );
}