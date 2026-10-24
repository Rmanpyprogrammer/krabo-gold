using krabo_gold.Services.Security;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace krabo_gold.Controllers;

[ApiController]
[AllowAnonymous]
[Route("api/captcha")]
public sealed class CaptchaController : ControllerBase
{
    private readonly ICaptchaService _captchaService;

    public CaptchaController(ICaptchaService captchaService)
    {
        _captchaService = captchaService;
    }

    [HttpGet]
    [Produces("application/json")]
    public async Task<IActionResult> Create(
        CancellationToken cancellationToken)
    {
        var captcha = await _captchaService.CreateAsync(
            cancellationToken
        );

        return Ok(new
        {
            captchaId = captcha.CaptchaId,
            image = $"data:image/svg+xml;base64,{Convert.ToBase64String(
                System.Text.Encoding.UTF8.GetBytes(captcha.ImageSvg)
            )}",
            expiresInSeconds = 120
        });
    }
}