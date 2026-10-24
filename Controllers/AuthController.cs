using System.Security.Cryptography;
using System.Text;
using krabo_gold.Data;
using krabo_gold.DTOs;
using krabo_gold.Models.Identity;
using krabo_gold.Services.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace krabo_gold.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController : ControllerBase
{
    private const string RefreshCookie = "krabo_refresh";
    private const string CsrfCookie = "krabo_csrf";
    private readonly IOtpService _otp;
    private readonly UserManager<AppUser> _users;
    private readonly ApplicationDbContext _db;
    private readonly TokenService _tokens;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IOtpService otp, UserManager<AppUser> users, ApplicationDbContext db, TokenService tokens, ILogger<AuthController> logger)
    { _otp = otp; _users = users; _db = db; _tokens = tokens; _logger = logger; }

    [AllowAnonymous, HttpPost("request-otp")]
    public async Task<IActionResult> RequestOtp([FromBody] RequestOtpDto dto, CancellationToken ct)
    {
        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        try
        {
            var result = await _otp.RequestAsync(dto.Mobile, dto.CaptchaId, dto.CaptchaAnswer, ip, ct);
            return result switch
            {
                OtpRequestResult.Sent => Ok(new MessageResponse("اگر اطلاعات معتبر باشد، کد ورود ارسال می‌شود.")),
                OtpRequestResult.InvalidCaptcha => BadRequest(new { error = "invalid_captcha", message = "کپچا نامعتبر یا منقضی شده است." }),
                OtpRequestResult.RateLimited => StatusCode(429, new { error = "otp_rate_limited", message = "تعداد درخواست‌ها بیش از حد مجاز است." }),
                _ => BadRequest(new { error = "invalid_mobile", message = "شماره موبایل معتبر نیست." })
            };
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "OTP request failed.");
            return StatusCode(503, new { error = "otp_unavailable", message = "فعلاً ارسال کد ممکن نیست." });
        }
    }

    [AllowAnonymous, HttpPost("verify-otp")]
    public async Task<IActionResult> VerifyOtp([FromBody] VerifyOtpDto dto, CancellationToken ct)
    {
        var mobile = MobileNormalizer.NormalizeIranianMobile(dto.Mobile);
        if (mobile is null) return BadRequest(new { error = "invalid_mobile" });
        var result = await _otp.VerifyAsync(mobile, dto.Code, ct);
        if (result != OtpVerifyResult.Valid)
            return Unauthorized(new { error = result == OtpVerifyResult.Expired ? "otp_expired" : result == OtpVerifyResult.RateLimited ? "otp_attempts_exceeded" : "invalid_otp", message = "کد ورود معتبر نیست یا منقضی شده است." });

        var user = await _users.Users.SingleOrDefaultAsync(x => x.PhoneNumber == mobile, ct);
        if (user is null)
        {
            user = new AppUser { UserName = mobile, PhoneNumber = mobile, PhoneNumberConfirmed = true, IsActive = true, CreatedAt = DateTime.UtcNow, UpdatedAt = DateTime.UtcNow };
            var created = await _users.CreateAsync(user);
            if (!created.Succeeded)
            {
                _logger.LogError("Identity user creation failed: {Errors}", string.Join(",", created.Errors.Select(x => x.Code)));
                return StatusCode(500, new { error = "user_creation_failed" });
            }
        }
        if (!user.IsActive) return StatusCode(403, new { error = "account_disabled" });
        user.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);
        var pair = await _tokens.IssueAsync(user, HttpContext.Connection.RemoteIpAddress?.ToString(), ct);
        SetRefreshCookies(pair.RefreshToken);
        return Ok(new AuthResponse(pair.AccessToken, "Bearer", pair.ExpiresInSeconds, user.Id.ToString(), user.Name, mobile));
    }

    [AllowAnonymous, HttpPost("refresh")]
    public async Task<IActionResult> Refresh(CancellationToken ct)
    {
        if (!HasValidCsrf()) return StatusCode(403, new { error = "csrf_validation_failed" });
        var raw = Request.Cookies[RefreshCookie];
        if (string.IsNullOrWhiteSpace(raw)) return Unauthorized(new { error = "refresh_token_missing" });
        var pair = await _tokens.RotateAsync(raw, HttpContext.Connection.RemoteIpAddress?.ToString(), ct);
        if (pair is null) { ClearRefreshCookies(); return Unauthorized(new { error = "refresh_token_invalid" }); }
        SetRefreshCookies(pair.RefreshToken);
        return Ok(new { accessToken = pair.AccessToken, tokenType = "Bearer", expiresInSeconds = pair.ExpiresInSeconds });
    }

    [Authorize, HttpPost("logout")]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        if (!HasValidCsrf()) return StatusCode(403, new { error = "csrf_validation_failed" });
        var raw = Request.Cookies[RefreshCookie];
        if (!string.IsNullOrWhiteSpace(raw)) await _tokens.RevokeAsync(raw, HttpContext.Connection.RemoteIpAddress?.ToString(), ct);
        ClearRefreshCookies();
        return Ok(new MessageResponse("از حساب خارج شدید."));
    }

    private bool HasValidCsrf()
    {
        var cookie = Request.Cookies[CsrfCookie];
        var header = Request.Headers["X-CSRF-TOKEN"].ToString();
        if (string.IsNullOrEmpty(cookie) || string.IsNullOrEmpty(header) || cookie.Length != header.Length) return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(cookie), Encoding.UTF8.GetBytes(header));
    }

    private void SetRefreshCookies(string refresh)
    {
        var secure = Request.IsHttps;
        var days = HttpContext.RequestServices.GetRequiredService<IConfiguration>().GetValue<int>("Jwt:RefreshExpireDays", 7);
        Response.Cookies.Append(RefreshCookie, refresh, new CookieOptions { HttpOnly = true, Secure = secure, SameSite = SameSiteMode.Strict, Path = "/api/auth", Expires = DateTimeOffset.UtcNow.AddDays(days), IsEssential = true });
        var csrf = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+','-').Replace('/','_');
        Response.Cookies.Append(CsrfCookie, csrf, new CookieOptions { HttpOnly = false, Secure = secure, SameSite = SameSiteMode.Strict, Path = "/", Expires = DateTimeOffset.UtcNow.AddDays(days), IsEssential = true });
    }

    private void ClearRefreshCookies()
    {
        Response.Cookies.Delete(RefreshCookie, new CookieOptions { HttpOnly = true, Secure = Request.IsHttps, SameSite = SameSiteMode.Strict, Path = "/api/auth" });
        Response.Cookies.Delete(CsrfCookie, new CookieOptions { HttpOnly = false, Secure = Request.IsHttps, SameSite = SameSiteMode.Strict, Path = "/" });
    }
}
