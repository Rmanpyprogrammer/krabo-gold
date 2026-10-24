using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using krabo_gold.Data;
using krabo_gold.Models.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace krabo_gold.Services.Auth;

public sealed record TokenPair(string AccessToken, int ExpiresInSeconds, string RefreshToken);
public sealed class TokenService
{
    private readonly IConfiguration _configuration;
    private readonly ApplicationDbContext _db;
    private readonly UserManager<AppUser> _users;

    public TokenService(IConfiguration configuration, ApplicationDbContext db, UserManager<AppUser> users)
    { _configuration = configuration; _db = db; _users = users; }

    public async Task<TokenPair> IssueAsync(AppUser user, string? ip, CancellationToken ct)
    {
        var accessMinutes = _configuration.GetValue<int>("Jwt:ExpireMinutes", 15);
        var refreshDays = _configuration.GetValue<int>("Jwt:RefreshExpireDays", 7);
        var now = DateTime.UtcNow;
        var rawRefresh = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var hash = HashRefresh(rawRefresh);
        _db.Set<RefreshToken>().Add(new RefreshToken { UserId = user.Id, TokenHash = hash, ExpiresAt = now.AddDays(refreshDays), CreatedAt = now, CreatedByIp = ip });
        var jwt = await CreateAccessTokenAsync(user, now, accessMinutes);
        await _db.SaveChangesAsync(ct);
        return new TokenPair(jwt, checked(accessMinutes * 60), rawRefresh);
    }

    public async Task<TokenPair?> RotateAsync(string rawRefresh, string? ip, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(rawRefresh) || rawRefresh.Length > 256) return null;
        var hash = HashRefresh(rawRefresh);
        await using var tx = await _db.Database.BeginTransactionAsync(ct);
        var current = await _db.Set<RefreshToken>().Include(x => x.User).SingleOrDefaultAsync(x => x.TokenHash == hash, ct);
        var now = DateTime.UtcNow;
        if (current is null || current.RevokedAt is not null || current.ExpiresAt <= now || !current.User.IsActive) return null;
        var user = current.User;
        var accessMinutes = _configuration.GetValue<int>("Jwt:ExpireMinutes", 15);
        var refreshDays = _configuration.GetValue<int>("Jwt:RefreshExpireDays", 7);
        var newRaw = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        var newHash = HashRefresh(newRaw);
        current.RevokedAt = now;
        current.RevokedByIp = ip;
        current.ReplacedByTokenHash = newHash;
        _db.Set<RefreshToken>().Add(new RefreshToken { UserId = user.Id, TokenHash = newHash, ExpiresAt = now.AddDays(refreshDays), CreatedAt = now, CreatedByIp = ip });
        var jwt = await CreateAccessTokenAsync(user, now, accessMinutes);
        await _db.SaveChangesAsync(ct);
        await tx.CommitAsync(ct);
        return new TokenPair(jwt, checked(accessMinutes * 60), newRaw);
    }

    public async Task RevokeAsync(string rawRefresh, string? ip, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(rawRefresh) || rawRefresh.Length > 256) return;
        var token = await _db.Set<RefreshToken>().SingleOrDefaultAsync(x => x.TokenHash == HashRefresh(rawRefresh), ct);
        if (token is null || token.RevokedAt is not null) return;
        token.RevokedAt = DateTime.UtcNow; token.RevokedByIp = ip;
        await _db.SaveChangesAsync(ct);
    }

    private async Task<string> CreateAccessTokenAsync(AppUser user, DateTime now, int minutes)
    {
        var section = _configuration.GetSection("Jwt");
        var keyText = section["Key"] ?? throw new InvalidOperationException("JWT key missing.");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyText));
        var claims = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.MobilePhone, user.PhoneNumber ?? string.Empty),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
        };
        if (!string.IsNullOrWhiteSpace(user.Name)) claims.Add(new Claim(ClaimTypes.Name, user.Name));
        foreach (var role in await _users.GetRolesAsync(user)) claims.Add(new Claim(ClaimTypes.Role, role));
        var token = new JwtSecurityToken(section["Issuer"], section["Audience"], claims,
            notBefore: now, expires: now.AddMinutes(minutes), signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string HashRefresh(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}
