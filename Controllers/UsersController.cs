using System.Security.Claims;
using krabo_gold.Data;
using krabo_gold.DTOs;
using krabo_gold.Models.Identity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace krabo_gold.Controllers;

[ApiController]
[Authorize]
[Route("api/users/me")]
public sealed class UsersController : ControllerBase
{
    private readonly ApplicationDbContext _db;
    private readonly UserManager<AppUser> _users;

    public UsersController(ApplicationDbContext db, UserManager<AppUser> users)
    {
        _db = db;
        _users = users;
    }

    [HttpGet]
    public async Task<IActionResult> GetProfile(CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized(new { error = "user_id_missing" });

        var user = await _users.Users
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == userId, ct);

        if (user is null)
            return NotFound(new { error = "user_not_found" });

        return Ok(ToProfileResponse(user));
    }

    [HttpPut]
    public async Task<IActionResult> UpdateProfile([FromBody] UpdateUserProfileDto dto, CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized(new { error = "user_id_missing" });

        var user = await _users.Users.SingleOrDefaultAsync(x => x.Id == userId, ct);
        if (user is null)
            return NotFound(new { error = "user_not_found" });

        var nationalCode = string.IsNullOrWhiteSpace(dto.NationalCode)
            ? null
            : dto.NationalCode.Trim();

        if (nationalCode is not null)
        {
            var exists = await _users.Users.AnyAsync(
                x => x.Id != userId && x.NationalCode == nationalCode,
                ct);

            if (exists)
            {
                return Conflict(new
                {
                    error = "national_code_already_exists",
                    message = "این کد ملی قبلاً ثبت شده است."
                });
            }
        }

        user.Name = dto.Name.Trim();
        user.NationalCode = nationalCode;
        user.Email = string.IsNullOrWhiteSpace(dto.Email) ? null : dto.Email.Trim();
        user.UpdatedAt = DateTime.UtcNow;

        var updated = await _users.UpdateAsync(user);
        if (!updated.Succeeded)
        {
            return BadRequest(new
            {
                error = "profile_update_failed",
                errors = updated.Errors.Select(x => new { x.Code, x.Description })
            });
        }

        return Ok(ToProfileResponse(user));
    }

    [HttpGet("addresses")]
    public async Task<IActionResult> GetAddresses(CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized(new { error = "user_id_missing" });

        var addresses = await _db.UserAddresses
            .AsNoTracking()
            .Where(x => x.UserId == userId)
            .OrderByDescending(x => x.IsDefault)
            .ThenByDescending(x => x.CreatedAt)
            .ToListAsync(ct);

        return Ok(addresses.Select(ToAddressResponse));
    }

    [HttpPost("addresses")]
    public async Task<IActionResult> CreateAddress([FromBody] UpsertUserAddressDto dto, CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized(new { error = "user_id_missing" });

        var userExists = await _users.Users.AnyAsync(x => x.Id == userId && x.IsActive, ct);
        if (!userExists)
            return NotFound(new { error = "user_not_found" });

        var hasAddress = await _db.UserAddresses.AnyAsync(x => x.UserId == userId, ct);
        var makeDefault = !hasAddress || dto.IsDefault;

        if (makeDefault)
            await ClearDefaultAddressAsync(userId, null, ct);

        var now = DateTime.UtcNow;
        var address = new UserAddress
        {
            UserId = userId,
            Title = dto.Title.Trim(),
            Province = dto.Province.Trim(),
            City = dto.City.Trim(),
            AddressLine = dto.AddressLine.Trim(),
            PostalCode = dto.PostalCode.Trim(),
            Plaque = CleanOptional(dto.Plaque),
            Unit = CleanOptional(dto.Unit),
            IsDefault = makeDefault,
            CreatedAt = now,
            UpdatedAt = now
        };

        _db.UserAddresses.Add(address);
        await _db.SaveChangesAsync(ct);

        return CreatedAtAction(
            nameof(GetAddress),
            new { addressId = address.Id },
            ToAddressResponse(address));
    }

    [HttpGet("addresses/{addressId:guid}")]
    public async Task<IActionResult> GetAddress(Guid addressId, CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized(new { error = "user_id_missing" });

        var address = await _db.UserAddresses
            .AsNoTracking()
            .SingleOrDefaultAsync(x => x.Id == addressId && x.UserId == userId, ct);

        return address is null
            ? NotFound(new { error = "address_not_found" })
            : Ok(ToAddressResponse(address));
    }

    [HttpPut("addresses/{addressId:guid}")]
    public async Task<IActionResult> UpdateAddress(
        Guid addressId,
        [FromBody] UpsertUserAddressDto dto,
        CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized(new { error = "user_id_missing" });

        var address = await _db.UserAddresses
            .SingleOrDefaultAsync(x => x.Id == addressId && x.UserId == userId, ct);

        if (address is null)
            return NotFound(new { error = "address_not_found" });

        if (dto.IsDefault && !address.IsDefault)
            await ClearDefaultAddressAsync(userId, addressId, ct);

        address.Title = dto.Title.Trim();
        address.Province = dto.Province.Trim();
        address.City = dto.City.Trim();
        address.AddressLine = dto.AddressLine.Trim();
        address.PostalCode = dto.PostalCode.Trim();
        address.Plaque = CleanOptional(dto.Plaque);
        address.Unit = CleanOptional(dto.Unit);

        if (dto.IsDefault)
            address.IsDefault = true;

        address.UpdatedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync(ct);

        return Ok(ToAddressResponse(address));
    }

    [HttpDelete("addresses/{addressId:guid}")]
    public async Task<IActionResult> DeleteAddress(Guid addressId, CancellationToken ct)
    {
        if (!TryGetUserId(out var userId))
            return Unauthorized(new { error = "user_id_missing" });

        var address = await _db.UserAddresses
            .SingleOrDefaultAsync(x => x.Id == addressId && x.UserId == userId, ct);

        if (address is null)
            return NotFound(new { error = "address_not_found" });

        var wasDefault = address.IsDefault;
        _db.UserAddresses.Remove(address);
        await _db.SaveChangesAsync(ct);

        if (wasDefault)
        {
            var next = await _db.UserAddresses
                .Where(x => x.UserId == userId)
                .OrderBy(x => x.CreatedAt)
                .FirstOrDefaultAsync(ct);

            if (next is not null)
            {
                next.IsDefault = true;
                next.UpdatedAt = DateTime.UtcNow;
                await _db.SaveChangesAsync(ct);
            }
        }

        return NoContent();
    }

    private async Task ClearDefaultAddressAsync(Guid userId, Guid? exceptAddressId, CancellationToken ct)
    {
        var defaults = await _db.UserAddresses
            .Where(x => x.UserId == userId &&
                        x.IsDefault &&
                        (!exceptAddressId.HasValue || x.Id != exceptAddressId.Value))
            .ToListAsync(ct);

        foreach (var item in defaults)
        {
            item.IsDefault = false;
            item.UpdatedAt = DateTime.UtcNow;
        }
    }

    private bool TryGetUserId(out Guid userId)
    {
        var raw = User.FindFirstValue(ClaimTypes.NameIdentifier)
                  ?? User.FindFirstValue("sub")
                  ?? User.FindFirstValue("user_id");

        return Guid.TryParse(raw, out userId);
    }

    private static UserProfileResponse ToProfileResponse(AppUser user)
        => new(
            user.Id.ToString(),
            user.PhoneNumber ?? string.Empty,
            user.Name,
            user.NationalCode,
            user.Email,
            user.IsActive,
            user.CreatedAt,
            user.UpdatedAt);

    private static UserAddressResponse ToAddressResponse(UserAddress address)
        => new(
            address.Id,
            address.Title,
            address.Province,
            address.City,
            address.AddressLine,
            address.PostalCode,
            address.Plaque,
            address.Unit,
            address.IsDefault,
            address.CreatedAt,
            address.UpdatedAt);

    private static string? CleanOptional(string? value)
        => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
