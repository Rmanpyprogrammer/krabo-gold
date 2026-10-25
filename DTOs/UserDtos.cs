using System.ComponentModel.DataAnnotations;

namespace krabo_gold.DTOs;

public sealed class RegisterUserDto
{
    [Required, StringLength(128, MinimumLength = 32)]
    public string RegistrationToken { get; init; } = string.Empty;

    [Required, StringLength(100, MinimumLength = 2)]
    public string Name { get; init; } = string.Empty;

    [RegularExpression("^[0-9]{10}$")]
    public string? NationalCode { get; init; }

    [EmailAddress, StringLength(256)]
    public string? Email { get; init; }
}

public sealed class UpdateUserProfileDto
{
    [Required, StringLength(100, MinimumLength = 2)]
    public string Name { get; init; } = string.Empty;

    [RegularExpression("^[0-9]{10}$")]
    public string? NationalCode { get; init; }

    [EmailAddress, StringLength(256)]
    public string? Email { get; init; }
}

public sealed record UserProfileResponse(
    string UserId,
    string Mobile,
    string? Name,
    string? NationalCode,
    string? Email,
    bool IsActive,
    DateTime CreatedAt,
    DateTime UpdatedAt);

public sealed class UpsertUserAddressDto
{
    [Required, StringLength(50, MinimumLength = 1)]
    public string Title { get; init; } = string.Empty;

    [Required, StringLength(100, MinimumLength = 2)]
    public string Province { get; init; } = string.Empty;

    [Required, StringLength(100, MinimumLength = 2)]
    public string City { get; init; } = string.Empty;

    [Required, StringLength(1000, MinimumLength = 5)]
    public string AddressLine { get; init; } = string.Empty;

    [Required, RegularExpression("^[0-9]{10}$")]
    public string PostalCode { get; init; } = string.Empty;

    [StringLength(20)]
    public string? Plaque { get; init; }

    [StringLength(20)]
    public string? Unit { get; init; }

    public bool IsDefault { get; init; }
}

public sealed record UserAddressResponse(
    Guid Id,
    string Title,
    string Province,
    string City,
    string AddressLine,
    string PostalCode,
    string? Plaque,
    string? Unit,
    bool IsDefault,
    DateTime CreatedAt,
    DateTime UpdatedAt);
