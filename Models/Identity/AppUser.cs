using Microsoft.AspNetCore.Identity;

namespace krabo_gold.Models.Identity;

public class AppUser : IdentityUser<Guid>
{
    public string? Name { get; set; }

    public string? NationalCode { get; set; }

    public bool IsActive { get; set; } = true;

    public DateTime CreatedAt { get; set; }

    public DateTime UpdatedAt { get; set; }


    public ICollection<UserExternalIdentity>
        ExternalIdentities { get; set; }
        = new List<UserExternalIdentity>();
}