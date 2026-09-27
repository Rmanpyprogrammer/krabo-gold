using krabo_gold.Models.Identity;

namespace krabo_gold.Models.Identity;

public class UserExternalIdentity
{
    public Guid Id { get; set; }

    public Guid UserId { get; set; }

    public AppUser User { get; set; } = null!;


    public ExternalSystem ExternalSystem { get; set; }


    public string ExternalUserId { get; set; } = null!;


    public DateTime CreatedAt { get; set; }

    public DateTime UpdatedAt { get; set; }
}