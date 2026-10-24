
using Microsoft.AspNetCore.Identity;

namespace krabo_gold.Models.Identity;

public class AppRole : IdentityRole<Guid>
{
    public ICollection<RolePermission> RolePermissions { get; set; }
        = new List<RolePermission>();
}
