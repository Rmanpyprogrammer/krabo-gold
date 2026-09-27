using krabo_gold.Models.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace krabo_gold.Data;

public class ApplicationDbContext
    : IdentityDbContext<
        AppUser,
        AppRole,
        Guid
    >
{
    public ApplicationDbContext(
        DbContextOptions<ApplicationDbContext> options
    )
        : base(options)
    {
    }

    public DbSet<UserExternalIdentity>
        UserExternalIdentities
        => Set<UserExternalIdentity>();

    public DbSet<Permission>
        Permissions
        => Set<Permission>();

    public DbSet<RolePermission>
        RolePermissions
        => Set<RolePermission>();

    protected override void OnModelCreating(
        ModelBuilder builder
    )
    {
        base.OnModelCreating(builder);

        builder.ApplyConfigurationsFromAssembly(
            typeof(ApplicationDbContext).Assembly
        );
    }
}