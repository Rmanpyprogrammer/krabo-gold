using krabo_gold.Models.Identity;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace krabo_gold.Data;

public static class DbSeeder
{
    public static async Task SeedAdminAsync(IServiceProvider services)
    {
        var userManager =
            services.GetRequiredService<UserManager<AppUser>>();

        var roleManager =
            services.GetRequiredService<RoleManager<AppRole>>();

        const string adminEmail = "admin@core.local";
        const string adminPassword = "Admin@12345";
        const string adminRole = "SuperAdmin";

        // 1. Create SuperAdmin role if it does not exist.
        var role = await roleManager.FindByNameAsync(adminRole);

        if (role is null)
        {
            var newRole = new AppRole
            {
                Name = adminRole
            };

            var roleResult = await roleManager.CreateAsync(newRole);

            if (!roleResult.Succeeded)
            {
                var errors = string.Join(
                    "; ",
                    roleResult.Errors.Select(e => $"{e.Code}: {e.Description}"));

                throw new InvalidOperationException(
                    $"Failed to create role '{adminRole}': {errors}");
            }
        }

        // 2. Find or create the admin user.
        var admin = await userManager.FindByEmailAsync(adminEmail);

        if (admin is null)
        {
            admin = new AppUser
            {
                UserName = adminEmail,
                Email = adminEmail,
                EmailConfirmed = true,
                IsActive = true
            };

            var userResult =
                await userManager.CreateAsync(admin, adminPassword);

            if (!userResult.Succeeded)
            {
                var errors = string.Join(
                    "; ",
                    userResult.Errors.Select(e => $"{e.Code}: {e.Description}"));

                throw new InvalidOperationException(
                    $"Failed to create initial admin: {errors}");
            }
        }

        // 3. Ensure the existing or new user has the SuperAdmin role.
        if (!await userManager.IsInRoleAsync(admin, adminRole))
        {
            var addRoleResult =
                await userManager.AddToRoleAsync(admin, adminRole);

            if (!addRoleResult.Succeeded)
            {
                var errors = string.Join(
                    "; ",
                    addRoleResult.Errors.Select(e => $"{e.Code}: {e.Description}"));

                throw new InvalidOperationException(
                    $"Failed to assign '{adminRole}' to admin: {errors}");
            }
        }
    }
}