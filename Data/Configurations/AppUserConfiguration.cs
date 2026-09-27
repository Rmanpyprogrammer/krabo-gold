using krabo_gold.Models.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace krabo_gold.Data.Configurations;

public class AppUserConfiguration
    : IEntityTypeConfiguration<AppUser>
{
    public void Configure(
        EntityTypeBuilder<AppUser> builder
    )
    {
        builder.Property(x => x.Name)
            .HasMaxLength(40);

        builder.Property(x => x.NationalCode)
            .HasMaxLength(10);

        builder.Property(x => x.CreatedAt)
            .IsRequired();

        builder.Property(x => x.UpdatedAt)
            .IsRequired();

        builder.Property(x => x.IsActive)
            .HasDefaultValue(true);

        builder.HasIndex(x => x.NationalCode)
            .IsUnique()
            .HasFilter("\"NationalCode\" IS NOT NULL");
    }
}