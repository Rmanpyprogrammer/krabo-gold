using krabo_gold.Models.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace krabo_gold.Data.Configurations;

public class UserExternalIdentityConfiguration
    : IEntityTypeConfiguration<UserExternalIdentity>
{
    public void Configure(
        EntityTypeBuilder<UserExternalIdentity> builder
    )
    {
        builder.ToTable("UserExternalIdentities");

        builder.HasKey(x => x.Id);

        builder.Property(x => x.ExternalUserId)
            .IsRequired()
            .HasMaxLength(100);

        builder.HasIndex(x => new
        {
            x.ExternalSystem,
            x.ExternalUserId
        })
        .IsUnique();

        builder.HasOne(x => x.User)
            .WithMany(x => x.ExternalIdentities)
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.Property(x => x.CreatedAt)
            .IsRequired();

        builder.Property(x => x.UpdatedAt)
            .IsRequired();
    }
}