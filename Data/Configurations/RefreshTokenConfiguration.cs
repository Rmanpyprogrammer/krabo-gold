using krabo_gold.Models.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace krabo_gold.Data.Configurations;

public sealed class RefreshTokenConfiguration : IEntityTypeConfiguration<RefreshToken>
{
    public void Configure(EntityTypeBuilder<RefreshToken> builder)
    {
        builder.ToTable("RefreshTokens");
        builder.HasKey(x => x.Id);
        builder.Property(x => x.TokenHash).IsRequired().HasMaxLength(64);
        builder.HasIndex(x => x.TokenHash).IsUnique();
        builder.Property(x => x.CreatedByIp).HasMaxLength(64);
        builder.Property(x => x.RevokedByIp).HasMaxLength(64);
        builder.HasOne(x => x.User).WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        builder.HasIndex(x => new { x.UserId, x.ExpiresAt });
    }
}
