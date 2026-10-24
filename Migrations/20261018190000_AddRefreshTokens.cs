using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using krabo_gold.Data;

#nullable disable
namespace krabo_gold.Migrations;

[DbContext(typeof(ApplicationDbContext))]
[Migration("20261018190000_AddRefreshTokens")]
public sealed class AddRefreshTokens : Migration
{
    protected override void Up(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.CreateTable(
            name: "RefreshTokens",
            columns: table => new
            {
                Id = table.Column<Guid>(type: "uuid", nullable: false),
                UserId = table.Column<Guid>(type: "uuid", nullable: false),
                TokenHash = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                ExpiresAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                CreatedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: false),
                RevokedAt = table.Column<DateTime>(type: "timestamp with time zone", nullable: true),
                ReplacedByTokenHash = table.Column<string>(type: "text", nullable: true),
                CreatedByIp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true),
                RevokedByIp = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: true)
            },
            constraints: table =>
            {
                table.PrimaryKey("PK_RefreshTokens", x => x.Id);
                table.ForeignKey("FK_RefreshTokens_AspNetUsers_UserId", x => x.UserId, "AspNetUsers", "Id", onDelete: ReferentialAction.Cascade);
            });
        migrationBuilder.CreateIndex(name: "IX_AspNetUsers_PhoneNumber", table: "AspNetUsers", column: "PhoneNumber", unique: true, filter: "\"PhoneNumber\" IS NOT NULL");
        migrationBuilder.CreateIndex(name: "IX_RefreshTokens_TokenHash", table: "RefreshTokens", column: "TokenHash", unique: true);
        migrationBuilder.CreateIndex(name: "IX_RefreshTokens_UserId_ExpiresAt", table: "RefreshTokens", columns: new[] { "UserId", "ExpiresAt" });
    }
    protected override void Down(MigrationBuilder migrationBuilder)
    {
        migrationBuilder.DropTable(name: "RefreshTokens");
        migrationBuilder.DropIndex(name: "IX_AspNetUsers_PhoneNumber", table: "AspNetUsers");
    }
}
