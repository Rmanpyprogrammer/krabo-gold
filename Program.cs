using System.Text;
using krabo_gold.Data;
using krabo_gold.Models.Identity;
using krabo_gold.Services.Security;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis; 
using Hangfire;
using Hangfire.PostgreSql;
using Hangfire.Dashboard;
using krabo_gold.Middleware;
using krabo_gold.Services.Sms;
using krabo_gold.Services.Auth;
using krabo_gold.Services.Gateway;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSwaggerGen();
builder.Services.AddOpenApi();

builder.Services.Configure<SabaNovinOptions>(
    builder.Configuration.GetSection("Sms:SabaNovin"));

builder.Services.AddHttpClient<ISmsSender, SabaNovinSmsSender>(
    client =>
    {
        client.Timeout = TimeSpan.FromSeconds(10);
    });



// PostgreSQL
var connectionString = builder.Configuration
    .GetConnectionString("DefaultConnection");

if (string.IsNullOrWhiteSpace(connectionString))
{
    throw new InvalidOperationException(
        "DefaultConnection is not configured.");
}

//hangfire
builder.Services.AddHangfire(config =>
    config.UsePostgreSqlStorage(options =>
        options.UseNpgsqlConnection(
            builder.Configuration.GetConnectionString("DefaultConnection"))));

builder.Services.AddHangfireServer();






builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(connectionString));

// Identity
builder.Services
    .AddIdentity<AppUser, AppRole>(options =>
    {
        options.User.RequireUniqueEmail = false;

        options.Password.RequiredLength = 8;
        options.Password.RequireDigit = true;
        options.Password.RequireLowercase = true;
        options.Password.RequireUppercase = true;
        options.Password.RequireNonAlphanumeric = false;

        options.Lockout.AllowedForNewUsers = true;
        options.Lockout.MaxFailedAccessAttempts = 5;
        options.Lockout.DefaultLockoutTimeSpan =
            TimeSpan.FromMinutes(15);
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// JWT
var jwt = builder.Configuration.GetSection("Jwt");

var jwtKey = jwt["Key"];
var issuer = jwt["Issuer"];
var audience = jwt["Audience"];

if (string.IsNullOrWhiteSpace(jwtKey) ||
    Encoding.UTF8.GetByteCount(jwtKey) < 32 ||
    string.IsNullOrWhiteSpace(issuer) ||
    string.IsNullOrWhiteSpace(audience))
{
    throw new InvalidOperationException(
        "JWT configuration is missing or invalid.");
}

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme =
            JwtBearerDefaults.AuthenticationScheme;

        options.DefaultChallengeScheme =
            JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters =
            new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,

                ValidateAudience = true,
                ValidAudience = audience,

                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,

                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(jwtKey)),

                ClockSkew = TimeSpan.FromSeconds(30)
            };
    });

// Authorization
builder.Services.AddAuthorization();


// Redis
var redisSection = builder.Configuration.GetSection("Redis");

var redisHost = redisSection["Host"];
var redisPort = redisSection.GetValue<int?>("Port");
var redisUser = redisSection["User"];
var redisPassword = redisSection["Password"];

if (string.IsNullOrWhiteSpace(redisHost) ||
    redisPort is null or <= 0 or > 65535 ||
    string.IsNullOrWhiteSpace(redisUser) ||
    string.IsNullOrWhiteSpace(redisPassword))
{
    throw new InvalidOperationException(
        "Redis configuration is missing or invalid.");
}

var redisOptions = new ConfigurationOptions
{
    AbortOnConnectFail = false,
    User = redisUser,
    Password = redisPassword
};

redisOptions.EndPoints.Add(redisHost, redisPort.Value);

builder.Services.AddSingleton<IConnectionMultiplexer>(
    _ => ConnectionMultiplexer.Connect(redisOptions));

builder.Services.AddScoped<ICaptchaService, CaptchaService>();
builder.Services.Configure<OtpOptions>(builder.Configuration.GetSection("Otp"));
builder.Services.AddScoped<IOtpService, OtpService>();
builder.Services.AddScoped<TokenService>();
builder.Services.AddHttpClient("GatewayBackend", client => client.Timeout = TimeSpan.FromSeconds(30));

//cors
builder.Services.AddCors(options =>
{
    options.AddPolicy("Frontend", policy =>
    {
        policy
            .WithOrigins("http://localhost:3000")
            .AllowCredentials()
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

var app = builder.Build();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<GlobalRateLimitMiddleware>();

var hangfireUsername = builder.Configuration["HangfireDashboard:Username"];
var hangfirePassword = builder.Configuration["HangfireDashboard:Password"];

if (string.IsNullOrWhiteSpace(hangfireUsername) ||
    string.IsNullOrWhiteSpace(hangfirePassword))
{
    throw new Exception("Hangfire dashboard username/password is not configured.");
}

app.UseHangfireDashboard("/hangfire", new DashboardOptions
{
    Authorization = new[]
    {
        new HangfireBasicAuthFilter(
            hangfireUsername,
            hangfirePassword
        )
    }
});

app.UseSwagger();
app.UseSwaggerUI();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await db.Database.MigrateAsync();

    await DbSeeder.SeedAdminAsync(scope.ServiceProvider);

}








if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseRouting();
app.UseCors("Frontend");

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapGet("/", () => Results.Ok(new
{
    service = "krabo_gold",
    status = "running"
})).AllowAnonymous();

app.Run();


public class HangfireBasicAuthFilter : IDashboardAuthorizationFilter
{
    private readonly string _username;
    private readonly string _password;

    public HangfireBasicAuthFilter(
        string username,
        string password
    )
    {
        _username = username;
        _password = password;
    }

    public bool Authorize(DashboardContext context)
    {
        var httpContext = context.GetHttpContext();

        var authorizationHeader =
            httpContext.Request.Headers.Authorization.ToString();

        if (string.IsNullOrWhiteSpace(authorizationHeader) ||
            !authorizationHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            Challenge(httpContext);
            return false;
        }

        try
        {
            var encodedCredentials = authorizationHeader
                .Substring("Basic ".Length)
                .Trim();

            var credentialBytes = Convert.FromBase64String(encodedCredentials);

            var credentials = Encoding.UTF8.GetString(credentialBytes);

            var separatorIndex = credentials.IndexOf(':');

            if (separatorIndex <= 0)
            {
                Challenge(httpContext);
                return false;
            }

            var username = credentials.Substring(0, separatorIndex);
            var password = credentials.Substring(separatorIndex + 1);

            if (username == _username && password == _password)
            {
                return true;
            }
        }
        catch
        {
            // invalid auth header
        }

        Challenge(httpContext);
        return false;
    }

    private static void Challenge(HttpContext httpContext)
    {
        httpContext.Response.Headers.WWWAuthenticate =
            "Basic realm=\"Hangfire Dashboard\"";

        httpContext.Response.StatusCode =
            StatusCodes.Status401Unauthorized;
    }
}