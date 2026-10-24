namespace krabo_gold.Middleware;

public sealed class SecurityHeadersMiddleware
{
    private readonly RequestDelegate _next;
    public SecurityHeadersMiddleware(RequestDelegate next) => _next = next;
    public async Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            var h = context.Response.Headers;
            h["X-Content-Type-Options"] = "nosniff";
            h["X-Frame-Options"] = "DENY";
            h["Referrer-Policy"] = "strict-origin-when-cross-origin";
            h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
            if (!context.Request.Path.StartsWithSegments("/swagger"))
                h["Content-Security-Policy"] = "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'";
            if (context.Request.IsHttps) h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
            return Task.CompletedTask;
        });
        await _next(context);
    }
}
