using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace krabo_gold.Services.Gateway;

public sealed class SwaggerAnonymousOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        if (context.MethodInfo.IsDefined(typeof(AllowAnonymousAttribute), inherit: true))
        {
            // An empty operation-level security list overrides the global
            // Swagger Bearer requirement for this endpoint only.
            operation.Security = new List<OpenApiSecurityRequirement>();
        }
    }
}
