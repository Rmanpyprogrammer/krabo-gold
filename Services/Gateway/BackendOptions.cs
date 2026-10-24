namespace krabo_gold.Services.Gateway;

public sealed class BackendOptions
{
    public string BaseUrl { get; set; } = string.Empty;
    public string ServiceToken { get; set; } = string.Empty;
    public string[] AllowedPathPrefixes { get; set; } = [];
}
