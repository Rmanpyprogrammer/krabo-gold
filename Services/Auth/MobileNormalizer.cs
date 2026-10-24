namespace krabo_gold.Services.Auth;

public static class MobileNormalizer
{
    public static string? NormalizeIranianMobile(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var s = value.Trim()
            .Replace('۰','0').Replace('۱','1').Replace('۲','2').Replace('۳','3').Replace('۴','4')
            .Replace('۵','5').Replace('۶','6').Replace('۷','7').Replace('۸','8').Replace('۹','9')
            .Replace('٠','0').Replace('١','1').Replace('٢','2').Replace('٣','3').Replace('٤','4')
            .Replace('٥','5').Replace('٦','6').Replace('٧','7').Replace('٨','8').Replace('٩','9');
        if (s.StartsWith("+98")) s = "0" + s[3..];
        else if (s.StartsWith("0098")) s = "0" + s[4..];
        else if (s.StartsWith("98") && s.Length == 12) s = "0" + s[2..];
        return s.Length == 11 && s.StartsWith("09") && s.All(char.IsAsciiDigit) ? s : null;
    }
}
