using System.Text.RegularExpressions;

namespace GpoRemediator.Domain;

public static class WindowsAccount
{
    // Normalize a common typing mistake for consistent session and audit identity matching.
    public static string Normalize(string? value) => (value ?? "").Trim().Replace('/', '\\');
    public static bool IsOperator(string value) => value.Length<=256&&value.IndexOfAny(['\r','\n','\0'])<0&&Regex.IsMatch(value, @"^[^\\/\s]+\\[^\\/\s]+$");
}
