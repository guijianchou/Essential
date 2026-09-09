namespace LocalSecurityAudit.Models;

public static class AppMode
{
    public const string Assistant = "assistant";
    public const string Extended = "extended";
    public const string Full = "full";

    public static string Normalize(string? mode) => mode is Extended or Full ? mode : Assistant;
    public static bool RequiresElevation(string? mode) => Normalize(mode) == Full;
    public static string Label(string mode) => mode switch
    {
        Full => "Full-access mode",
        Extended => "Extended mode",
        _ => "Assistant mode"
    };
}
