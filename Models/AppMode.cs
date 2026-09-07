namespace LocalSecurityAudit.Models;

public static class AppMode
{
    public const string Assistant = "assistant";
    public const string Extended = "extended";

    public static string Normalize(string? mode) => mode == Extended ? Extended : Assistant;
}
