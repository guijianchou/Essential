using System;
using System.Collections.Generic;
using System.Linq;

namespace LocalSecurityAudit.Models;

public static class AiKernelCatalog
{
    public const string Codex = "codex";
    public const string Pi = "pi";

    public static IReadOnlyList<string> Kernels { get; } = Array.AsReadOnly(new[] { Codex, Pi });

    public static string Normalize(string? kernel) => Kernels.FirstOrDefault(candidate =>
        string.Equals(candidate, kernel?.Trim(), StringComparison.OrdinalIgnoreCase)) ?? Codex;
}
