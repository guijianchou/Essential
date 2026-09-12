using System;
using System.Collections.Generic;
using System.Linq;
using LocalSecurityAudit.Views;

namespace LocalSecurityAudit.Models;

public sealed record HubTaskDefinition(string Id, string Title, string Glyph, Type PageType);

// The navigation entry, Hub rule card and audit request share the same task id.
public static class HubTaskCatalog
{
    public const string SecurityAuditId = "security-audit";
    public const string OptimizationId = "system-optimization";

    public static IReadOnlyList<HubTaskDefinition> Tasks { get; } = new[]
    {
        new HubTaskDefinition(SecurityAuditId, "Security audit", "\uEA18", typeof(DashboardPage)),
        new HubTaskDefinition(OptimizationId, "Optimization", "\uE771", typeof(OptimizationPage))
    };

    public static bool TryGet(string? id, out HubTaskDefinition definition)
    {
        definition = Tasks.FirstOrDefault(task => string.Equals(task.Id, id, StringComparison.OrdinalIgnoreCase))!;
        return definition != null;
    }

    public static HubTaskDefinition Get(string id) => TryGet(id, out var definition)
        ? definition
        : throw new ArgumentException("Unknown Hub task.", nameof(id));
}
