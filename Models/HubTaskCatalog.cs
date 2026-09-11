using System;
using System.Collections.Generic;
using System.Linq;

namespace LocalSecurityAudit.Models;

public sealed record HubTaskDefinition(string Id, string Title, string Glyph);

// The navigation entry, Hub rule card and audit request share the same task id.
public static class HubTaskCatalog
{
    public const string SecurityAuditId = "security-audit";
    public static IReadOnlyList<HubTaskDefinition> Tasks { get; } = new[]
    {
        new HubTaskDefinition(SecurityAuditId, "Security audit", "\uEA18")
    };

    public static HubTaskDefinition Get(string id) => Tasks.FirstOrDefault(task => task.Id == id)
        ?? throw new ArgumentException("Unknown Hub task.", nameof(id));
}
