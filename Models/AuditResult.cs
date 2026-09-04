using System;
using System.Collections.Generic;
using System.Text.Json;

namespace LocalSecurityAudit.Models;

public class AuditResult
{
    public DateTime Timestamp { get; set; }
    public int HealthScore { get; set; }
    public List<AuditIssue> Findings { get; set; } = new();
    public Dictionary<string, JsonElement>? Metadata { get; set; }
}
