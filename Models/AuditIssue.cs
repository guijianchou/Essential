using System;

namespace LocalSecurityAudit.Models;

public class AuditIssue
{
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty; // "High", "Medium", "Low"
    public string Category { get; set; } = string.Empty; // "Login", "Privilege", "Firewall", "System"
    public string RootCause { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; }
}
