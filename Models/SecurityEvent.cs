using System;

namespace LocalSecurityAudit.Models;

public class SecurityEvent
{
    public int EventId { get; set; }
    public DateTime Timestamp { get; set; }
    public string LogName { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty; // "Error", "Warning", "Information"
    public string? UserName { get; set; }
    public string? IpAddress { get; set; }
    public string? AdditionalData { get; set; }
}
