using System.Collections.Generic;
using System.Linq;

namespace LocalSecurityAudit.Models;

public sealed record AuditChannelCoverage(string LogName, string Status, int EventCount, string Reason);

public sealed class EventCollectionResult
{
    public List<SecurityEvent> Events { get; } = new();
    public List<AuditChannelCoverage> Channels { get; } = new();
    public string CoverageStatus => Channels.Any(channel => channel.Status is "unavailable" or "truncated")
        ? "partial" : Channels.Any(channel => channel.Status == "skipped") ? "limited" : "complete";
    public string CoverageNotes => string.Join("; ", Channels.Where(channel => channel.Status != "complete")
        .Select(channel => $"{channel.LogName}: {channel.Status} ({channel.Reason})"));
}
