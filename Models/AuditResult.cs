using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LocalSecurityAudit.Models;

public class AuditResult
{
    public DateTime Timestamp { get; set; }
    public int HealthScore { get; set; }
    public List<AuditIssue> Findings { get; set; } = new();
    public Dictionary<string, JsonElement>? Metadata { get; set; }

    [JsonIgnore]
    public bool HasIncompleteCoverage => Metadata?.TryGetValue("CoverageStatus", out var status) == true
        && (status.ValueKind != JsonValueKind.String || status.GetString() != "complete");

    [JsonIgnore]
    public bool HasAssessment
    {
        get
        {
            if (HasIncompleteCoverage) return false;
            if (Findings.Count > 0) return true;
            if (Metadata == null) return false;
            string key = Metadata.ContainsKey("AnalyzedEventCount") ? "AnalyzedEventCount" : "EventCount";
            return Metadata.TryGetValue(key, out var count) && count.ValueKind == JsonValueKind.Number
                && count.TryGetInt32(out int value) && value > 0;
        }
    }
}
