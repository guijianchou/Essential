using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace LocalSecurityAudit.Models;

/// <summary>
/// One finding as returned by the AI analysis contract and as persisted in the
/// audit database. String enumerations (<see cref="Severity"/>, <see cref="Confidence"/>,
/// <see cref="Category"/>) are normalized by <c>AiAnalysisService</c> before storage.
/// </summary>
public class AuditIssue
{
    /// <summary>Stable snake_case identifier for the finding pattern, used to merge duplicates.</summary>
    public string Key { get; set; } = string.Empty;
    public string EventRef { get; set; } = string.Empty;
    public string EventId { get; set; } = string.Empty;
    public string EventTimestamp { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string LogName { get; set; } = string.Empty;
    public string EventRecordId { get; set; } = string.Empty;
    public string EventDescription { get; set; } = string.Empty;
    public string EventAdditionalData { get; set; } = string.Empty;
    public string UserName { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public DateTime FirstSeenUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public int SupportingEventCount { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty; // High | Medium | Low
    public string Confidence { get; set; } = string.Empty; // High | Medium | Low
    public string Category { get; set; } = string.Empty; // Login | Privilege | Firewall | System | Application | Network | Encryption | Policy | Audit | Other
    public string Affected { get; set; } = string.Empty;
    public string RootCause { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public string TitleZh { get; set; } = string.Empty;
    public string DescriptionZh { get; set; } = string.Empty;
    public string RootCauseZh { get; set; } = string.Empty;
    public string RecommendationZh { get; set; } = string.Empty;
    public string AnalysisModel { get; set; } = string.Empty;
    public string OriginalAnalysisModel { get; set; } = string.Empty;
    public DateTime? OptimizedAtUtc { get; set; }

    [JsonIgnore]
    public bool HasBilingualText => !string.IsNullOrWhiteSpace(Title)
        && !string.IsNullOrWhiteSpace(Description)
        && !string.IsNullOrWhiteSpace(RootCause)
        && !string.IsNullOrWhiteSpace(Recommendation)
        && !string.IsNullOrWhiteSpace(TitleZh)
        && !string.IsNullOrWhiteSpace(DescriptionZh)
        && !string.IsNullOrWhiteSpace(RootCauseZh)
        && !string.IsNullOrWhiteSpace(RecommendationZh);
    public int Occurrences { get; set; } = 1;
    public List<string> RelatedEventRefs { get; set; } = new();
    public DateTime DetectedAt { get; set; }
}
