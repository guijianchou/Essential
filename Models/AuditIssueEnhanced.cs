using System;
using System.Collections.Generic;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit.Models;

public enum IssueCategory
{
    Authentication,
    Authorization,
    Encryption,
    Configuration,
    MissingSettings,
    Performance,
    Resources,
    Stability,
    Application,
    PolicyViolation,
    AuditFailure,
    NetworkSecurity,
    FileSystem,
    Registry,
    Unknown
}

public enum IssueSeverity
{
    Critical,
    High,
    Medium,
    Low,
    Info
}

/// <summary>
/// Presentation model for one finding: strongly typed severity and category plus
/// the display strings the dashboard binds to.
/// </summary>
public class AuditIssueEnhanced
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Key { get; set; } = string.Empty;
    public string EventRef { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public IssueSeverity Severity { get; set; } = IssueSeverity.Medium;
    public IssueCategory Category { get; set; } = IssueCategory.Unknown;
    public string Confidence { get; set; } = string.Empty;
    public string EventId { get; set; } = string.Empty;
    public DateTime EventTimestamp { get; set; }
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
    public string Affected { get; set; } = string.Empty;
    public string RootCause { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public bool NeedsTranslation { get; set; }
    public string SeverityText => AppText.Get(SeverityLabel);
    public int Occurrences { get; set; } = 1;
    public List<string> RelatedEventRefs { get; set; } = new();
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public List<string> ComplianceTags { get; set; } = new();

    /// <summary>Contract severity name used for filters and brushes: High, Medium or Low.</summary>
    public string SeverityLabel => Severity switch
    {
        IssueSeverity.Critical or IssueSeverity.High => "High",
        IssueSeverity.Medium => "Medium",
        _ => "Low"
    };

    public bool IsHigh => SeverityLabel == "High";
    public bool IsMedium => SeverityLabel == "Medium";
    public bool IsLow => SeverityLabel == "Low";

    public string CategoryLabel => AppText.Get(GetCategoryLabel(Category));

    public int CategoryOrder => GetCategoryOrder(Category);

    /// <summary>The headline shown on the card. Older records have no title, so fall back to the description.</summary>
    public string DisplayTitle => string.IsNullOrWhiteSpace(Title) ? Description : Title;

    /// <summary>The body shown under the headline; empty when the description already served as the title.</summary>
    public string DisplayDescription => string.IsNullOrWhiteSpace(Title) ? string.Empty : Description;

    public bool HasDisplayDescription => !string.IsNullOrWhiteSpace(DisplayDescription);
    public bool HasRootCause => !string.IsNullOrWhiteSpace(RootCause);
    public bool HasRecommendation => !string.IsNullOrWhiteSpace(Recommendation);
    public bool HasEventId => !string.IsNullOrWhiteSpace(EventId);
    public bool HasOccurrences => Occurrences > 1;
    public bool HasConfidence => !string.IsNullOrWhiteSpace(Confidence);
    public bool HasAffected => !string.IsNullOrWhiteSpace(Affected);

    public string EventIdLabel => HasEventId ? AppText.Format("Event {0}", EventId) : string.Empty;
    public string OccurrencesLabel => Occurrences > 1 ? AppText.Format("{0} occurrences", Occurrences) : string.Empty;
    public string ConfidenceLabel => HasConfidence ? AppText.Format("{0} confidence", AppText.Get(Confidence)) : string.Empty;

    public bool HasEvidence => !string.IsNullOrWhiteSpace(LogName)
        || !string.IsNullOrWhiteSpace(Source)
        || !string.IsNullOrWhiteSpace(EventRecordId)
        || !string.IsNullOrWhiteSpace(UserName)
        || !string.IsNullOrWhiteSpace(IpAddress)
        || SupportingEventCount > 0;

    public string EvidenceSummaryText
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(LogName)) parts.Add(LogName);
            if (!string.IsNullOrWhiteSpace(Source)) parts.Add(Source);
            if (HasEventId) parts.Add(EventIdLabel);
            if (!string.IsNullOrWhiteSpace(EventRecordId)) parts.Add(AppText.Format("record {0}", EventRecordId));
            if (!string.IsNullOrWhiteSpace(UserName)) parts.Add(AppText.Format("account {0}", UserName));
            if (!string.IsNullOrWhiteSpace(IpAddress)) parts.Add(AppText.Format("source {0}", IpAddress));
            return parts.Count == 0 ? AppText.Get("Evidence unavailable") : string.Join(" · ", parts);
        }
    }

    public string EvidenceTimeText
    {
        get
        {
            DateTime first = FirstSeenUtc == default ? EventTimestamp : FirstSeenUtc;
            DateTime last = LastSeenUtc == default ? EventTimestamp : LastSeenUtc;
            if (first == default && last == default) return AppText.Get("Observation time unavailable");
            if (first == default) first = last;
            if (last == default) last = first;
            string firstText = first.ToLocalTime().ToString("MMM d, HH:mm", AppText.Culture);
            string lastText = last.ToLocalTime().ToString("MMM d, HH:mm", AppText.Culture);
            return first == last ? AppText.Format("Observed {0}", firstText) : AppText.Format("Observed {0} to {1}", firstText, lastText);
        }
    }

    public string OccurrenceSummaryText
    {
        get
        {
            int supporting = Math.Max(0, SupportingEventCount);
            if (supporting > 0 && Occurrences > supporting)
            {
                return AppText.Format("{0} occurrences \u00B7 {1} supporting events", Occurrences, supporting);
            }

            if (supporting > 0)
            {
                return supporting == 1 ? AppText.Get("1 supporting event") : AppText.Format("{0} supporting events", supporting);
            }

            return Occurrences == 1 ? AppText.Get("1 occurrence") : AppText.Format("{0} occurrences", Occurrences);
        }
    }

    public string PriorityReasonText => HasRootCause
        ? RootCause
        : HasDisplayDescription ? DisplayDescription : AppText.Get("Review the supporting event details.");

    public string PriorityActionText => HasRecommendation
        ? Recommendation
        : AppText.Get("Review the affected account, host or service and confirm whether this activity was expected.");

    public string DetectedAtText => DetectedAt == default
        ? AppText.Get("Time unavailable")
        : DetectedAt.ToLocalTime().ToString("MMM d, HH:mm", AppText.Culture);

    public string EventTimestampText => EventTimestamp == default
        ? DetectedAtText
        : EventTimestamp.ToLocalTime().ToString("MMM d, HH:mm", AppText.Culture);

    public static string GetCategoryLabel(IssueCategory category)
    {
        return category switch
        {
            IssueCategory.Authentication => "Login",
            IssueCategory.Authorization => "Privilege",
            IssueCategory.NetworkSecurity => "Firewall and network",
            IssueCategory.Configuration or IssueCategory.MissingSettings
                or IssueCategory.Performance or IssueCategory.Resources or IssueCategory.Stability => "System",
            IssueCategory.Application or IssueCategory.FileSystem or IssueCategory.Registry => "Application",
            IssueCategory.Encryption => "Encryption",
            IssueCategory.PolicyViolation => "Policy",
            IssueCategory.AuditFailure => "Audit and logging",
            _ => "Other"
        };
    }

    public static int GetCategoryOrder(IssueCategory category)
    {
        return category switch
        {
            IssueCategory.Authentication => 0,
            IssueCategory.Authorization => 1,
            IssueCategory.NetworkSecurity => 2,
            IssueCategory.Configuration or IssueCategory.MissingSettings
                or IssueCategory.Performance or IssueCategory.Resources or IssueCategory.Stability => 3,
            IssueCategory.Application or IssueCategory.FileSystem or IssueCategory.Registry => 4,
            IssueCategory.Encryption => 5,
            IssueCategory.PolicyViolation => 6,
            IssueCategory.AuditFailure => 7,
            _ => 8
        };
    }
}
