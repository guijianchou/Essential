using System;
using System.Collections.Generic;

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

public class AuditIssueEnhanced
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public IssueSeverity Severity { get; set; } = IssueSeverity.Medium;
    public IssueCategory Category { get; set; } = IssueCategory.Unknown;
    public string EventId { get; set; } = string.Empty;
    public string Source { get; set; } = string.Empty;
    public string RootCause { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    public string AffectedResource { get; set; } = string.Empty;
    public List<string> ComplianceTags { get; set; } = new();
    public bool IsExpanded { get; set; }
    public bool IsDismissed { get; set; }

    public string CategoryGroup => Category switch
    {
        IssueCategory.Authentication or IssueCategory.Authorization or IssueCategory.Encryption
            or IssueCategory.PolicyViolation or IssueCategory.AuditFailure => "Security Issues",
        IssueCategory.Configuration or IssueCategory.MissingSettings => "System Issues",
        IssueCategory.Performance or IssueCategory.Resources or IssueCategory.Stability => "System Issues",
        IssueCategory.Application or IssueCategory.FileSystem or IssueCategory.Registry => "Application Issues",
        IssueCategory.NetworkSecurity => "Network Issues",
        _ => "Other Issues"
    };

    public string CategoryLabel => Category switch
    {
        IssueCategory.Authentication => "Authentication / Login",
        IssueCategory.Authorization => "Authorization / Privilege",
        IssueCategory.Encryption => "Encryption",
        IssueCategory.Configuration => "System / Configuration",
        IssueCategory.MissingSettings => "System / Settings",
        IssueCategory.Performance => "System / Performance",
        IssueCategory.Resources => "System / Resources",
        IssueCategory.Stability => "System / Stability",
        IssueCategory.Application => "Application / Program",
        IssueCategory.FileSystem => "Application / File System",
        IssueCategory.Registry => "Application / Registry",
        IssueCategory.PolicyViolation => "Policy / Compliance",
        IssueCategory.AuditFailure => "Audit / Logging",
        IssueCategory.NetworkSecurity => "Firewall / Network",
        _ => "Other"
    };

    public string DetectedAtText => DetectedAt == default
        ? "Time unavailable"
        : DetectedAt.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    public string CategoryIcon => Category switch
    {
        IssueCategory.Authentication => "",
        IssueCategory.Authorization => "",
        IssueCategory.Encryption => "",
        IssueCategory.Configuration => "",
        IssueCategory.MissingSettings => "",
        IssueCategory.Performance => "",
        IssueCategory.Resources => "",
        IssueCategory.Stability => "",
        IssueCategory.Application => "",
        IssueCategory.PolicyViolation => "",
        IssueCategory.AuditFailure => "",
        IssueCategory.NetworkSecurity => "",
        IssueCategory.FileSystem => "",
        IssueCategory.Registry => "",
        _ => ""
    };

    public string CategoryColor => Category switch
    {
        IssueCategory.Authentication or IssueCategory.Authorization or IssueCategory.Encryption => "#DC2626",
        IssueCategory.Configuration or IssueCategory.MissingSettings => "#F59E0B",
        IssueCategory.Performance or IssueCategory.Resources or IssueCategory.Stability => "#0EA5E9",
        IssueCategory.Application or IssueCategory.FileSystem or IssueCategory.Registry => "#8B5CF6",
        IssueCategory.NetworkSecurity => "#0EA5E9",
        IssueCategory.PolicyViolation or IssueCategory.AuditFailure => "#8B5CF6",
        _ => "#6B7280"
    };

    public string SeverityBadgeColor => Severity switch
    {
        IssueSeverity.Critical => "#F97316",
        IssueSeverity.High => "#DC2626",
        IssueSeverity.Medium => "#F59E0B",
        IssueSeverity.Low => "#10B981",
        IssueSeverity.Info => "#3B82F6",
        _ => "#6B7280"
    };
}
