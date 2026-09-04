using System;
using System.Collections.Generic;
using System.Linq;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public static class IssueCategorizer
{
    private static readonly Dictionary<int, (IssueCategory Category, IssueSeverity Severity, string Title)> EventIdMap = new()
    {
        // Authentication
        { 4625, (IssueCategory.Authentication, IssueSeverity.High, "Failed login attempt") },
        { 4624, (IssueCategory.Authentication, IssueSeverity.Low, "Successful login") },
        { 4648, (IssueCategory.Authentication, IssueSeverity.Medium, "Explicit credential logon") },
        { 4634, (IssueCategory.Authentication, IssueSeverity.Low, "Account logged off") },

        // Authorization & Privilege
        { 4672, (IssueCategory.Authorization, IssueSeverity.High, "Special privileges assigned") },
        { 4673, (IssueCategory.Authorization, IssueSeverity.Medium, "Privileged service called") },
        { 4728, (IssueCategory.Authorization, IssueSeverity.High, "Member added to security-enabled group") },
        { 4732, (IssueCategory.Authorization, IssueSeverity.High, "Member added to local group") },
        { 4756, (IssueCategory.Authorization, IssueSeverity.High, "Member added to universal group") },

        // Configuration
        { 4719, (IssueCategory.Configuration, IssueSeverity.Critical, "System audit policy changed") },
        { 4739, (IssueCategory.Configuration, IssueSeverity.Medium, "Domain policy changed") },
        { 5024, (IssueCategory.NetworkSecurity, IssueSeverity.High, "Windows Firewall service stopped") },
        { 5025, (IssueCategory.NetworkSecurity, IssueSeverity.High, "Windows Firewall service stopped") },
        { 7036, (IssueCategory.Stability, IssueSeverity.Medium, "Service state changed") },

        // Encryption & Security
        { 4723, (IssueCategory.Encryption, IssueSeverity.Medium, "Password change attempt") },
        { 4724, (IssueCategory.Encryption, IssueSeverity.Medium, "Password reset attempt") },

        // Policy Violations
        { 4657, (IssueCategory.PolicyViolation, IssueSeverity.Medium, "Registry value modified") },
        { 4663, (IssueCategory.PolicyViolation, IssueSeverity.Medium, "Object access attempt") },
        { 4688, (IssueCategory.Application, IssueSeverity.Low, "New process created") },

        // Audit Failures
        { 1102, (IssueCategory.AuditFailure, IssueSeverity.Critical, "Audit log was cleared") },
        { 4616, (IssueCategory.AuditFailure, IssueSeverity.High, "System time changed") },

        // System Issues
        { 7000, (IssueCategory.Stability, IssueSeverity.Medium, "Service failed to start") },
        { 7001, (IssueCategory.Stability, IssueSeverity.Medium, "Service dependency failure") },
        { 7022, (IssueCategory.Stability, IssueSeverity.High, "Service hung on starting") },
        { 7023, (IssueCategory.Stability, IssueSeverity.High, "Service terminated with error") },
        { 7034, (IssueCategory.Stability, IssueSeverity.High, "Service crashed unexpectedly") },

        // Network Security
        { 5152, (IssueCategory.NetworkSecurity, IssueSeverity.Medium, "Windows Firewall blocked packet") },
        { 5157, (IssueCategory.NetworkSecurity, IssueSeverity.Medium, "Windows Firewall blocked connection") },
    };

    public static AuditIssueEnhanced CategorizeIssue(AuditIssue issue)
    {
        var enhanced = new AuditIssueEnhanced
        {
            Title = issue.Description,
            Description = issue.Description,
            RootCause = issue.RootCause,
            Recommendation = issue.Recommendation,
            DetectedAt = issue.DetectedAt,
            Category = MapCategory(issue.Category),
            Severity = MapSeverity(issue.Severity)
        };

        AddComplianceTags(enhanced);
        return enhanced;
    }

    public static AuditIssueEnhanced CategorizeFromEventId(int eventId, string description, string rootCause, DateTime timestamp)
    {
        var enhanced = new AuditIssueEnhanced
        {
            EventId = eventId.ToString(),
            Description = description,
            RootCause = rootCause,
            DetectedAt = timestamp
        };

        if (EventIdMap.TryGetValue(eventId, out var mapping))
        {
            enhanced.Category = mapping.Category;
            enhanced.Severity = mapping.Severity;
            enhanced.Title = mapping.Title;
        }
        else
        {
            enhanced.Category = InferCategoryFromDescription(description);
            enhanced.Severity = IssueSeverity.Medium;
            enhanced.Title = description;
        }

        AddComplianceTags(enhanced);
        return enhanced;
    }

    private static IssueCategory MapCategory(string category)
    {
        return category?.ToLowerInvariant() switch
        {
            "login" or "authentication" => IssueCategory.Authentication,
            "privilege" or "authorization" => IssueCategory.Authorization,
            "firewall" or "network" or "networksecurity" => IssueCategory.NetworkSecurity,
            "system" => IssueCategory.Stability,
            "configuration" => IssueCategory.Configuration,
            "application" or "program" or "process" or "software" => IssueCategory.Application,
            "filesystem" or "file system" => IssueCategory.FileSystem,
            "registry" => IssueCategory.Registry,
            "audit" or "auditfailure" => IssueCategory.AuditFailure,
            "policy" or "compliance" => IssueCategory.PolicyViolation,
            "encryption" or "crypto" => IssueCategory.Encryption,
            _ => IssueCategory.Unknown
        };
    }

    private static IssueSeverity MapSeverity(string severity)
    {
        return severity?.ToLowerInvariant() switch
        {
            "critical" => IssueSeverity.Critical,
            "high" => IssueSeverity.High,
            "medium" => IssueSeverity.Medium,
            "low" => IssueSeverity.Low,
            "info" or "information" => IssueSeverity.Info,
            _ => IssueSeverity.Medium
        };
    }

    private static IssueCategory InferCategoryFromDescription(string description)
    {
        var lower = (description ?? string.Empty).ToLowerInvariant();

        if (lower.Contains("login") || lower.Contains("logon") || lower.Contains("authentication"))
            return IssueCategory.Authentication;
        if (lower.Contains("privilege") || lower.Contains("permission") || lower.Contains("authorization"))
            return IssueCategory.Authorization;
        if (lower.Contains("firewall") || lower.Contains("network") || lower.Contains("port"))
            return IssueCategory.NetworkSecurity;
        if (lower.Contains("process") || lower.Contains("program") || lower.Contains("application") || lower.Contains("software"))
            return IssueCategory.Application;
        if (lower.Contains("registry"))
            return IssueCategory.Registry;
        if (lower.Contains("file system") || lower.Contains("filesystem"))
            return IssueCategory.FileSystem;
        if (lower.Contains("password") || lower.Contains("encryption") || lower.Contains("crypto"))
            return IssueCategory.Encryption;
        if (lower.Contains("service") || lower.Contains("crash") || lower.Contains("hang"))
            return IssueCategory.Stability;
        if (lower.Contains("audit") || lower.Contains("log cleared"))
            return IssueCategory.AuditFailure;
        if (lower.Contains("policy") || lower.Contains("compliance"))
            return IssueCategory.PolicyViolation;

        return IssueCategory.Unknown;
    }

    private static void AddComplianceTags(AuditIssueEnhanced issue)
    {
        issue.ComplianceTags.Clear();

        switch (issue.Category)
        {
            case IssueCategory.Authentication:
            case IssueCategory.Authorization:
                issue.ComplianceTags.AddRange(new[] { "CIS 5.1", "NIST AC-2", "PCI-DSS 8.1" });
                break;
            case IssueCategory.Encryption:
                issue.ComplianceTags.AddRange(new[] { "CIS 2.3", "NIST SC-13", "PCI-DSS 3.4" });
                break;
            case IssueCategory.AuditFailure:
                issue.ComplianceTags.AddRange(new[] { "CIS 8.2", "NIST AU-2", "PCI-DSS 10.1" });
                break;
            case IssueCategory.Configuration:
                issue.ComplianceTags.AddRange(new[] { "CIS 5.3", "NIST CM-6" });
                break;
            case IssueCategory.NetworkSecurity:
                issue.ComplianceTags.AddRange(new[] { "CIS 9.1", "NIST SC-7", "PCI-DSS 1.2" });
                break;
        }
    }
}
