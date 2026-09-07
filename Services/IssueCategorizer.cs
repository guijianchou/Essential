using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

/// <summary>
/// Deterministic classification helpers shared by the AI normalization step and the
/// dashboard. Category follows the Windows event ID when it is known so that the same
/// event always lands in the same dashboard section; severity stays with the analysis.
/// </summary>
public static class IssueCategorizer
{
    public static readonly string[] ContractCategories =
    {
        "Login", "Privilege", "Firewall", "System", "Application",
        "Network", "Encryption", "Policy", "Audit", "Other"
    };

    public static readonly string[] ContractSeverities = { "High", "Medium", "Low" };

    private static readonly Dictionary<int, (IssueCategory Category, IssueSeverity Severity, string Title)> EventIdMap = new()
    {
        // Login / authentication
        { 4624, (IssueCategory.Authentication, IssueSeverity.Low, "Successful logon") },
        { 4625, (IssueCategory.Authentication, IssueSeverity.Medium, "Failed logon attempt") },
        { 4634, (IssueCategory.Authentication, IssueSeverity.Low, "Account logged off") },
        { 4647, (IssueCategory.Authentication, IssueSeverity.Low, "User initiated logoff") },
        { 4648, (IssueCategory.Authentication, IssueSeverity.Medium, "Logon with explicit credentials") },
        { 4740, (IssueCategory.Authentication, IssueSeverity.Medium, "Account locked out") },
        { 4776, (IssueCategory.Authentication, IssueSeverity.Low, "Credential validation") },
        { 4778, (IssueCategory.Authentication, IssueSeverity.Low, "Session reconnected") },
        { 4779, (IssueCategory.Authentication, IssueSeverity.Low, "Session disconnected") },

        // Privilege / accounts and groups
        { 4672, (IssueCategory.Authorization, IssueSeverity.Low, "Special privileges assigned to new logon") },
        { 4673, (IssueCategory.Authorization, IssueSeverity.Medium, "Privileged service called") },
        { 4674, (IssueCategory.Authorization, IssueSeverity.Medium, "Operation attempted on privileged object") },
        { 4697, (IssueCategory.Authorization, IssueSeverity.High, "Service installed") },
        { 4720, (IssueCategory.Authorization, IssueSeverity.High, "User account created") },
        { 4722, (IssueCategory.Authorization, IssueSeverity.Medium, "User account enabled") },
        { 4724, (IssueCategory.Authorization, IssueSeverity.Medium, "Password reset attempt") },
        { 4728, (IssueCategory.Authorization, IssueSeverity.High, "Member added to security-enabled global group") },
        { 4732, (IssueCategory.Authorization, IssueSeverity.High, "Member added to security-enabled local group") },
        { 4738, (IssueCategory.Authorization, IssueSeverity.Medium, "User account changed") },
        { 4756, (IssueCategory.Authorization, IssueSeverity.High, "Member added to security-enabled universal group") },

        // Firewall and network
        { 4946, (IssueCategory.NetworkSecurity, IssueSeverity.Medium, "Firewall rule added") },
        { 4947, (IssueCategory.NetworkSecurity, IssueSeverity.Medium, "Firewall rule modified") },
        { 4948, (IssueCategory.NetworkSecurity, IssueSeverity.Medium, "Firewall rule deleted") },
        { 4950, (IssueCategory.NetworkSecurity, IssueSeverity.Medium, "Firewall setting changed") },
        { 5024, (IssueCategory.NetworkSecurity, IssueSeverity.Low, "Windows Firewall service started") },
        { 5025, (IssueCategory.NetworkSecurity, IssueSeverity.High, "Windows Firewall service stopped") },
        { 5031, (IssueCategory.NetworkSecurity, IssueSeverity.Medium, "Firewall blocked an application from accepting connections") },
        { 5152, (IssueCategory.NetworkSecurity, IssueSeverity.Low, "Windows Filtering Platform blocked a packet") },
        { 5157, (IssueCategory.NetworkSecurity, IssueSeverity.Low, "Windows Filtering Platform blocked a connection") },

        // Policy
        { 4719, (IssueCategory.PolicyViolation, IssueSeverity.High, "System audit policy changed") },
        { 4739, (IssueCategory.PolicyViolation, IssueSeverity.Medium, "Domain policy changed") },
        { 4817, (IssueCategory.PolicyViolation, IssueSeverity.Medium, "Auditing settings on object changed") },
        { 4902, (IssueCategory.PolicyViolation, IssueSeverity.Medium, "Per-user audit policy table created") },
        { 4907, (IssueCategory.PolicyViolation, IssueSeverity.Medium, "Auditing settings on object changed") },

        // Encryption and credentials
        { 4723, (IssueCategory.Encryption, IssueSeverity.Low, "Password change attempt") },

        // Audit and logging
        { 1102, (IssueCategory.AuditFailure, IssueSeverity.High, "Audit log was cleared") },
        { 1104, (IssueCategory.AuditFailure, IssueSeverity.Medium, "Security log is full") },
        { 1108, (IssueCategory.AuditFailure, IssueSeverity.Medium, "Event logging service error") },
        { 4616, (IssueCategory.AuditFailure, IssueSeverity.Medium, "System time changed") },

        // System / services
        { 7000, (IssueCategory.Stability, IssueSeverity.Medium, "Service failed to start") },
        { 7001, (IssueCategory.Stability, IssueSeverity.Medium, "Service dependency failed") },
        { 7022, (IssueCategory.Stability, IssueSeverity.Medium, "Service hung on starting") },
        { 7023, (IssueCategory.Stability, IssueSeverity.Medium, "Service terminated with error") },
        { 7024, (IssueCategory.Stability, IssueSeverity.Medium, "Service terminated with service-specific error") },
        { 7026, (IssueCategory.Stability, IssueSeverity.Low, "Boot-start or system-start driver failed to load") },
        { 7031, (IssueCategory.Stability, IssueSeverity.Medium, "Service terminated unexpectedly") },
        { 7034, (IssueCategory.Stability, IssueSeverity.Medium, "Service terminated unexpectedly") },
        { 7036, (IssueCategory.Stability, IssueSeverity.Low, "Service state changed") },
        { 7040, (IssueCategory.Configuration, IssueSeverity.Low, "Service start type changed") },
        { 7045, (IssueCategory.Configuration, IssueSeverity.Medium, "New service installed") },
        { 4698, (IssueCategory.Configuration, IssueSeverity.Medium, "Scheduled task created") },
        { 4702, (IssueCategory.Configuration, IssueSeverity.Medium, "Scheduled task updated") },
        { 6008, (IssueCategory.Stability, IssueSeverity.Medium, "Unexpected shutdown") },
        { 41, (IssueCategory.Stability, IssueSeverity.Medium, "System rebooted without a clean shutdown") },

        // Application
        { 1000, (IssueCategory.Application, IssueSeverity.Low, "Application error") },
        { 1001, (IssueCategory.Application, IssueSeverity.Low, "Windows Error Reporting") },
        { 1002, (IssueCategory.Application, IssueSeverity.Low, "Application hang") },
        { 4688, (IssueCategory.Application, IssueSeverity.Low, "New process created") },
        { 4657, (IssueCategory.Registry, IssueSeverity.Medium, "Registry value modified") },
        { 4663, (IssueCategory.FileSystem, IssueSeverity.Low, "Object access attempt") },
    };

    public static AuditIssueEnhanced CategorizeIssue(AuditIssue issue)
    {
        var category = ParseCategory(issue.Category);
        if (int.TryParse(issue.EventId, out int eventId)
            && TryGetEventClassification(eventId, issue.LogName, issue.Source, out var mappedCategory, out _, out _))
        {
            category = mappedCategory;
        }
        else if (string.Equals(issue.LogName, "Setup", StringComparison.OrdinalIgnoreCase)) category = IssueCategory.Configuration;

        return new AuditIssueEnhanced
        {
            Key = issue.Key,
            EventRef = issue.EventRef,
            Title = AppText.IsChinese && issue.HasBilingualText ? issue.TitleZh : issue.Title,
            Description = AppText.IsChinese && issue.HasBilingualText ? issue.DescriptionZh : issue.Description,
            RootCause = AppText.IsChinese && issue.HasBilingualText ? issue.RootCauseZh : issue.RootCause,
            Recommendation = AppText.IsChinese && issue.HasBilingualText ? issue.RecommendationZh : issue.Recommendation,
            NeedsTranslation = !issue.HasBilingualText,
            Confidence = ParseConfidence(issue.Confidence),
            Affected = issue.Affected,
            Occurrences = Math.Max(1, issue.Occurrences),
            RelatedEventRefs = issue.RelatedEventRefs?.ToList() ?? new List<string>(),
            DetectedAt = issue.DetectedAt,
            EventTimestamp = ParseTimestamp(issue.EventTimestamp),
            EventId = issue.EventId,
            Source = issue.Source,
            LogName = issue.LogName,
            EventRecordId = issue.EventRecordId,
            EventDescription = issue.EventDescription,
            EventAdditionalData = issue.EventAdditionalData,
            UserName = issue.UserName,
            IpAddress = issue.IpAddress,
            FirstSeenUtc = issue.FirstSeenUtc,
            LastSeenUtc = issue.LastSeenUtc,
            SupportingEventCount = Math.Max(issue.SupportingEventCount, issue.RelatedEventRefs?.Count ?? 0),
            Category = category,
            Severity = ParseSeverity(issue.Severity)
        };
    }

    public static bool TryGetEventClassification(
        int eventId,
        string? logName,
        string? provider,
        out IssueCategory category,
        out IssueSeverity severity,
        out string title)
    {
        category = IssueCategory.Unknown;
        severity = IssueSeverity.Medium;
        title = string.Empty;
        string log = logName?.ToLowerInvariant() ?? string.Empty;
        if (log == "setup")
        {
            category = IssueCategory.Configuration;
            return true;
        }
        if (log == "system" && eventId == 1001
            && (string.Equals(provider, "Microsoft-Windows-WER-SystemErrorReporting", StringComparison.OrdinalIgnoreCase)
                || string.Equals(provider, "BugCheck", StringComparison.OrdinalIgnoreCase)))
        {
            category = IssueCategory.Stability;
            title = "Windows restarted after a bugcheck";
            return true;
        }

        // Event IDs belong to a log/provider namespace, not a machine-wide taxonomy.
        bool matchesLog = log switch
        {
            "system" => eventId is 7000 or 7001 or 7022 or 7023 or 7024 or 7026 or 7031 or 7034 or 7036 or 7040 or 7045
                || (eventId == 41 && string.Equals(provider, "Microsoft-Windows-Kernel-Power", StringComparison.OrdinalIgnoreCase))
                || (eventId == 6008 && string.Equals(provider, "EventLog", StringComparison.OrdinalIgnoreCase)),
            "application" => eventId is 1000 or 1001 or 1002,
            "security" => eventId is 1102 or 1104 or 1108 || eventId is >= 4600 and <= 5999,
            "" => true,
            _ => false
        };
        if (matchesLog && EventIdMap.TryGetValue(eventId, out var mapping))
        {
            category = mapping.Category;
            severity = mapping.Severity;
            title = mapping.Title;
            return true;
        }

        return false;
    }

    public static string ToContractCategory(IssueCategory category)
    {
        return category switch
        {
            IssueCategory.Authentication => "Login",
            IssueCategory.Authorization => "Privilege",
            IssueCategory.NetworkSecurity => "Firewall",
            IssueCategory.Application or IssueCategory.FileSystem or IssueCategory.Registry => "Application",
            IssueCategory.Configuration or IssueCategory.MissingSettings
                or IssueCategory.Performance or IssueCategory.Resources or IssueCategory.Stability => "System",
            IssueCategory.Encryption => "Encryption",
            IssueCategory.PolicyViolation => "Policy",
            IssueCategory.AuditFailure => "Audit",
            _ => "Other"
        };
    }

    public static string ToContractSeverity(IssueSeverity severity)
    {
        return severity switch
        {
            IssueSeverity.Critical or IssueSeverity.High => "High",
            IssueSeverity.Medium => "Medium",
            IssueSeverity.Low or IssueSeverity.Info => "Low",
            _ => "Medium"
        };
    }

    public static IssueCategory ParseCategory(string? category)
    {
        return category?.Trim().ToLowerInvariant() switch
        {
            "login" or "logon" or "authentication" or "auth" => IssueCategory.Authentication,
            "privilege" or "privileges" or "authorization" or "account" or "accounts" => IssueCategory.Authorization,
            "firewall" or "network" or "networksecurity" or "network security" or "connectivity" => IssueCategory.NetworkSecurity,
            "system" or "stability" or "service" or "services" or "kernel" => IssueCategory.Stability,
            "configuration" or "config" => IssueCategory.Configuration,
            "missingsettings" or "settings" => IssueCategory.MissingSettings,
            "performance" => IssueCategory.Performance,
            "resources" or "resource" => IssueCategory.Resources,
            "application" or "applications" or "program" or "process" or "software" or "app" => IssueCategory.Application,
            "filesystem" or "file system" or "file" => IssueCategory.FileSystem,
            "registry" => IssueCategory.Registry,
            "audit" or "auditing" or "auditfailure" or "logging" => IssueCategory.AuditFailure,
            "policy" or "compliance" or "group policy" => IssueCategory.PolicyViolation,
            "encryption" or "crypto" or "cryptography" or "certificate" or "tls" => IssueCategory.Encryption,
            _ => IssueCategory.Unknown
        };
    }

    public static IssueSeverity ParseSeverity(string? severity)
    {
        return severity?.Trim().ToLowerInvariant() switch
        {
            "critical" => IssueSeverity.Critical,
            "high" or "error" or "severe" => IssueSeverity.High,
            "medium" or "moderate" or "warning" => IssueSeverity.Medium,
            "low" or "minor" => IssueSeverity.Low,
            "info" or "information" or "informational" => IssueSeverity.Info,
            _ => IssueSeverity.Medium
        };
    }

    /// <summary>Returns "High", "Medium", "Low", or an empty string when the value is absent or unknown.</summary>
    public static string ParseConfidence(string? confidence)
    {
        return confidence?.Trim().ToLowerInvariant() switch
        {
            "high" or "certain" or "strong" => "High",
            "medium" or "moderate" or "probable" or "likely" => "Medium",
            "low" or "weak" or "possible" or "uncertain" => "Low",
            _ => string.Empty
        };
    }

    /// <summary>Normalizes a pattern key to lowercase snake_case, at most 48 characters.</summary>
    public static string NormalizeKey(string? key)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(key.Length);
        bool previousUnderscore = true;
        foreach (char character in key.Trim().ToLowerInvariant())
        {
            bool keep = character is >= 'a' and <= 'z' or >= '0' and <= '9';
            if (keep)
            {
                builder.Append(character);
                previousUnderscore = false;
            }
            else if (!previousUnderscore)
            {
                builder.Append('_');
                previousUnderscore = true;
            }

            if (builder.Length >= 48)
            {
                break;
            }
        }

        return builder.ToString().Trim('_');
    }

    public static IssueCategory InferCategoryFromDescription(string? description)
    {
        var lower = (description ?? string.Empty).ToLowerInvariant();

        if (lower.Contains("firewall") || lower.Contains("filtering platform"))
            return IssueCategory.NetworkSecurity;
        if (lower.Contains("login") || lower.Contains("logon") || lower.Contains("authentication") || lower.Contains("credential"))
            return IssueCategory.Authentication;
        if (lower.Contains("privilege") || lower.Contains("permission") || lower.Contains("authorization") || lower.Contains("group member"))
            return IssueCategory.Authorization;
        if (lower.Contains("network") || lower.Contains("dns") || lower.Contains("dhcp") || lower.Contains("adapter"))
            return IssueCategory.NetworkSecurity;
        if (lower.Contains("audit") || lower.Contains("log cleared") || lower.Contains("event log"))
            return IssueCategory.AuditFailure;
        if (lower.Contains("policy") || lower.Contains("compliance"))
            return IssueCategory.PolicyViolation;
        if (lower.Contains("password") || lower.Contains("encryption") || lower.Contains("crypto") || lower.Contains("bitlocker") || lower.Contains("certificate") || lower.Contains("schannel"))
            return IssueCategory.Encryption;
        if (lower.Contains("registry"))
            return IssueCategory.Registry;
        if (lower.Contains("file system") || lower.Contains("filesystem"))
            return IssueCategory.FileSystem;
        if (lower.Contains("service") || lower.Contains("crash") || lower.Contains("hang") || lower.Contains("driver") || lower.Contains("kernel") || lower.Contains("shutdown"))
            return IssueCategory.Stability;
        if (lower.Contains("process") || lower.Contains("program") || lower.Contains("application") || lower.Contains("software") || lower.Contains(".exe"))
            return IssueCategory.Application;

        return IssueCategory.Unknown;
    }

    private static DateTime ParseTimestamp(string? value)
    {
        return DateTime.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var timestamp)
            ? timestamp
            : default;
    }
}
