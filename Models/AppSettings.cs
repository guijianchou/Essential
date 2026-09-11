using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace LocalSecurityAudit.Models;

public sealed class AppSettings
{
    public string Mode { get; set; } = AppMode.Extended;
    public string Theme { get; set; } = "system";
    public string Language { get; set; } = "en";
    public string TokenUsagePeriod { get; set; } = "day";
    public bool MinimizeToTray { get; set; }
    public bool AutoScanEnabled { get; set; } = true;
    public int ScanIntervalHours { get; set; } = 4;
    public int FastScanRangeHours { get; set; } = 0;
    public int RetentionDays { get; set; } = 30;
    public int RetentionPolicyVersion { get; set; }
    public bool HighSeverityNotification { get; set; } = true;
    public bool ScanCompleteNotification { get; set; }
    public bool DiagnosticLoggingEnabled { get; set; }
    public string SecurityAuditInstructions { get; set; } = "";
    // Read the old shared setting once; new saves contain only the audit-specific field.
    [JsonPropertyName("AgentInstructions")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? LegacyAgentInstructions { get; set; }
    public string AiKernel { get; set; } = AiKernelCatalog.Codex;
    public List<AiTargetSettings> AiTargets { get; set; } = new();
    public int MaxConcurrentAnalysis { get; set; } = 3;
    public bool EnableSmartFiltering { get; set; } = true;
    public bool EnableCaching { get; set; } = true;
}

public sealed class AiTargetSettings
{
    public const string MainName = "Main";
    public const string FallbackName = "Fallback";

    public string Name { get; set; } = MainName;
    public bool IsActive { get; set; } = true;
    public string BaseUrl { get; set; } = "https://api.falsemeet.site";
    public string ApiKey { get; set; } = "";
    public string Mode { get; set; } = "responses";
    public const string LunaModel = "gpt-5.6-luna";

    public string Model { get; set; } = LunaModel;
    public string Effort { get; set; } = "medium";
}
