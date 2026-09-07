using System.Collections.Generic;

namespace LocalSecurityAudit.Models;

public sealed class AppSettings
{
    public string Theme { get; set; } = "system";
    public string Language { get; set; } = "en";
    public bool MinimizeToTray { get; set; }
    public bool AutoScanEnabled { get; set; } = true;
    public int ScanIntervalHours { get; set; } = 4;
    public int FastScanRangeHours { get; set; } = 0;
    public int RetentionDays { get; set; } = 30;
    public int RetentionPolicyVersion { get; set; }
    public bool HighSeverityNotification { get; set; } = true;
    public bool ScanCompleteNotification { get; set; }
    public bool DiagnosticLoggingEnabled { get; set; }
    public string AgentInstructions { get; set; } = "";
    public List<AiTargetSettings> AiTargets { get; set; } = new();
    public string OptimizationModel { get; set; } = AiModelCatalog.Astra;
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
