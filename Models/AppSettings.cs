using System.Collections.Generic;

namespace LocalSecurityAudit.Models;

public sealed class AppSettings
{
    public string Theme { get; set; } = "system";
    public bool MinimizeToTray { get; set; }
    public bool AutoScanEnabled { get; set; } = true;
    public int ScanIntervalHours { get; set; } = 4;
    public int FastScanRangeHours { get; set; } = 0;
    public int RetentionDays { get; set; } = 7;
    public bool HighSeverityNotification { get; set; } = true;
    public bool ScanCompleteNotification { get; set; }
    public bool DiagnosticLoggingEnabled { get; set; }
    public string AgentInstructions { get; set; } = "";
    public List<AiTargetSettings> AiTargets { get; set; } = new();
    public int MaxConcurrentAnalysis { get; set; } = 1;
    public bool EnableSmartFiltering { get; set; } = true;
    public bool EnableCaching { get; set; } = true;
}

public sealed class AiTargetSettings
{
    public string Name { get; set; } = "Primary Target";
    public bool IsActive { get; set; } = true;
    public string BaseUrl { get; set; } = "https://api.falsemeet.site";
    public string ApiKey { get; set; } = "";
    public string Mode { get; set; } = "responses";
    public string Model { get; set; } = "gpt-5.6-sol";
    public string Effort { get; set; } = "medium";
}
