using System;

namespace LocalSecurityAudit.Models;

public sealed class AuditActivityDay
{
    public DateTime Date { get; init; }
    public int Scans { get; set; }
    public int Findings { get; set; }
    public int AssessedScans { get; set; }
    public int ScoreSum { get; set; }
    public int ScopedAssessedScans { get; set; }
    public int ScopedScoreSum { get; set; }
}
