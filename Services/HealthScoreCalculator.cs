using System;
using System.Collections.Generic;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public enum HealthBand
{
    Good,
    Warning,
    Risk
}

public readonly record struct HealthScoreBreakdown(
    int Score,
    int HighCount,
    int MediumCount,
    int LowCount,
    int HighDeduction,
    int MediumDeduction,
    int LowDeduction)
{
    public int TotalFindings => HighCount + MediumCount + LowCount;
    public int TotalDeduction => HighDeduction + MediumDeduction + LowDeduction;
    public string Verdict => HealthScoreCalculator.GetVerdict(Score);
    public HealthBand Band => HealthScoreCalculator.GetBand(Score);
}

/// <summary>
/// Turns a list of findings into a 0-100 health score. Each severity has a weight
/// and a cap so that a flood of low findings cannot zero the score on its own, while
/// a single high finding still moves it visibly.
/// </summary>
public static class HealthScoreCalculator
{
    public const int HighWeight = 15;
    public const int HighCap = 60;
    public const int MediumWeight = 6;
    public const int MediumCap = 25;
    public const double LowWeight = 1.5;
    public const int LowCap = 15;

    public const int GoodThreshold = 80;
    public const int WarningThreshold = 50;

    public static HealthScoreBreakdown Calculate(IEnumerable<AuditIssue> issues)
    {
        int high = 0, medium = 0, low = 0;
        foreach (var issue in issues)
        {
            switch (IssueCategorizer.ParseSeverity(issue.Severity))
            {
                case IssueSeverity.Critical:
                case IssueSeverity.High:
                    high++;
                    break;
                case IssueSeverity.Medium:
                    medium++;
                    break;
                default:
                    low++;
                    break;
            }
        }

        return Calculate(high, medium, low);
    }

    public static HealthScoreBreakdown Calculate(int highCount, int mediumCount, int lowCount)
    {
        int highDeduction = Math.Min(HighCap, highCount * HighWeight);
        int mediumDeduction = Math.Min(MediumCap, mediumCount * MediumWeight);
        int lowDeduction = Math.Min(LowCap, (int)Math.Round(lowCount * LowWeight, MidpointRounding.AwayFromZero));
        int score = Math.Clamp(100 - highDeduction - mediumDeduction - lowDeduction, 0, 100);
        return new HealthScoreBreakdown(score, highCount, mediumCount, lowCount, highDeduction, mediumDeduction, lowDeduction);
    }

    public static string GetVerdict(int score)
    {
        return score >= GoodThreshold
            ? AppText.Get("Healthy")
            : score >= WarningThreshold
                ? AppText.Get("Needs review")
                : AppText.Get("At risk");
    }

    public static HealthBand GetBand(int score)
    {
        return score >= GoodThreshold
            ? HealthBand.Good
            : score >= WarningThreshold
                ? HealthBand.Warning
                : HealthBand.Risk;
    }
}
