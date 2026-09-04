using System;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public sealed class AuditCompletedEventArgs : EventArgs
{
    public AuditResult Result { get; }

    public bool HasHighSeverityIssue => Result.Findings.Exists(issue =>
        string.Equals(issue.Severity, "High", StringComparison.OrdinalIgnoreCase));

    public AuditCompletedEventArgs(AuditResult result)
    {
        Result = result;
    }
}

public sealed class AuditFailedEventArgs : EventArgs
{
    public string Message { get; }

    public AuditFailedEventArgs(string message)
    {
        Message = message;
    }
}

public sealed class AuditProgressEventArgs : EventArgs
{
    public string Message { get; }

    public AuditProgressEventArgs(string message)
    {
        Message = message;
    }
}
