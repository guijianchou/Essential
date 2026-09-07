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

public enum AuditStage { Collect, Route, Analyze, Save, Translate, Complete }
public enum AuditStepState { Pending, Active, Done, Skipped, Failed }

public sealed class AuditProgressEventArgs : EventArgs
{
    public AuditStage Stage { get; }
    public AuditStepState State { get; }
    public string MessageKey { get; }
    public object?[] Arguments { get; }
    public string Message => AppText.Format(MessageKey, Arguments);
    public int CompletedBatches { get; init; }
    public int TotalBatches { get; init; }

    public AuditProgressEventArgs(AuditStage stage, AuditStepState state, string message, params object?[] arguments)
    {
        Stage = stage;
        State = state;
        MessageKey = message;
        Arguments = arguments;
    }
}

// Report synchronously so terminal scan events cannot overtake queued progress callbacks.
internal sealed class AuditProgressReporter(Action<AuditProgressEventArgs> report) : IProgress<AuditProgressEventArgs>
{
    public void Report(AuditProgressEventArgs value) => report(value);
}
