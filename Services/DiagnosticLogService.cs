using System;
using System.IO;
using System.Text;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public sealed class DiagnosticLogService
{
    private static readonly Encoding LogEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    private readonly object _writeLock = new();
    private readonly string _logPath;
    private readonly SettingsService _settingsService;

    public DiagnosticLogService(SettingsService settingsService)
    {
        _settingsService = settingsService;
        var appDataPath = Path.GetDirectoryName(settingsService.SettingsPath)!;

        Directory.CreateDirectory(appDataPath);
        _logPath = Path.Combine(appDataPath, "diagnostic.log");
    }

    public string LogPath => _logPath;

    public void Write(string message)
    {
        if (!_settingsService.Current.DiagnosticLoggingEnabled
            || string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        try
        {
            string line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [{Environment.CurrentManagedThreadId}] {Sanitize(message)}{Environment.NewLine}";
            lock (_writeLock)
            {
                File.AppendAllText(_logPath, line, LogEncoding);
            }
        }
        catch (IOException)
        {
            // Diagnostics must never interrupt an audit.
        }
        catch (UnauthorizedAccessException)
        {
            // Diagnostics must never interrupt an audit.
        }
    }

    public void WriteException(string operation, Exception exception)
    {
        var messages = new StringBuilder(operation);
        for (var current = exception; current != null; current = current.InnerException)
        {
            messages.Append(" | ");
            messages.Append(current.GetType().Name);
            messages.Append(": ");
            messages.Append(Sanitize(current.Message));
        }

        Write(messages.ToString());
    }

    private string Sanitize(string value)
    {
        var sanitized = value
            .Replace("\r", "\\r", StringComparison.Ordinal)
            .Replace("\n", "\\n", StringComparison.Ordinal);
        foreach (var target in _settingsService.Current.AiTargets)
        {
            if (!string.IsNullOrWhiteSpace(target.ApiKey))
            {
                sanitized = sanitized.Replace(target.ApiKey, "[redacted]", StringComparison.Ordinal);
            }
        }

        return sanitized;
    }
}
