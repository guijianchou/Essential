using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Linq;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public class EventLogService
{
    private readonly DiagnosticLogService _diagnosticLogService;
    private readonly SettingsService _settingsService;

    public EventLogService(DiagnosticLogService diagnosticLogService, SettingsService settingsService)
    {
        _diagnosticLogService = diagnosticLogService;
        _settingsService = settingsService;
    }

    // Key event IDs
    private static readonly int[] SecurityEventIds =
    {
        1102, 1104, 1108, 4616, 4624, 4625, 4634, 4647, 4648, 4657, 4663,
        4672, 4673, 4674, 4688, 4697, 4698, 4702, 4719, 4720, 4722, 4723,
        4724, 4728, 4732, 4738, 4739, 4740, 4756, 4776, 4778, 4779, 4817, 4902, 4907
    };
    private static readonly int[] FirewallEventIds = { 4946, 4947, 4948, 4950, 5024, 5025, 5031, 5152, 5157 };
    private const string FailureLevels = "(Level=1 or Level=2 or Level=3)";

    public async IAsyncEnumerable<SecurityEvent> ReadSecurityEventsAsync(
        DateTime from,
        DateTime to,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string query = BuildEventIdQuery("Security", from, to, SecurityEventIds);

        await foreach (var evt in ReadEventsFromLogAsync("Security", query, cancellationToken))
        {
            yield return evt;
        }
    }

    public async IAsyncEnumerable<SecurityEvent> ReadSystemEventsAsync(
        DateTime from,
        DateTime to,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string query = BuildQuery(from, to, FailureLevels);

        await foreach (var evt in ReadEventsFromLogAsync("System", query, cancellationToken))
        {
            yield return evt;
        }
    }

    public async IAsyncEnumerable<SecurityEvent> ReadApplicationEventsAsync(
        DateTime from,
        DateTime to,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string query = BuildQuery(from, to, FailureLevels);

        await foreach (var evt in ReadEventsFromLogAsync("Application", query, cancellationToken))
        {
            yield return evt;
        }
    }

    public async IAsyncEnumerable<SecurityEvent> ReadFirewallEventsAsync(
        DateTime from,
        DateTime to,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string query = BuildEventIdQuery("Security", from, to, FirewallEventIds);

        await foreach (var evt in ReadEventsFromLogAsync(
            "Security",
            query,
            cancellationToken))
        {
            yield return evt;
        }
    }

    public async IAsyncEnumerable<SecurityEvent> ReadSetupEventsAsync(
        DateTime from,
        DateTime to,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string query = BuildQuery(from, to, FailureLevels);
        await foreach (var evt in ReadEventsFromLogAsync("Setup", query, cancellationToken))
            yield return evt;
    }

    public async Task<EventCollectionResult> ReadAllEventsAsync(
        DateTime from,
        DateTime to,
        CancellationToken cancellationToken = default,
        IProgress<AuditProgressEventArgs>? progress = null)
    {
        _settingsService.EnsureExtendedMode();
        var stopwatch = Stopwatch.StartNew();
        _diagnosticLogService.Write(
            $"Event log read started: from={from:O}, to={to:O}");
        return await Task.Run(async () =>
        {
            var result = new EventCollectionResult();
            var queries = BuildCollectionQueries(_settingsService.IsFullMode, from, to);
            foreach (var (logName, query) in queries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                progress?.Report(new(AuditStage.Collect, AuditStepState.Active,
                    "Reading {0}; {1:N0} events collected", logName, result.Events.Count)
                    { CompletedUnits = result.Channels.Count, TotalUnits = queries.Count });
                if (query == null)
                {
                    result.Channels.Add(new(logName, "skipped", 0, "not_requested"));
                    continue;
                }
                var channelEvents = new List<SecurityEvent>();
                string status = "complete", reason = "none";
                try
                {
                    await foreach (var evt in ReadEventsFromLogAsync(logName, query, cancellationToken))
                    {
                        // Probe one extra event, like the external collector, without silently losing coverage.
                        if (channelEvents.Count == 2000) { status = "truncated"; reason = "limit"; break; }
                        channelEvents.Add(evt);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    channelEvents.Clear();
                    status = "unavailable";
                    reason = ex switch
                    {
                        UnauthorizedAccessException => "access_denied",
                        EventLogNotFoundException => "not_found",
                        EventLogException error when (error.HResult & 0xffff) == 5 => "access_denied",
                        _ => "query_failed"
                    };
                    // Log only the channel/status, never exception text containing event data.
                    _diagnosticLogService.Write($"Event channel unavailable: channel={logName}, reason={reason}");
                }
                result.Events.AddRange(channelEvents);
                result.Channels.Add(new(logName, status, channelEvents.Count, reason));
            }
            _diagnosticLogService.Write($"Event log read completed: events={result.Events.Count}, coverage={result.CoverageStatus}, elapsedMs={stopwatch.ElapsedMilliseconds}");
            return result;
        }, cancellationToken);
    }

    internal static List<(string LogName, string? Query)> BuildCollectionQueries(bool fullMode, DateTime from, DateTime to) =>
        new[] { "Security", "System", "Application", "Setup", "ForwardedEvents" }
            .Select(log => (log, log == "Security"
                ? fullMode ? BuildEventIdQuery(log, from, to, SecurityEventIds.Concat(FirewallEventIds).Distinct().ToArray()) : null
                : BuildQuery(from, to, FailureLevels))).ToList();

    private async IAsyncEnumerable<SecurityEvent> ReadEventsFromLogAsync(
        string logName,
        string xpathQuery,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        _settingsService.EnsureExtendedMode();
        if (logName == "Security" && !_settingsService.IsFullMode)
            throw new InvalidOperationException("Security collection is only enabled in full-access mode.");
        await Task.Run(() => { }, cancellationToken); // Ensure async context

        EventLogQuery query = new(logName, PathType.LogName, xpathQuery) { ReverseDirection = true };

        using EventLogReader reader = new(query);

        EventRecord? eventRecord;
        while ((eventRecord = reader.ReadEvent()) != null)
        {
            using (eventRecord)
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return EventLogParser.Parse(eventRecord, logName);
            }
        }
    }

    private static string BuildEventIdQuery(string logName, DateTime from, DateTime to, int[] eventIds)
    {
        // Windows Event Log limits XPath expression complexity; split long ID allowlists.
        return new XElement("QueryList", new XElement("Query", new XAttribute("Id", 0), new XAttribute("Path", logName),
            eventIds.Chunk(16).Select(ids => new XElement("Select", new XAttribute("Path", logName),
                BuildQuery(from, to, $"({string.Join(" or ", ids.Select(id => $"EventID={id}"))})")))))
            .ToString(SaveOptions.DisableFormatting);
    }

    private static string BuildQuery(DateTime from, DateTime to, string systemPredicate)
    {
        string utcFrom = from.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        string utcTo = to.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

        return $"*[System[TimeCreated[@SystemTime >= '{utcFrom}' and @SystemTime < '{utcTo}'] and {systemPredicate}]]";
    }
}
