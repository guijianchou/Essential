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

    public EventLogService(DiagnosticLogService diagnosticLogService)
    {
        _diagnosticLogService = diagnosticLogService;
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

    public async Task<List<SecurityEvent>> ReadAllEventsAsync(
        DateTime from,
        DateTime to,
        CancellationToken cancellationToken = default,
        IProgress<AuditProgressEventArgs>? progress = null)
    {
        var stopwatch = Stopwatch.StartNew();
        _diagnosticLogService.Write(
            $"Event log read started: from={from:O}, to={to:O}");
        return await Task.Run(async () =>
        {
            var events = new List<SecurityEvent>();

            try
            {
                ReportChannel(0, "Security");
                await foreach (var evt in ReadSecurityEventsAsync(from, to, cancellationToken))
                {
                    events.Add(evt);
                }

                ReportChannel(1, "System");
                await foreach (var evt in ReadSystemEventsAsync(from, to, cancellationToken))
                {
                    events.Add(evt);
                }

                ReportChannel(2, "Application");
                await foreach (var evt in ReadApplicationEventsAsync(from, to, cancellationToken))
                {
                    events.Add(evt);
                }

                ReportChannel(3, "Setup");
                await foreach (var evt in ReadSetupEventsAsync(from, to, cancellationToken))
                {
                    events.Add(evt);
                }

                ReportChannel(4, "Firewall (Security)");
                // Windows Filtering Platform audit events are in Security, not the Firewall channel.
                await foreach (var evt in ReadFirewallEventsAsync(from, to, cancellationToken))
                {
                    events.Add(evt);
                }

                _diagnosticLogService.Write(
                    $"Event log read completed: events={events.Count}, elapsedMs={stopwatch.ElapsedMilliseconds}");
                return events;
            }
            catch (Exception ex)
            {
                _diagnosticLogService.WriteException(
                    $"Event log read failed: elapsedMs={stopwatch.ElapsedMilliseconds}",
                    ex);
                throw;
            }

            void ReportChannel(int completed, string channel) => progress?.Report(
                new(AuditStage.Collect, AuditStepState.Active, "Reading {0}; {1:N0} events collected", channel, events.Count)
                { CompletedUnits = completed, TotalUnits = 5 });
        }, cancellationToken);
    }

    private async IAsyncEnumerable<SecurityEvent> ReadEventsFromLogAsync(
        string logName,
        string xpathQuery,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        await Task.Run(() => { }, cancellationToken); // Ensure async context

        EventLogQuery query = new(logName, PathType.LogName, xpathQuery);

        using EventLogReader reader = new(query);

        EventRecord? eventRecord;
        while ((eventRecord = reader.ReadEvent()) != null)
        {
            cancellationToken.ThrowIfCancellationRequested();

            using (eventRecord)
            {
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

        return $"*[System[TimeCreated[@SystemTime >= '{utcFrom}' and @SystemTime <= '{utcTo}'] and {systemPredicate}]]";
    }
}
