using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
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
    private static readonly int[] SecurityEventIds = { 4624, 4625, 4648, 4672, 4720, 4732 };
    private static readonly int[] FirewallEventIds = { 5152, 5157 };

    public async IAsyncEnumerable<SecurityEvent> ReadSecurityEventsAsync(
        DateTime from,
        DateTime to,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        string query = BuildQuery(from, to, $"({string.Join(" or ", SecurityEventIds.Select(id => $"EventID={id}"))})");

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
        // Level=2 (Error) or Level=3 (Warning)
        string query = BuildQuery(from, to, "(Level=2 or Level=3)");

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
        string query = BuildQuery(from, to, "(Level=2 or Level=3)");

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
        string query = BuildQuery(from, to, $"({string.Join(" or ", FirewallEventIds.Select(id => $"EventID={id}"))})");

        await foreach (var evt in ReadEventsFromLogAsync(
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
            query,
            cancellationToken))
        {
            yield return evt;
        }
    }

    public async Task<List<SecurityEvent>> ReadAllEventsAsync(
        DateTime from,
        DateTime to,
        CancellationToken cancellationToken = default)
    {
        var stopwatch = Stopwatch.StartNew();
        _diagnosticLogService.Write(
            $"Event log read started: from={from:O}, to={to:O}");
        return await Task.Run(async () =>
        {
            var events = new List<SecurityEvent>();

            try
            {
                await foreach (var evt in ReadSecurityEventsAsync(from, to, cancellationToken))
                {
                    events.Add(evt);
                }

                await foreach (var evt in ReadSystemEventsAsync(from, to, cancellationToken))
                {
                    events.Add(evt);
                }

                await foreach (var evt in ReadApplicationEventsAsync(from, to, cancellationToken))
                {
                    events.Add(evt);
                }

                try
                {
                    await foreach (var evt in ReadFirewallEventsAsync(from, to, cancellationToken))
                    {
                        events.Add(evt);
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    _diagnosticLogService.WriteException(
                        "Firewall event log read failed; continuing without firewall events",
                        ex);
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

    private static string BuildQuery(DateTime from, DateTime to, string systemPredicate)
    {
        string utcFrom = from.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);
        string utcTo = to.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

        return $"*[System[TimeCreated[@SystemTime >= '{utcFrom}' and @SystemTime <= '{utcTo}'] and {systemPredicate}]]";
    }
}
