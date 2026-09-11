using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using LocalSecurityAudit.Models;
using Microsoft.Data.Sqlite;

namespace LocalSecurityAudit.Services;

public partial class DataStorageService
{
    public int RejectedLegacyRecords { get; private set; }

    private async IAsyncEnumerable<AuditResult> ReadHistoryAsync(DateTime? startUtc = null, DateTime? endUtc = null)
    {
        int rejected = 0;
        bool anyRows = false, anyValid = false;
        var runs = new HashSet<string>(StringComparer.Ordinal);
        foreach (string path in _historyPaths)
        {
            if (!File.Exists(path)) continue;
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = path, Mode = SqliteOpenMode.ReadOnly, DefaultTimeout = 5 }.ToString());
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT Timestamp, HealthScore, FindingsJson, MetadataJson FROM AuditResults WHERE (@start IS NULL OR Timestamp>=@start) AND (@end IS NULL OR Timestamp<@end) ORDER BY Timestamp, Id";
            command.Parameters.AddWithValue("@start", (object?)startUtc?.ToUniversalTime() ?? DBNull.Value);
            command.Parameters.AddWithValue("@end", (object?)endUtc?.ToUniversalTime() ?? DBNull.Value);
            using var reader = await command.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                anyRows = true;
                var result = ReadResult(reader);
                if ((path == _historyPaths[1] || result != null && AuditHistory.Text(result, "Mode") == "assistant")
                    && (result == null || !AuditHistory.ValidateLegacyResult(result)))
                { rejected++; continue; }
                if (result == null) continue;
                string run = AuditHistory.Text(result, "RunId");
                if (run.Length > 0 && !runs.Add(run)) continue;
                anyValid = true;
                yield return result;
            }
        }
        RejectedLegacyRecords = rejected;
        if (anyRows && !anyValid) throw new InvalidDataException(AppText.Get("No readable audit records were found."));
    }

    public async Task<(DateTime Cursor, int BestModelRank)> GetScanCheckpointAsync(string mode)
    {
        DateTime cursor = default;
        int rank = -1;
        var records = new List<AuditResult>();
        await foreach (var result in ReadHistoryAsync())
            records.Add(result);
        (cursor, rank) = AuditHistory.Checkpoint(records, mode);
        if (File.Exists(_historyPaths[0]))
        {
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            { DataSource = _historyPaths[0], Mode = SqliteOpenMode.ReadOnly }.ToString());
            await connection.OpenAsync();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='ScanCheckpoints'";
            if (Convert.ToInt32(await command.ExecuteScalarAsync()) > 0)
            {
                command.CommandText = "SELECT ModelRank, ScanEnd FROM ScanCheckpoints WHERE Scope=@scope";
                command.Parameters.AddWithValue("@scope", mode == AppMode.Full ? "full" : "standard");
                using var reader = await command.ExecuteReaderAsync();
                while (await reader.ReadAsync())
                {
                    DateTime end = AsUtc(reader.GetDateTime(1));
                    if (end > DateTime.UtcNow) continue;
                    if (end > cursor) cursor = end;
                    rank = Math.Max(rank, reader.GetInt32(0));
                }
            }
        }
        return (cursor, rank);
    }

    private static async Task SaveCheckpointAsync(SqliteConnection connection, SqliteTransaction transaction, AuditResult result)
    {
        foreach (string mode in new[] { AppMode.Extended, AppMode.Full })
        {
            if (!AuditHistory.Eligible(result, mode)) continue;
            AuditHistory.Window(result, out _, out var end);
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "INSERT INTO ScanCheckpoints(Scope,ModelRank,ScanEnd) VALUES(@scope,@rank,@end) ON CONFLICT(Scope,ModelRank) DO UPDATE SET ScanEnd=max(ScanEnd,excluded.ScanEnd)";
            command.Parameters.AddWithValue("@scope", mode == AppMode.Full ? "full" : "standard");
            command.Parameters.AddWithValue("@rank", AuditHistory.ModelRank(result));
            command.Parameters.AddWithValue("@end", end);
            await command.ExecuteNonQueryAsync();
        }
    }

    public async Task<List<AuditIssue>> GetEffectiveFindingsAsync()
    {
        var results = new List<AuditResult>();
        await foreach (var result in ReadHistoryAsync()) results.Add(result);
        return AuditHistory.EffectiveFindings(results);
    }
}
