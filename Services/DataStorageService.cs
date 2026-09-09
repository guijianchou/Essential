using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public partial class DataStorageService
{
    private readonly string _connectionString;
    private readonly string _dbPath;
    private readonly string[] _historyPaths;
    public string DatabasePath => _dbPath;
    public bool IsReadOnly { get; }

    private DataStorageService(string mode, string? dataDirectory)
    {
        IsReadOnly = AppMode.Normalize(mode) == AppMode.Assistant;
        _dbPath = GetDatabasePath(mode, dataDirectory);
        _historyPaths = new[] { GetDatabasePath(AppMode.Extended, dataDirectory), GetDatabasePath(AppMode.Assistant, dataDirectory) };
        Directory.CreateDirectory(Path.GetDirectoryName(_dbPath)!);
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _dbPath,
            Mode = IsReadOnly ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWriteCreate,
            DefaultTimeout = 5
        }.ToString();

        SQLitePCL.Batteries_V2.Init();
    }

    public static string GetDatabasePath(string mode, string? dataDirectory = null)
    {
        string root = dataDirectory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "LocalSecurityAudit");
        return Path.GetFullPath(AppMode.Normalize(mode) == AppMode.Assistant
            ? Path.Combine(root, "assistant", "audit_data.db") : Path.Combine(root, "audit_data.db"));
    }

    public static async Task<DataStorageService> CreateAsync(string mode = AppMode.Assistant, string? dataDirectory = null)
    {
        var service = new DataStorageService(mode, dataDirectory);
        // The viewer can create an empty schema, but opens existing assistant results read-only.
        if (!service.IsReadOnly || !File.Exists(service._dbPath)) await service.InitializeDatabaseAsync();
        return service;
    }

    private async Task InitializeDatabaseAsync()
    {
        string connectionString = IsReadOnly
            ? new SqliteConnectionStringBuilder(_connectionString) { Mode = SqliteOpenMode.ReadWriteCreate }.ToString()
            : _connectionString;
        using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();

        var createTableCmd = connection.CreateCommand();
        createTableCmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS AuditResults (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Timestamp DATETIME NOT NULL,
                HealthScore INTEGER NOT NULL,
                FindingsJson TEXT NOT NULL,
                MetadataJson TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_timestamp ON AuditResults(Timestamp DESC);
            CREATE TABLE IF NOT EXISTS ScanCheckpoints (
                Scope TEXT NOT NULL, ModelRank INTEGER NOT NULL, ScanEnd DATETIME NOT NULL,
                PRIMARY KEY (Scope, ModelRank)
            );
        ";

        await createTableCmd.ExecuteNonQueryAsync();
    }

    public async Task SaveAuditResultAsync(AuditResult result)
    {
        EnsureWritable();
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        using var transaction = connection.BeginTransaction();

        try
        {
            // Insert audit result
            var insertCmd = connection.CreateCommand();
            insertCmd.CommandText = @"
                INSERT INTO AuditResults (Timestamp, HealthScore, FindingsJson, MetadataJson)
                VALUES (@timestamp, @healthScore, @findings, @metadata)
            ";

            insertCmd.Parameters.AddWithValue("@timestamp", result.Timestamp.ToUniversalTime());
            insertCmd.Parameters.AddWithValue("@healthScore", result.HealthScore);
            insertCmd.Parameters.AddWithValue("@findings", JsonSerializer.Serialize(result.Findings));
            insertCmd.Parameters.AddWithValue("@metadata",
                result.Metadata != null ? JsonSerializer.Serialize(result.Metadata) : DBNull.Value);

            await insertCmd.ExecuteNonQueryAsync();
            await SaveCheckpointAsync(connection, transaction, result);

            transaction.Commit();
        }
        catch
        {
            transaction.Rollback();
            throw;
        }
    }

    public async Task<AuditResult?> GetTodayResultAsync()
    {
        return (await GetResultsAsync(DateTime.Today.ToUniversalTime(), DateTime.Today.AddDays(1).ToUniversalTime())).LastOrDefault();
    }

    public async Task<AuditResult?> GetLatestResultAsync(string? mode = null)
    {
        AuditResult? latest = null;
        await foreach (var result in ReadHistoryAsync())
            if ((mode == null || AuditHistory.Text(result, "Mode") == mode) && (latest == null || result.Timestamp >= latest.Timestamp)) latest = result;
        return latest;
    }

    public Task<List<AuditResult>> GetTrendsAsync(int days = 30)
    {
        var today = DateTime.Today;
        return GetResultsAsync(today.AddDays(1 - Math.Max(1, days)).ToUniversalTime(), today.AddDays(1).ToUniversalTime());
    }

    public async Task<List<AuditActivityDay>> GetAuditActivityAsync(DateTime today)
    {
        var days = new Dictionary<DateTime, AuditActivityDay>();
        await foreach (var result in ReadHistoryAsync(endUtc: today.Date.AddDays(1).ToUniversalTime()))
        {
            DateTime date = result.Timestamp.ToLocalTime().Date;
            if (!days.TryGetValue(date, out var day)) days[date] = day = new() { Date = date };
            day.Scans++;
            day.Findings += result.Findings.Count;
            if (result.HasAssessment)
            {
                day.AssessedScans++;
                day.ScoreSum += HealthScoreCalculator.Calculate(result.Findings).Score;
            }
        }
        return days.Values.OrderBy(day => day.Date).ToList();
    }

    public async Task<Dictionary<DateTime, int>> GetRecentAuditDatesAsync(DateTime today)
    {
        var dates = new Dictionary<DateTime, int>();
        await foreach (var result in ReadHistoryAsync(today.AddDays(-6).ToUniversalTime(), today.AddDays(1).ToUniversalTime()))
        {
            DateTime date = result.Timestamp.ToLocalTime().Date;
            dates[date] = dates.GetValueOrDefault(date) + 1;
        }
        return dates;
    }

    public async Task<List<AuditResult>> GetResultsAsync(DateTime startUtc, DateTime endUtc)
    {
        var results = new List<AuditResult>();
        await foreach (var result in ReadHistoryAsync(startUtc, endUtc)) results.Add(result);
        return results.OrderBy(result => result.Timestamp).ToList();
    }

    private static AuditResult? ReadResult(SqliteDataReader reader)
    {
        try
        {
            var findings = JsonSerializer.Deserialize<List<AuditIssue>>(reader.GetString(2));
            if (findings == null || findings.Any(issue => issue == null || issue.EventTimes == null || issue.RelatedEventRefs == null)) return null;
            return new AuditResult
            {
                Timestamp = AsUtc(reader.GetDateTime(0)),
                HealthScore = reader.GetInt32(1),
                Findings = findings,
                Metadata = reader.IsDBNull(3) ? null :
                    JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(reader.GetString(3))
            };
        }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidCastException or OverflowException)
        {
            // An unreadable row must not hide the remaining audit history.
            return null;
        }
    }

    private static DateTime AsUtc(DateTime timestamp)
    {
        return DateTime.SpecifyKind(timestamp, DateTimeKind.Utc);
    }

    public async Task CleanupOldDataAsync(int retentionDays = 30)
    {
        EnsureWritable();
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        // Preserve progress independently of the configurable history retention period.
        using var transaction = connection.BeginTransaction();
        var records = await GetResultsAsync(DateTime.SpecifyKind(DateTime.MinValue, DateTimeKind.Utc), DateTime.UtcNow.AddMinutes(1));
        foreach (var result in records.Where(result => AuditHistory.Text(result, "Mode") != AppMode.Assistant))
            await SaveCheckpointAsync(connection, transaction, result);
        var cleanupCmd = connection.CreateCommand();
        cleanupCmd.Transaction = transaction;
        cleanupCmd.CommandText = "DELETE FROM AuditResults WHERE Timestamp < @cutoff";
        cleanupCmd.Parameters.AddWithValue("@cutoff", DateTime.Today.AddDays(1 - Math.Max(1, retentionDays)).ToUniversalTime());

        await cleanupCmd.ExecuteNonQueryAsync();
        transaction.Commit();
    }

    public async Task VacuumDatabaseAsync()
    {
        EnsureWritable();
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var vacuumCmd = connection.CreateCommand();
        vacuumCmd.CommandText = "VACUUM";

        await vacuumCmd.ExecuteNonQueryAsync();
    }

    public async Task<int> GetAuditRecordCountAsync()
    {
        int count = 0;
        await foreach (var result in ReadHistoryAsync()) count++;
        return count;
    }

    public Task<List<(long Id, string OriginalJson, List<AuditIssue> Findings)>> GetLegacyFindingsAsync()
        => ReadStoredFindingsAsync(true, CancellationToken.None);

    public Task<List<(long Id, string OriginalJson, List<AuditIssue> Findings)>> GetOptimizationRecordsAsync(CancellationToken cancellationToken = default)
        => ReadStoredFindingsAsync(false, cancellationToken);

    private async Task<List<(long Id, string OriginalJson, List<AuditIssue> Findings)>> ReadStoredFindingsAsync(bool legacyOnly, CancellationToken cancellationToken)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, FindingsJson FROM AuditResults ORDER BY Timestamp DESC";
        using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var results = new List<(long, string, List<AuditIssue>)>();
        while (await reader.ReadAsync(cancellationToken))
        {
            string json = reader.GetString(1);
            List<AuditIssue>? findings;
            try { findings = JsonSerializer.Deserialize<List<AuditIssue>>(json); }
            catch (JsonException) { continue; }
            if (findings == null || findings.Any(issue => issue == null)) continue;
            if (!legacyOnly || findings.Any(issue => !issue.HasBilingualText))
                results.Add((reader.GetInt64(0), json, findings));
        }
        return results;
    }

    public async Task<string?> UpdateOptimizedFindingsAsync(long id, string originalJson,
        IReadOnlyDictionary<int, AuditIssue> updates, string model, CancellationToken cancellationToken = default)
    {
        EnsureWritable();
        if (updates.Count == 0 || JsonNode.Parse(originalJson) is not JsonArray stored) return null;
        foreach (var (index, finding) in updates)
        {
            if (index < 0 || index >= stored.Count || stored[index] is not JsonObject original
                || original.Deserialize<AuditIssue>() is not { } previous || !finding.HasBilingualText
                || finding.AnalysisModel != model || !AiModelCatalog.CanOptimize(previous.AnalysisModel, model)) return null;
            var reviewed = JsonSerializer.SerializeToNode(finding)!;
            foreach (string property in new[] { nameof(AuditIssue.Title), nameof(AuditIssue.Description), nameof(AuditIssue.RootCause),
                nameof(AuditIssue.Recommendation), nameof(AuditIssue.TitleZh), nameof(AuditIssue.DescriptionZh), nameof(AuditIssue.RootCauseZh),
                nameof(AuditIssue.RecommendationZh), nameof(AuditIssue.Severity), nameof(AuditIssue.Confidence) })
                original[property] = reviewed[property]?.DeepClone();
            original[nameof(AuditIssue.AnalysisModel)] = model;
            original[nameof(AuditIssue.OriginalAnalysisModel)] = previous.OptimizedAtUtc == null ? previous.AnalysisModel : previous.OriginalAnalysisModel;
            original[nameof(AuditIssue.OptimizedAtUtc)] = JsonSerializer.SerializeToNode(DateTime.UtcNow);
        }
        string updatedJson = stored.ToJsonString();
        int score = HealthScoreCalculator.Calculate(stored.Deserialize<List<AuditIssue>>()!).Score;
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken);
        using var command = connection.CreateCommand();
        command.CommandText = "UPDATE AuditResults SET FindingsJson=@updated, HealthScore=@score WHERE Id=@id AND FindingsJson=@original";
        command.Parameters.AddWithValue("@updated", updatedJson);
        command.Parameters.AddWithValue("@score", score);
        command.Parameters.AddWithValue("@id", id);
        command.Parameters.AddWithValue("@original", originalJson);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1 ? updatedJson : null;
    }

    public async Task<bool> UpdateTranslatedFindingsAsync(long id, string originalJson, IReadOnlyList<AuditIssue> findings)
    {
        EnsureWritable();
        if (!findings.Any(issue => issue.HasBilingualText)) return false;
        if (JsonNode.Parse(originalJson) is not JsonArray storedFindings
            || storedFindings.Count != findings.Count
            || storedFindings.Any(node => node is not JsonObject)) return false;

        // Patch text in the original JSON so evidence and unrecognized legacy fields survive.
        for (int i = 0; i < findings.Count; i++)
        {
            var stored = storedFindings[i]!;
            var translated = findings[i];
            if (!translated.HasBilingualText) continue;
            stored[nameof(AuditIssue.Title)] = translated.Title;
            stored[nameof(AuditIssue.Description)] = translated.Description;
            stored[nameof(AuditIssue.RootCause)] = translated.RootCause;
            stored[nameof(AuditIssue.Recommendation)] = translated.Recommendation;
            stored[nameof(AuditIssue.TitleZh)] = translated.TitleZh;
            stored[nameof(AuditIssue.DescriptionZh)] = translated.DescriptionZh;
            stored[nameof(AuditIssue.RootCauseZh)] = translated.RootCauseZh;
            stored[nameof(AuditIssue.RecommendationZh)] = translated.RecommendationZh;
        }

        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();
        using var command = connection.CreateCommand();
        // Only the text payload changes, and a concurrently edited row is left alone.
        command.CommandText = "UPDATE AuditResults SET FindingsJson=@translated WHERE Id=@id AND FindingsJson=@original";
        command.Parameters.AddWithValue("@translated", storedFindings.ToJsonString());
        command.Parameters.AddWithValue("@id", id);
        command.Parameters.AddWithValue("@original", originalJson);
        return await command.ExecuteNonQueryAsync() == 1;
    }

    private void EnsureWritable()
    {
        if (IsReadOnly)
            throw new InvalidOperationException(AppText.Get("The assistant database is read-only in this app. Publish results using the AGENTS.md workflow."));
    }

    public async Task WatchForChangesAsync(Action changed, CancellationToken cancellationToken)
    {
        // data_version detects commits from another connection, including commits still in a WAL.
        // It must be read on the same connection each time, without holding a read transaction.
        var monitors = new Dictionary<string, (SqliteConnection Connection, long Version)>();
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
            do
            {
                bool update = false;
                foreach (string path in _historyPaths)
                {
                    if (!File.Exists(path)) continue;
                    if (!monitors.TryGetValue(path, out var monitor))
                    {
                        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
                        { DataSource = path, Mode = SqliteOpenMode.ReadOnly, Pooling = false, DefaultTimeout = 5 }.ToString());
                        monitors[path] = monitor = (connection, -1);
                        await connection.OpenAsync(cancellationToken);
                    }
                    using var command = monitor.Connection.CreateCommand();
                    command.CommandText = "PRAGMA data_version";
                    long next = Convert.ToInt64(await command.ExecuteScalarAsync(cancellationToken));
                    if (next == monitor.Version) continue;
                    monitors[path] = (monitor.Connection, next);
                    update = true;
                }
                if (update) changed();
            } while (await timer.WaitForNextTickAsync(cancellationToken));
        }
        finally { foreach (var monitor in monitors.Values) monitor.Connection.Dispose(); }
    }
}
