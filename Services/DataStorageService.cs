using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public class DataStorageService
{
    private readonly string _connectionString;
    private readonly string _dbPath;

    private DataStorageService()
    {
        string appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalSecurityAudit");

        Directory.CreateDirectory(appDataPath);

        _dbPath = Path.Combine(appDataPath, "audit_data.db");
        _connectionString = $"Data Source={_dbPath}";

        SQLitePCL.Batteries_V2.Init();
    }

    public static async Task<DataStorageService> CreateAsync()
    {
        var service = new DataStorageService();
        await service.InitializeDatabaseAsync();
        return service;
    }

    private async Task InitializeDatabaseAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
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
        ";

        await createTableCmd.ExecuteNonQueryAsync();
    }

    public async Task SaveAuditResultAsync(AuditResult result)
    {
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
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        DateTime localStart = DateTime.Today;
        DateTime utcStart = localStart.ToUniversalTime();
        DateTime utcEnd = localStart.AddDays(1).ToUniversalTime();

        var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            SELECT Timestamp, HealthScore, FindingsJson, MetadataJson
            FROM AuditResults
            WHERE Timestamp >= @start AND Timestamp < @end
            ORDER BY Timestamp DESC, Id DESC
        ";
        cmd.Parameters.AddWithValue("@start", utcStart);
        cmd.Parameters.AddWithValue("@end", utcEnd);

        using var reader = await cmd.ExecuteReaderAsync();

        while (await reader.ReadAsync())
        {
            if (ReadResult(reader) is { } result) return result;
        }

        return null;
    }

    public async Task<AuditResult?> GetLatestResultAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            SELECT Timestamp, HealthScore, FindingsJson, MetadataJson
            FROM AuditResults
            ORDER BY Timestamp DESC, Id DESC
        ";

        using var reader = await cmd.ExecuteReaderAsync();

        bool hasRows = false;
        while (await reader.ReadAsync())
        {
            hasRows = true;
            if (ReadResult(reader) is { } result) return result;
        }

        if (hasRows) throw new InvalidDataException(AppText.Get("No readable audit records were found."));
        return null;
    }

    public Task<List<AuditResult>> GetTrendsAsync(int days = 30)
    {
        var today = DateTime.Today;
        return GetResultsAsync(today.AddDays(1 - Math.Max(1, days)).ToUniversalTime(), today.AddDays(1).ToUniversalTime());
    }

    public async Task<List<AuditResult>> GetResultsAsync(DateTime startUtc, DateTime endUtc)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            SELECT Timestamp, HealthScore, FindingsJson, MetadataJson
            FROM AuditResults
            WHERE Timestamp >= @start AND Timestamp < @end
            ORDER BY Timestamp ASC, Id ASC
        ";

        cmd.Parameters.AddWithValue("@start", startUtc.ToUniversalTime());
        cmd.Parameters.AddWithValue("@end", endUtc.ToUniversalTime());

        var results = new List<AuditResult>();

        using var reader = await cmd.ExecuteReaderAsync();

        bool hasRows = false;
        while (await reader.ReadAsync())
        {
            hasRows = true;
            if (ReadResult(reader) is { } result) results.Add(result);
        }

        if (hasRows && results.Count == 0) throw new InvalidDataException(AppText.Get("No readable audit records were found."));
        return results;
    }

    private static AuditResult? ReadResult(SqliteDataReader reader)
    {
        try
        {
            var findings = JsonSerializer.Deserialize<List<AuditIssue>>(reader.GetString(2));
            if (findings == null || findings.Any(issue => issue == null)) return null;
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
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var cleanupCmd = connection.CreateCommand();
        cleanupCmd.CommandText = "DELETE FROM AuditResults WHERE Timestamp < @cutoff";
        cleanupCmd.Parameters.AddWithValue("@cutoff", DateTime.Today.AddDays(1 - Math.Max(1, retentionDays)).ToUniversalTime());

        await cleanupCmd.ExecuteNonQueryAsync();
    }

    public async Task VacuumDatabaseAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var vacuumCmd = connection.CreateCommand();
        vacuumCmd.CommandText = "VACUUM";

        await vacuumCmd.ExecuteNonQueryAsync();
    }

    public async Task<int> GetAuditRecordCountAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var countCmd = connection.CreateCommand();
        countCmd.CommandText = "SELECT COUNT(*) FROM AuditResults";
        return Convert.ToInt32(await countCmd.ExecuteScalarAsync());
    }

    public async Task<List<(long Id, string OriginalJson, List<AuditIssue> Findings)>> GetLegacyFindingsAsync()
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, FindingsJson FROM AuditResults ORDER BY Timestamp DESC";
        using var reader = await command.ExecuteReaderAsync();
        var results = new List<(long, string, List<AuditIssue>)>();
        while (await reader.ReadAsync())
        {
            string json = reader.GetString(1);
            List<AuditIssue>? findings;
            try { findings = JsonSerializer.Deserialize<List<AuditIssue>>(json); }
            catch (JsonException) { continue; }
            if (findings == null || findings.Any(issue => issue == null)) continue;
            if (findings.Any(issue => !issue.HasBilingualText))
                results.Add((reader.GetInt64(0), json, findings));
        }
        return results;
    }

    public async Task<bool> UpdateTranslatedFindingsAsync(long id, string originalJson, IReadOnlyList<AuditIssue> findings)
    {
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
}
