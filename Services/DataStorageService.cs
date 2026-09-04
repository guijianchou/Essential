using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
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
            ORDER BY Timestamp DESC
            LIMIT 1
        ";
        cmd.Parameters.AddWithValue("@start", utcStart);
        cmd.Parameters.AddWithValue("@end", utcEnd);

        using var reader = await cmd.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return new AuditResult
            {
                Timestamp = AsUtc(reader.GetDateTime(0)),
                HealthScore = reader.GetInt32(1),
                Findings = JsonSerializer.Deserialize<List<AuditIssue>>(reader.GetString(2)) ?? new(),
                Metadata = reader.IsDBNull(3) ? null :
                    JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(reader.GetString(3))
            };
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
            ORDER BY Timestamp DESC
            LIMIT 1
        ";

        using var reader = await cmd.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return new AuditResult
            {
                Timestamp = AsUtc(reader.GetDateTime(0)),
                HealthScore = reader.GetInt32(1),
                Findings = JsonSerializer.Deserialize<List<AuditIssue>>(reader.GetString(2)) ?? new(),
                Metadata = reader.IsDBNull(3) ? null :
                    JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(reader.GetString(3))
            };
        }

        return null;
    }

    public async Task<List<AuditResult>> GetTrendsAsync(int days = 7)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var cmd = connection.CreateCommand();
        cmd.CommandText = @"
            SELECT Timestamp, HealthScore, FindingsJson, MetadataJson
            FROM AuditResults
            WHERE Timestamp >= @cutoff
            ORDER BY Timestamp ASC
        ";

        cmd.Parameters.AddWithValue("@cutoff", DateTime.UtcNow.AddDays(-days));

        var results = new List<AuditResult>();

        using var reader = await cmd.ExecuteReaderAsync();

        while (await reader.ReadAsync())
        {
            results.Add(new AuditResult
            {
                Timestamp = AsUtc(reader.GetDateTime(0)),
                HealthScore = reader.GetInt32(1),
                Findings = JsonSerializer.Deserialize<List<AuditIssue>>(reader.GetString(2)) ?? new(),
                Metadata = reader.IsDBNull(3) ? null :
                    JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(reader.GetString(3))
            });
        }

        return results;
    }

    private static DateTime AsUtc(DateTime timestamp)
    {
        return DateTime.SpecifyKind(timestamp, DateTimeKind.Utc);
    }

    public async Task CleanupOldDataAsync(int retentionDays = 7)
    {
        using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync();

        var cleanupCmd = connection.CreateCommand();
        cleanupCmd.CommandText = "DELETE FROM AuditResults WHERE Timestamp < @cutoff";
        cleanupCmd.Parameters.AddWithValue("@cutoff", DateTime.UtcNow.AddDays(-Math.Max(1, retentionDays)));

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
}
