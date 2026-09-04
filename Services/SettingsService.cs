using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Services;

public sealed class SettingsService
{
    public const string DefaultAgentInstructions = """
        # Local Security Audit policy

        Treat this document as audit policy and context only. Do not execute commands,
        change files, or invent facts that are not present in the supplied event data.
        Prefer concrete evidence from the Windows event fields, explain uncertainty,
        and keep recommendations safe and reversible.
        """;

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private readonly string _settingsPath;
    private readonly string _agentInstructionsPath;

    public AppSettings Current { get; private set; }
    public string AgentInstructionsPath => _agentInstructionsPath;
    public string SettingsPath => _settingsPath;

    public event EventHandler? SettingsChanged;

    public SettingsService()
    {
        var appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalSecurityAudit");

        Directory.CreateDirectory(appDataPath);
        _settingsPath = Path.Combine(appDataPath, "settings.json");
        _agentInstructionsPath = Path.Combine(appDataPath, "AGENTS.md");
        Current = LoadSettings();
        EnsureAgentInstructionsFile(Current.AgentInstructions);
        PersistNormalizedSettingsIfNeeded();
    }

    public AppSettings CreateDefaultSettings()
    {
        var defaults = CreateDefaults();
        Normalize(defaults);
        return defaults;
    }

    public void Save(AppSettings settings)
    {
        Normalize(settings);

        var json = JsonSerializer.Serialize(settings, SerializerOptions);
        File.WriteAllText(_settingsPath, json);
        try
        {
            File.WriteAllText(_agentInstructionsPath, settings.AgentInstructions);
        }
        catch (IOException)
        {
            // The JSON settings file remains the source of truth if the optional
            // human-readable policy copy cannot be written.
        }
        catch (UnauthorizedAccessException)
        {
            // The JSON settings file remains the source of truth if the optional
            // human-readable policy copy cannot be written.
        }
        Current = settings;
        SettingsChanged?.Invoke(this, EventArgs.Empty);
    }

    private void PersistNormalizedSettingsIfNeeded()
    {
        try
        {
            string storedJson = File.Exists(_settingsPath)
                ? File.ReadAllText(_settingsPath)
                : string.Empty;
            var stored = string.IsNullOrWhiteSpace(storedJson)
                ? null
                : JsonSerializer.Deserialize<AppSettings>(storedJson, SerializerOptions);

            if (stored == null
                || string.IsNullOrWhiteSpace(stored.AgentInstructions)
                || stored.AiTargets == null
                || stored.AiTargets.Count == 0
                || !stored.AiTargets.Any(target => target.IsActive))
            {
                Save(Current);
            }
        }
        catch (JsonException)
        {
            Save(Current);
        }
        catch (IOException)
        {
            // The in-memory normalized settings remain usable for this session.
        }
        catch (UnauthorizedAccessException)
        {
            // The in-memory normalized settings remain usable for this session.
        }
    }

    private AppSettings LoadSettings()
    {
        if (File.Exists(_settingsPath))
        {
            try
            {
                var stored = JsonSerializer.Deserialize<AppSettings>(
                    File.ReadAllText(_settingsPath),
                    SerializerOptions);

                if (stored != null)
                {
                    Normalize(stored);
                    stored.AgentInstructions = LoadAgentInstructions(stored.AgentInstructions);
                    return stored;
                }
            }
            catch (JsonException)
            {
                // Use safe defaults when a partially written or old settings file is found.
            }
            catch (IOException)
            {
                // The application can still start with defaults if settings are unavailable.
            }
        }

        return CreateDefaultSettings();
    }

    private static AppSettings CreateDefaults()
    {
        var endpoint = "https://api.falsemeet.site";
        var apiKey = "";

        foreach (var apiFilePath in GetLegacyApiFilePaths())
        {
            if (!File.Exists(apiFilePath))
            {
                continue;
            }

            try
            {
                var lines = File.ReadAllLines(apiFilePath);
                if (lines.Length > 0 && Uri.TryCreate(lines[0].Trim(), UriKind.Absolute, out var uri)
                    && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
                {
                    endpoint = uri.ToString().TrimEnd('/');
                }

                if (lines.Length > 1)
                {
                    apiKey = lines[1].Trim();
                }

                break;
            }
            catch (IOException)
            {
                // Try the next development-time location.
            }
        }

        return new AppSettings
        {
            AgentInstructions = DefaultAgentInstructions,
            AiTargets =
            {
                new AiTargetSettings
                {
                    Name = "Primary Target",
                    BaseUrl = endpoint,
                    ApiKey = apiKey,
                    Mode = "responses",
                    Model = "gpt-5.6-sol",
                    Effort = "medium"
                }
            }
        };
    }

    private string LoadAgentInstructions(string fallback)
    {
        if (File.Exists(_agentInstructionsPath))
        {
            try
            {
                return File.ReadAllText(_agentInstructionsPath);
            }
            catch (IOException)
            {
                // Keep the copy in settings.json when the external policy file is unavailable.
            }
            catch (UnauthorizedAccessException)
            {
                // Keep the copy in settings.json when the external policy file is unavailable.
            }
        }

        return string.IsNullOrWhiteSpace(fallback)
            ? DefaultAgentInstructions
            : fallback;
    }

    private void EnsureAgentInstructionsFile(string instructions)
    {
        if (File.Exists(_agentInstructionsPath))
        {
            return;
        }

        try
        {
            File.WriteAllText(_agentInstructionsPath, instructions);
        }
        catch (IOException)
        {
            // Settings can still be edited and saved if the optional copy cannot be created.
        }
        catch (UnauthorizedAccessException)
        {
            // Settings can still be edited and saved if the optional copy cannot be created.
        }
    }

    private static string[] GetLegacyApiFilePaths()
    {
        var paths = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "API.txt"),
            Path.Combine(Directory.GetCurrentDirectory(), "API.txt")
        }.ToList();

        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 6 && directory != null; i++, directory = directory.Parent)
        {
            paths.Add(Path.Combine(directory.FullName, "API.txt"));
        }

        return paths.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static void Normalize(AppSettings settings)
    {
        settings.Theme = settings.Theme is "system" or "light" or "dark"
            ? settings.Theme
            : "system";
        settings.ScanIntervalHours = settings.ScanIntervalHours switch
        {
            1 or 2 or 4 or 8 or 24 => settings.ScanIntervalHours,
            _ => 4
        };
        settings.FastScanRangeHours = settings.FastScanRangeHours switch
        {
            1 or 2 or 4 => settings.FastScanRangeHours,
            _ => 0
        };
        settings.RetentionDays = settings.RetentionDays switch
        {
            3 or 7 or 14 or 30 => settings.RetentionDays,
            _ => 7
        };
        settings.AgentInstructions = string.IsNullOrWhiteSpace(settings.AgentInstructions)
            ? DefaultAgentInstructions
            : settings.AgentInstructions;

        settings.AiTargets ??= new();
        if (settings.AiTargets.Count == 0)
        {
            settings.AiTargets.Add(new AiTargetSettings());
        }

        foreach (var target in settings.AiTargets)
        {
            target.Name = string.IsNullOrWhiteSpace(target.Name) ? "AI Target" : target.Name.Trim();
            target.BaseUrl = target.BaseUrl?.Trim().TrimEnd('/') ?? "";
            target.ApiKey ??= "";
            target.Mode = target.Mode is "chat" or "responses" ? target.Mode : "responses";
            target.Model = string.IsNullOrWhiteSpace(target.Model) ? "gpt-5.6-sol" : target.Model.Trim();
            target.Effort = target.Effort is "low" or "medium" or "high" or "xhigh" or "max"
                ? target.Effort
                : "medium";
        }

        // Keep target selection deterministic when older settings did not have
        // an active-target flag or when multiple targets were marked active.
        bool activeTargetFound = false;
        foreach (var target in settings.AiTargets)
        {
            target.IsActive = target.IsActive && !activeTargetFound;
            activeTargetFound |= target.IsActive;
        }

        if (!activeTargetFound)
        {
            settings.AiTargets[0].IsActive = true;
        }
    }
}
