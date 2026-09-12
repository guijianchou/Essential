using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.ViewModels;
using JsonKind = System.Text.Json.JsonValueKind;

namespace LocalSecurityAudit.Services;

/// <summary>
/// AI client for task-based file classification and recommendations.
/// Runs isolated kernel sessions with desensitized metadata input.
/// Does NOT execute file operations - only produces validated recommendations.
/// </summary>
public sealed class TaskAiClient
{
    private readonly DiagnosticLogService _diagnosticLogService;
    private readonly KernelManagerService _kernelManagerService;
    private const int KernelRequestTimeoutSeconds = 600;

    public TaskAiClient(
        DiagnosticLogService diagnosticLogService,
        KernelManagerService kernelManagerService)
    {
        _diagnosticLogService = diagnosticLogService;
        _kernelManagerService = kernelManagerService;
    }

    /// <summary>
    /// Load policy content from task-specific AGENTS.md file.
    /// </summary>
    public async Task<string> LoadPolicyAsync(string taskId, CancellationToken cancellationToken = default)
    {
        string policyPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "LocalSecurityAudit",
            "chains",
            taskId,
            "AGENTS.md");

        if (!File.Exists(policyPath))
        {
            throw new FileNotFoundException($"Policy file not found for task {taskId}: {policyPath}");
        }

        _diagnosticLogService.Write($"TaskAiClient: Loading policy from {policyPath}");
        return await File.ReadAllTextAsync(policyPath, cancellationToken);
    }

    /// <summary>
    /// Format file metadata as desensitized JSON input for AI classification.
    /// Uses itemId instead of absolute paths, with desensitized name hints.
    /// </summary>
    public Task<string> FormatMetadataAsync(
        IEnumerable<TempFileInfo> items,
        string taskId,
        CancellationToken cancellationToken = default)
    {
        var metadataItems = items.Select((item, index) => new
        {
            itemId = $"{taskId}-{index:D6}",
            extension = Path.GetExtension(item.FilePath).TrimStart('.').ToLowerInvariant(),
            category = item.Category,
            sizeBytes = item.SizeInBytes,
            lastModified = item.LastModified.ToString("yyyy-MM-ddTHH:mm:ss"),
            nameHint = DesensitizeName(Path.GetFileName(item.FilePath))
        }).ToList();

        string json = JsonSerializer.Serialize(new { files = metadataItems }, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        _diagnosticLogService.Write($"TaskAiClient: Formatted {metadataItems.Count} items for task {taskId}");
        return Task.FromResult(json);
    }

    /// <summary>
    /// Run AI classification with kernel isolation.
    /// </summary>
    public async Task<TaskAiResponse> RunClassificationAsync(
        string kernel,
        AiTargetSettings target,
        string policyContent,
        string metadataJson,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(kernel))
        {
            throw new ArgumentException("Kernel name is required", nameof(kernel));
        }

        if (!Uri.TryCreate(target.BaseUrl?.Trim(), UriKind.Absolute, out var endpoint)
            || endpoint.Scheme is not ("http" or "https"))
        {
            throw new InvalidOperationException("Valid HTTP or HTTPS endpoint URL required");
        }

        string executable = _kernelManagerService.RequireExecutable(kernel);
        _diagnosticLogService.Write($"TaskAiClient: Starting classification with kernel={kernel}, model={target.Model}");

        string temporaryRoot = Path.Combine(Path.GetTempPath(), $"lsa-task-{Guid.NewGuid():N}");
        Directory.CreateDirectory(temporaryRoot);

        try
        {
            string outputPath = Path.Combine(temporaryRoot, "last-message.txt");
            string userPromptPath = Path.Combine(temporaryRoot, "user-prompt.txt");
            await File.WriteAllTextAsync(userPromptPath, metadataJson, new UTF8Encoding(false), cancellationToken);

            var startInfo = new ProcessStartInfo
            {
                FileName = executable,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = temporaryRoot
            };

            ConfigureKernelProcess(startInfo, kernel, target, policyContent, outputPath, temporaryRoot);

            if (kernel == AiKernelCatalog.Codex)
            {
                await ConfigureCodexModelCatalogAsync(startInfo, Path.Combine(temporaryRoot, "codex-home"), cancellationToken);
            }

            using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            if (!process.Start())
            {
                throw new InvalidOperationException($"Failed to start {kernel} kernel");
            }

            using var requestCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            requestCts.CancelAfter(TimeSpan.FromSeconds(KernelRequestTimeoutSeconds));

            var output = new StringBuilder();
            var errorOutput = new StringBuilder();

            Task stdoutTask = Task.Run(async () =>
            {
                while (!process.StandardOutput.EndOfStream)
                {
                    string? line = await process.StandardOutput.ReadLineAsync(requestCts.Token);
                    if (line != null) output.AppendLine(line);
                }
            }, requestCts.Token);

            Task stderrTask = Task.Run(async () =>
            {
                while (!process.StandardError.EndOfStream)
                {
                    string? line = await process.StandardError.ReadLineAsync(requestCts.Token);
                    if (line != null) errorOutput.AppendLine(line);
                }
            }, requestCts.Token);

            try
            {
                if (kernel == AiKernelCatalog.Codex)
                {
                    await process.StandardInput.WriteAsync(metadataJson.AsMemory(), requestCts.Token);
                }
                process.StandardInput.Close();

                await process.WaitForExitAsync(requestCts.Token);
                await Task.WhenAll(stdoutTask, stderrTask);

                if (process.ExitCode != 0)
                {
                    string error = errorOutput.ToString().Trim();
                    throw new InvalidOperationException($"{kernel} kernel failed (exit {process.ExitCode}): {error}");
                }

                string responseText;
                if (kernel == AiKernelCatalog.Codex && File.Exists(outputPath))
                {
                    responseText = await File.ReadAllTextAsync(outputPath, cancellationToken);
                }
                else
                {
                    responseText = output.ToString();
                }

                if (string.IsNullOrWhiteSpace(responseText))
                {
                    throw new InvalidOperationException($"{kernel} kernel returned empty response");
                }

                _diagnosticLogService.Write($"TaskAiClient: Received response ({responseText.Length} chars)");
                return ParseAndValidateResponse(responseText);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new TimeoutException($"{kernel} kernel timed out after {KernelRequestTimeoutSeconds}s");
            }
            finally
            {
                if (!process.HasExited)
                {
                    try { process.Kill(entireProcessTree: true); } catch { }
                }
                requestCts.Cancel();
            }
        }
        finally
        {
            try
            {
                if (Directory.Exists(temporaryRoot))
                {
                    Directory.Delete(temporaryRoot, recursive: true);
                }
            }
            catch { }
        }
    }

    private static void ConfigureKernelProcess(
        ProcessStartInfo startInfo,
        string kernel,
        AiTargetSettings target,
        string policyContent,
        string outputPath,
        string temporaryRoot)
    {
        string instructionsPath = Path.Combine(temporaryRoot, "AGENTS.md");
        File.WriteAllText(instructionsPath, policyContent, new UTF8Encoding(false));

        if (kernel == AiKernelCatalog.Codex)
        {
            string codexHome = Path.Combine(temporaryRoot, "codex-home");
            Directory.CreateDirectory(codexHome);

            string baseUrl = target.BaseUrl.TrimEnd('/');
            if (!baseUrl.EndsWith("/v1", StringComparison.OrdinalIgnoreCase))
            {
                baseUrl += "/v1";
            }

            if (string.Equals(target.Mode, "chat", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("Codex requires Responses API mode");
            }

            int instructionsBytes = Math.Max(32768, Encoding.UTF8.GetByteCount(policyContent));
            string config = $"model = {TomlString(target.Model)}\n" +
                          $"model_reasoning_effort = {TomlString(target.Effort ?? "medium")}\n" +
                          $"model_provider = \"taskai\"\n" +
                          $"project_doc_max_bytes = {instructionsBytes}\n\n" +
                          $"[model_providers.taskai]\n" +
                          $"name = \"TaskAI\"\n" +
                          $"base_url = {TomlString(baseUrl)}\n" +
                          $"wire_api = \"responses\"\n";

            if (!string.IsNullOrWhiteSpace(target.ApiKey))
            {
                config += "env_key = \"TASK_AI_API_KEY\"\n";
            }

            File.WriteAllText(Path.Combine(codexHome, "config.toml"), config, new UTF8Encoding(false));
            startInfo.Environment["CODEX_HOME"] = codexHome;
            startInfo.Environment.Remove("OPENAI_API_KEY");
            startInfo.Environment.Remove("CODEX_API_KEY");
            startInfo.Environment["TASK_AI_API_KEY"] = target.ApiKey?.Trim() ?? string.Empty;

            startInfo.ArgumentList.Add("exec");
            startInfo.ArgumentList.Add("--json");
            startInfo.ArgumentList.Add("--ephemeral");
            startInfo.ArgumentList.Add("--sandbox");
            startInfo.ArgumentList.Add("read-only");
            startInfo.ArgumentList.Add("--skip-git-repo-check");
            startInfo.ArgumentList.Add("--color");
            startInfo.ArgumentList.Add("never");
            startInfo.ArgumentList.Add("--output-last-message");
            startInfo.ArgumentList.Add(outputPath);
            startInfo.ArgumentList.Add("-");
            return;
        }

        // Pi kernel configuration
        string piHome = Path.Combine(temporaryRoot, "pi-home");
        Directory.CreateDirectory(piHome);

        string piBaseUrl = target.BaseUrl.TrimEnd('/');
        if (!piBaseUrl.EndsWith("/v1", StringComparison.OrdinalIgnoreCase))
        {
            piBaseUrl += "/v1";
        }

        startInfo.Environment["PI_CODING_AGENT_DIR"] = piHome;
        startInfo.Environment["PI_CODING_AGENT_SESSION_DIR"] = piHome;
        startInfo.Environment["PI_OFFLINE"] = "1";
        startInfo.Environment["PI_SKIP_VERSION_CHECK"] = "1";
        startInfo.Environment["PI_TELEMETRY"] = "0";
        startInfo.Environment["OPENAI_API_KEY"] = target.ApiKey?.Trim() ?? string.Empty;
        startInfo.Environment["OPENAI_BASE_URL"] = piBaseUrl;

        var piConfig = new
        {
            providers = new Dictionary<string, object>
            {
                ["taskai"] = new
                {
                    baseUrl = piBaseUrl,
                    api = string.Equals(target.Mode, "chat", StringComparison.OrdinalIgnoreCase)
                        ? "openai-completions"
                        : "openai-responses",
                    apiKey = "$OPENAI_API_KEY",
                    authHeader = true,
                    models = new[]
                    {
                        new
                        {
                            id = target.Model,
                            name = target.Model,
                            reasoning = true,
                            input = new[] { "text" },
                            contextWindow = 256000,
                            maxTokens = 8000
                        }
                    }
                }
            }
        };

        File.WriteAllText(Path.Combine(piHome, "models.json"), JsonSerializer.Serialize(piConfig), new UTF8Encoding(false));

        startInfo.ArgumentList.Add("--mode");
        startInfo.ArgumentList.Add("json");
        startInfo.ArgumentList.Add("--print");
        startInfo.ArgumentList.Add("--no-session");
        startInfo.ArgumentList.Add("--no-tools");
        startInfo.ArgumentList.Add("--no-context-files");
        startInfo.ArgumentList.Add("--provider");
        startInfo.ArgumentList.Add("taskai");
        startInfo.ArgumentList.Add("--model");
        startInfo.ArgumentList.Add(target.Model);
        startInfo.ArgumentList.Add("--thinking");
        startInfo.ArgumentList.Add(target.Effort ?? "medium");
        startInfo.ArgumentList.Add("--system-prompt");
        startInfo.ArgumentList.Add("Follow the task instructions. Return only valid JSON matching the required schema.");
    }

    private static async Task ConfigureCodexModelCatalogAsync(
        ProcessStartInfo startInfo,
        string codexHome,
        CancellationToken cancellationToken)
    {
        // Disable use_responses_lite to ensure full response format
        string catalogPath = Path.Combine(AppContext.BaseDirectory, "models.json");
        if (!File.Exists(catalogPath)) return;

        string catalogJson = await File.ReadAllTextAsync(catalogPath, cancellationToken);
        var catalog = JsonSerializer.Deserialize<JsonElement>(catalogJson);

        if (catalog.ValueKind == JsonKind.Object && catalog.TryGetProperty("models", out var models))
        {
            var modifiedCatalog = new { models = models };
            string modifiedJson = JsonSerializer.Serialize(modifiedCatalog);
            string targetPath = Path.Combine(codexHome, "models.json");
            await File.WriteAllTextAsync(targetPath, modifiedJson, new UTF8Encoding(false), cancellationToken);

            string configPath = Path.Combine(codexHome, "config.toml");
            if (File.Exists(configPath))
            {
                string config = await File.ReadAllTextAsync(configPath, cancellationToken);
                config += $"\nmodel_catalog_path = {TomlString(targetPath)}\n";
                await File.WriteAllTextAsync(configPath, config, new UTF8Encoding(false), cancellationToken);
            }
        }
    }

    /// <summary>
    /// Parse and strictly validate AI response JSON.
    /// </summary>
    private TaskAiResponse ParseAndValidateResponse(string responseText)
    {
        JsonElement root;
        try
        {
            root = JsonSerializer.Deserialize<JsonElement>(responseText);
        }
        catch (JsonException ex)
        {
            _diagnosticLogService.WriteException("TaskAiClient: JSON parse failed", ex);
            throw new InvalidOperationException($"Invalid JSON response: {ex.Message}", ex);
        }

        if (!root.TryGetProperty("recommendations", out var recommendationsArray) ||
            recommendationsArray.ValueKind != JsonKind.Array)
        {
            throw new InvalidOperationException("Response missing 'recommendations' array");
        }

        var recommendations = new List<TaskAiRecommendation>();
        foreach (var item in recommendationsArray.EnumerateArray())
        {
            recommendations.Add(ParseRecommendation(item));
        }

        _diagnosticLogService.Write($"TaskAiClient: Parsed {recommendations.Count} recommendations");
        return new TaskAiResponse { Recommendations = recommendations };
    }

    private TaskAiRecommendation ParseRecommendation(JsonElement item)
    {
        if (!item.TryGetProperty("itemId", out var itemIdProp) || itemIdProp.ValueKind != JsonKind.String)
        {
            throw new InvalidOperationException("Recommendation missing 'itemId' field");
        }

        if (!item.TryGetProperty("action", out var actionProp) || actionProp.ValueKind != JsonKind.String)
        {
            throw new InvalidOperationException($"Recommendation {itemIdProp.GetString()} missing 'action' field");
        }

        string action = actionProp.GetString()!.ToLowerInvariant();
        if (action is not ("move" or "delete" or "skip"))
        {
            throw new InvalidOperationException($"Invalid action '{action}' for {itemIdProp.GetString()}. Must be move, delete, or skip.");
        }

        string? targetRelative = null;
        if (item.TryGetProperty("targetRelative", out var targetProp) && targetProp.ValueKind == JsonKind.String)
        {
            targetRelative = targetProp.GetString();
        }

        if (action == "move" && string.IsNullOrWhiteSpace(targetRelative))
        {
            throw new InvalidOperationException($"Action 'move' requires non-empty 'targetRelative' for {itemIdProp.GetString()}");
        }

        if (!item.TryGetProperty("risk", out var riskProp) || riskProp.ValueKind != JsonKind.String)
        {
            throw new InvalidOperationException($"Recommendation {itemIdProp.GetString()} missing 'risk' field");
        }

        string risk = riskProp.GetString()!.ToLowerInvariant();
        if (risk is not ("low" or "medium" or "high"))
        {
            throw new InvalidOperationException($"Invalid risk '{risk}' for {itemIdProp.GetString()}. Must be low, medium, or high.");
        }

        if (!item.TryGetProperty("reasonEn", out var reasonEnProp) || reasonEnProp.ValueKind != JsonKind.String || string.IsNullOrWhiteSpace(reasonEnProp.GetString()))
        {
            throw new InvalidOperationException($"Recommendation {itemIdProp.GetString()} missing or empty 'reasonEn' field");
        }

        if (!item.TryGetProperty("reasonZh", out var reasonZhProp) || reasonZhProp.ValueKind != JsonKind.String || string.IsNullOrWhiteSpace(reasonZhProp.GetString()))
        {
            throw new InvalidOperationException($"Recommendation {itemIdProp.GetString()} missing or empty 'reasonZh' field");
        }

        return new TaskAiRecommendation
        {
            ItemId = itemIdProp.GetString()!,
            Action = action,
            TargetRelative = targetRelative,
            Risk = risk,
            ReasonEn = reasonEnProp.GetString()!,
            ReasonZh = reasonZhProp.GetString()!
        };
    }

    /// <summary>
    /// Desensitize filename to remove personally identifiable information.
    /// </summary>
    private static string DesensitizeName(string fileName)
    {
        // Replace sequences of digits with placeholder
        var result = System.Text.RegularExpressions.Regex.Replace(fileName, @"\d{3,}", "[NUM]");

        // Replace common PII patterns
        result = System.Text.RegularExpressions.Regex.Replace(result, @"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL]");
        result = System.Text.RegularExpressions.Regex.Replace(result, @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "[IP]");

        return result;
    }

    private static string TomlString(string value)
    {
        return $"\"{value.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"";
    }
}

public sealed class TaskAiResponse
{
    public List<TaskAiRecommendation> Recommendations { get; set; } = new();
}

public sealed class TaskAiRecommendation
{
    [JsonPropertyName("itemId")]
    public string ItemId { get; set; } = "";

    [JsonPropertyName("action")]
    public string Action { get; set; } = "";

    [JsonPropertyName("targetRelative")]
    public string? TargetRelative { get; set; }

    [JsonPropertyName("risk")]
    public string Risk { get; set; } = "";

    [JsonPropertyName("reasonEn")]
    public string ReasonEn { get; set; } = "";

    [JsonPropertyName("reasonZh")]
    public string ReasonZh { get; set; } = "";
}
