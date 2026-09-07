using System;
using System.Collections.Generic;
using System.Linq;

namespace LocalSecurityAudit.Models;

public static class AiModelCatalog
{
    public const int ContextWindowTokens = 256_000;
    public const string Astra = "gpt-6-astra";
    public const string GatewayAlias = "gpt-5.6";
    public static IReadOnlyList<string> OptimizationModels { get; } = Array.AsReadOnly(new[]
    {
        AiTargetSettings.LunaModel, "gpt-5.6-terra", "gpt-5.6-sol", Astra
    });
    public static IReadOnlyList<string> Models { get; } = Array.AsReadOnly(
        OptimizationModels.Append(GatewayAlias).ToArray());

    public static string Normalize(string? model) => Models.FirstOrDefault(
        candidate => string.Equals(candidate, model?.Trim(), StringComparison.OrdinalIgnoreCase)) ?? AiTargetSettings.LunaModel;

    public static int Rank(string? model)
    {
        for (int i = 0; i < OptimizationModels.Count; i++)
            if (string.Equals(OptimizationModels[i], model, StringComparison.OrdinalIgnoreCase)) return i;
        return -1;
    }

    public static bool CanOptimize(string? source, string target)
    {
        int targetRank = Rank(target);
        if (targetRank < 0) return false;
        // Unlabelled legacy records and the gateway alias have no reliable tier.
        // Only the highest explicit model can take ownership of these records.
        if (string.IsNullOrWhiteSpace(source) || string.Equals(source, GatewayAlias, StringComparison.OrdinalIgnoreCase))
            return target == Astra;
        int sourceRank = Rank(source);
        return sourceRank >= 0 && targetRank > sourceRank;
    }
}
