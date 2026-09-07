using Microsoft.UI.Xaml.Data;
using System;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Converters;

public class ModelToIndexConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        for (int i = 0; i < AiModelCatalog.Models.Count; i++)
            if (string.Equals(value as string, AiModelCatalog.Models[i], StringComparison.OrdinalIgnoreCase)) return i;
        return 0;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        return value is int index && index >= 0 && index < AiModelCatalog.Models.Count
            ? AiModelCatalog.Models[index] : AiTargetSettings.LunaModel;
    }
}
