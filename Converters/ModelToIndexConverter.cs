using Microsoft.UI.Xaml.Data;
using System;
using LocalSecurityAudit.Models;

namespace LocalSecurityAudit.Converters;

public class ModelToIndexConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        // Only Luna is supported at the moment, so every stored value maps to the single entry.
        return 0;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        return AiTargetSettings.LunaModel;
    }
}
