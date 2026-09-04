using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using System;

namespace LocalSecurityAudit.Converters;

public sealed class SeverityToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        string resourceKey = (value as string) switch
        {
            "High" => "SystemFillColorCriticalBrush",
            "Medium" => "SystemFillColorCautionBrush",
            "Low" => "SystemFillColorSuccessBrush",
            _ => "TextFillColorSecondaryBrush"
        };

        return Application.Current.Resources[resourceKey] as Brush
            ?? new SolidColorBrush(Microsoft.UI.Colors.Gray);
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotSupportedException();
    }
}
