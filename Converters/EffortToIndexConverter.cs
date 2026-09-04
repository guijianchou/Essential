using Microsoft.UI.Xaml.Data;
using System;

namespace LocalSecurityAudit.Converters;

public class EffortToIndexConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return (value as string) switch
        {
            "low" => 0,
            "medium" => 1,
            "high" => 2,
            "xhigh" => 3,
            "max" => 4,
            _ => 1
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        return value is int index ? (index switch
        {
            0 => "low",
            1 => "medium",
            2 => "high",
            3 => "xhigh",
            4 => "max",
            _ => "medium"
        }) : "medium";
    }
}
