using Microsoft.UI.Xaml.Data;
using System;

namespace LocalSecurityAudit.Converters;

public class ModelToIndexConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return (value as string) switch
        {
            "gpt-5.6-sol" => 0,
            "gpt-5.6-luna" => 1,
            "gpt-5.6-terra" => 2,
            _ => 0
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        return value is int index ? (index switch
        {
            0 => "gpt-5.6-sol",
            1 => "gpt-5.6-luna",
            2 => "gpt-5.6-terra",
            _ => "gpt-5.6-sol"
        }) : "gpt-5.6-sol";
    }
}
