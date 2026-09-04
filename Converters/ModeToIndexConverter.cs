using Microsoft.UI.Xaml.Data;
using System;

namespace LocalSecurityAudit.Converters;

public class ModeToIndexConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return (value as string) switch
        {
            "chat" => 0,
            "responses" => 1,
            _ => 1
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        return value is int index ? (index switch
        {
            0 => "chat",
            1 => "responses",
            _ => "responses"
        }) : "responses";
    }
}
