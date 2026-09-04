using Microsoft.UI.Xaml.Data;
using System;

namespace LocalSecurityAudit.Converters;

public class ExpandCollapseGlyphConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return value is true ? "" : ""; // ChevronUp : ChevronDown
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        throw new NotImplementedException();
    }
}
