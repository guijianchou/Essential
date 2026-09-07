using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;

namespace LocalSecurityAudit.Helpers;

/// <summary>
/// Resolves theme-dependent resources from code for the theme an element actually renders
/// in. <c>Application.Current.Resources[key]</c> alone follows the application theme, which
/// is wrong when the window overrides it through <c>RequestedTheme</c>.
/// </summary>
public static class ThemeResources
{
    public static Brush? GetBrush(FrameworkElement element, string key)
    {
        string themeKey = element.ActualTheme == ElementTheme.Dark ? "Default" : "Light";
        var themeDictionaries = Application.Current.Resources.ThemeDictionaries;
        if (themeDictionaries.TryGetValue(themeKey, out var dictionaryObject)
            && dictionaryObject is ResourceDictionary dictionary
            && dictionary.TryGetValue(key, out var value)
            && value is Brush brush)
        {
            return brush;
        }

        return Application.Current.Resources.TryGetValue(key, out var fallback)
            ? fallback as Brush
            : null;
    }
}
