using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Text.Json;

namespace LocalSecurityAudit.Services;

[Microsoft.UI.Xaml.Data.Bindable]
public sealed class AppText : INotifyPropertyChanged
{
    public static AppText Current { get; } = new();
    private readonly Dictionary<string, (string English, string Chinese)> _strings;
    private string _language = "en";

    private AppText()
    {
        using var stream = typeof(AppText).Assembly.GetManifestResourceStream("LocalSecurityAudit.Resources.Strings.zh-CN.json")
            ?? throw new InvalidOperationException("Language resources are missing.");
        var strings = JsonSerializer.Deserialize<Dictionary<string, string>>(stream)
            ?? throw new InvalidOperationException("Language resources are invalid.");
        _strings = strings.ToDictionary(pair => ResourceKey(pair.Key), pair => (pair.Key, pair.Value));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public event EventHandler? LanguageChanged;
    public static bool IsChinese => Current._language == "zh-CN";
    public static CultureInfo Culture => CultureInfo.GetCultureInfo(IsChinese ? "zh-CN" : "en-US");
    public string Language => _language;

    public string this[string key] => _strings.TryGetValue(ResourceKey(key), out var value)
        ? IsChinese ? value.Chinese : value.English
        : key;

    public static string Get(string text) => Current[text];
    public static string Format(string text, params object?[] values) => string.Format(Culture, Get(text), values);

    // XAML indexer paths use punctuation-free resource keys; code may use the English text.
    public static string ResourceKey(string text) => string.Concat(text.Where(char.IsLetterOrDigit));

    public void SetLanguage(string language)
    {
        string normalized = language == "zh-CN" ? "zh-CN" : "en";
        if (_language == normalized) return;
        _language = normalized;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("Item[]"));
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }
}
