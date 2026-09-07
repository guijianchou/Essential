using System;
using LiveChartsCore.SkiaSharpView.Painting;
using LocalSecurityAudit.Services;
using Microsoft.UI.Xaml;
using SkiaSharp;

namespace LocalSecurityAudit.Helpers;

/// <summary>
/// Colors for the SkiaSharp charts, selected per theme rather than flipped automatically.
/// The severity values mirror the brushes in App.xaml; the neutral series hue is used for
/// every single-series chart so identity never competes with severity.
/// </summary>
public sealed record ChartPalette(
    SKColor Surface,
    SKColor InkPrimary,
    SKColor InkSecondary,
    SKColor Grid,
    SKColor High,
    SKColor Medium,
    SKColor Low,
    SKColor Series,
    SKColor SeriesWash,
    SKColor TooltipBackground)
{
    public const string FontFamily = "Segoe UI Variable Small";
    public const double TextSize = 12;
    private static readonly Lazy<SKTypeface> DefaultTypeface = new(() => SKTypeface.FromFamilyName(FontFamily));
    private static readonly Lazy<SKTypeface> ChineseTypeface = new(() =>
        SKFontManager.Default.MatchCharacter(FontFamily, SKFontStyle.Normal, new[] { "zh-CN" }, 0x4E2D)
        ?? SKTypeface.FromFamilyName("Microsoft YaHei UI"));

    public static SolidColorPaint TextPaint(SKColor color, bool localized = true)
    {
        // Skia labels use one typeface and do not inherit WinUI's CJK font fallback.
        return new SolidColorPaint(color)
        {
            SKTypeface = localized && AppText.IsChinese ? ChineseTypeface.Value : DefaultTypeface.Value
        };
    }

    public static readonly ChartPalette Light = new(
        Surface: new SKColor(0xFB, 0xFB, 0xFB),
        InkPrimary: new SKColor(0x1B, 0x1B, 0x1B),
        InkSecondary: new SKColor(0x61, 0x61, 0x61),
        Grid: new SKColor(0x00, 0x00, 0x00, 0x14),
        High: new SKColor(0xC8, 0x30, 0x2F),
        Medium: new SKColor(0xE8, 0x89, 0x1F),
        Low: new SKColor(0x3F, 0x7F, 0xC0),
        Series: new SKColor(0x2A, 0x78, 0xD6),
        SeriesWash: new SKColor(0x2A, 0x78, 0xD6, 0x22),
        TooltipBackground: new SKColor(0xFF, 0xFF, 0xFF));

    public static readonly ChartPalette Dark = new(
        Surface: new SKColor(0x2A, 0x2A, 0x2A),
        InkPrimary: new SKColor(0xFF, 0xFF, 0xFF),
        InkSecondary: new SKColor(0xC5, 0xC5, 0xC5),
        Grid: new SKColor(0xFF, 0xFF, 0xFF, 0x1A),
        High: new SKColor(0xE8, 0x64, 0x64),
        Medium: new SKColor(0xE6, 0xA2, 0x3C),
        Low: new SKColor(0x6A, 0xA3, 0xE4),
        Series: new SKColor(0x39, 0x87, 0xE5),
        SeriesWash: new SKColor(0x39, 0x87, 0xE5, 0x33),
        TooltipBackground: new SKColor(0x33, 0x33, 0x33));

    public static ChartPalette For(ElementTheme theme)
    {
        return theme == ElementTheme.Dark ? Dark : Light;
    }
}
