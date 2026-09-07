using System;
using System.Numerics;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Hosting;
using Windows.UI.ViewManagement;

namespace LocalSecurityAudit.Helpers;

internal static class ContentMotion
{
    public static void SetLoading(FrameworkElement element, bool loading)
    {
        element.IsHitTestVisible = !loading;
        var visual = ElementCompositionPreview.GetElementVisual(element);
        visual.StopAnimation("Opacity");
        visual.StopAnimation("Translation.Y");
        if (!new UISettings().AnimationsEnabled)
        {
            visual.Opacity = loading ? 0.45f : 1;
            visual.Properties.InsertVector3("Translation", Vector3.Zero);
            return;
        }
        ElementCompositionPreview.SetIsTranslationEnabled(element, true);
        var compositor = visual.Compositor;
        var ease = compositor.CreateCubicBezierEasingFunction(new Vector2(0.2f, 0), new Vector2(0, 1));
        var fade = compositor.CreateScalarKeyFrameAnimation();
        fade.InsertExpressionKeyFrame(0, "this.StartingValue");
        fade.InsertKeyFrame(1, loading ? 0.45f : 1, ease);
        fade.Duration = TimeSpan.FromMilliseconds(160);
        visual.StartAnimation("Opacity", fade);
        if (!loading)
        {
            var slide = compositor.CreateScalarKeyFrameAnimation();
            slide.InsertKeyFrame(0, 4);
            slide.InsertKeyFrame(1, 0, ease);
            slide.Duration = TimeSpan.FromMilliseconds(180);
            visual.StartAnimation("Translation.Y", slide);
        }
    }
}
