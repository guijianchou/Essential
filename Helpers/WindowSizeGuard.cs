using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.UI.Xaml;

namespace LocalSecurityAudit.Helpers;

public sealed class WindowSizeGuard : IDisposable
{
    private const uint WmGetMinMaxInfo = 0x0024;
    private const uint DefaultDpi = 96;
    private static long _nextSubclassId;

    private readonly nint _windowHandle;
    private readonly nuint _subclassId;
    private readonly SubclassProcedure _subclassProcedure;
    private readonly double _minimumWidthDip;
    private readonly double _minimumHeightDip;
    private int _disposed;

    public WindowSizeGuard(Window window, double minimumWidthDip, double minimumHeightDip)
    {
        ArgumentNullException.ThrowIfNull(window);
        ValidateMinimumSize(minimumWidthDip, minimumHeightDip);

        _windowHandle = WinRT.Interop.WindowNative.GetWindowHandle(window);
        if (_windowHandle == nint.Zero)
        {
            throw new InvalidOperationException("The WinUI window does not have a native window handle.");
        }

        _minimumWidthDip = minimumWidthDip;
        _minimumHeightDip = minimumHeightDip;
        _subclassId = unchecked((nuint)Interlocked.Increment(ref _nextSubclassId));
        _subclassProcedure = ProcessWindowMessage;

        if (!SetWindowSubclass(_windowHandle, _subclassProcedure, _subclassId, nuint.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to subclass the WinUI window.");
        }
    }

    public void Dispose()
    {
        if (Volatile.Read(ref _disposed) != 0)
        {
            return;
        }

        if (!RemoveWindowSubclass(_windowHandle, _subclassProcedure, _subclassId)
            && IsWindow(_windowHandle))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to remove the window subclass.");
        }

        Volatile.Write(ref _disposed, 1);
        GC.SuppressFinalize(this);
    }

    private nint ProcessWindowMessage(nint windowHandle, uint message, nuint wParam, nint lParam, nuint subclassId, nuint referenceData)
    {
        if (message == WmGetMinMaxInfo && lParam != nint.Zero && Volatile.Read(ref _disposed) == 0)
        {
            try
            {
                uint dpi = GetDpiForWindow(windowHandle);
                if (dpi == 0) dpi = DefaultDpi;
                MinMaxInfo info = Marshal.PtrToStructure<MinMaxInfo>(lParam);
                info.MinimumTrackSize.X = DipToPixels(_minimumWidthDip, dpi);
                info.MinimumTrackSize.Y = DipToPixels(_minimumHeightDip, dpi);
                Marshal.StructureToPtr(info, lParam, false);
            }
            catch
            {
                // Native callbacks must never let an exception escape.
            }
        }

        return DefSubclassProc(windowHandle, message, wParam, lParam);
    }

    private static int DipToPixels(double dip, uint dpi) => (int)Math.Min(int.MaxValue, Math.Ceiling(dip * dpi / DefaultDpi));

    private static void ValidateMinimumSize(double widthDip, double heightDip)
    {
        if (!double.IsFinite(widthDip) || widthDip <= 0) throw new ArgumentOutOfRangeException(nameof(widthDip));
        if (!double.IsFinite(heightDip) || heightDip <= 0) throw new ArgumentOutOfRangeException(nameof(heightDip));
    }

    [StructLayout(LayoutKind.Sequential)] private struct NativePoint { public int X; public int Y; }
    [StructLayout(LayoutKind.Sequential)] private struct MinMaxInfo
    {
        public NativePoint Reserved;
        public NativePoint MaximumSize;
        public NativePoint MaximumPosition;
        public NativePoint MinimumTrackSize;
        public NativePoint MaximumTrackSize;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)] private delegate nint SubclassProcedure(nint windowHandle, uint message, nuint wParam, nint lParam, nuint subclassId, nuint referenceData);

    [DllImport("comctl32.dll", ExactSpelling = true, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowSubclass(nint windowHandle, SubclassProcedure subclassProcedure, nuint subclassId, nuint referenceData);
    [DllImport("comctl32.dll", ExactSpelling = true, SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveWindowSubclass(nint windowHandle, SubclassProcedure subclassProcedure, nuint subclassId);
    [DllImport("comctl32.dll", ExactSpelling = true)] private static extern nint DefSubclassProc(nint windowHandle, uint message, nuint wParam, nint lParam);
    [DllImport("user32.dll", ExactSpelling = true)] private static extern uint GetDpiForWindow(nint windowHandle);
    [DllImport("user32.dll", ExactSpelling = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool IsWindow(nint windowHandle);
}
