using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace LocalSecurityAudit.Views;

internal sealed class TrayIcon : IDisposable
{
    private const uint WmNull = 0x0000;
    private const uint WmContextMenu = 0x007B;
    private const uint WmLButtonUp = 0x0202;
    private const uint WmLButtonDoubleClick = 0x0203;
    private const uint WmRButtonUp = 0x0205;
    private const uint WmUser = 0x0400;
    private const uint WmApp = 0x8000;
    private const uint TrayCallbackMessage = WmApp + 0x051A;
    private const uint NinSelect = WmUser;
    private const uint NinKeySelect = WmUser + 1;

    private const uint NimAdd = 0x00000000;
    private const uint NimModify = 0x00000001;
    private const uint NimDelete = 0x00000002;
    private const uint NimSetVersion = 0x00000004;
    private const uint NifMessage = 0x00000001;
    private const uint NifIcon = 0x00000002;
    private const uint NifTip = 0x00000004;
    private const uint NifInfo = 0x00000010;
    private const uint NifShowTip = 0x00000080;
    private const uint NotifyIconVersion4 = 4;
    private const uint NiifInfo = 0x00000001;
    private const uint NiifError = 0x00000003;

    private const uint ImageIcon = 1;
    private const uint LoadFromFile = 0x00000010;
    private const uint LoadDefaultSize = 0x00000040;

    private const uint MfString = 0x00000000;
    private const uint MfSeparator = 0x00000800;
    private const uint TpmLeftAlign = 0x0000;
    private const uint TpmRightButton = 0x0002;
    private const uint TpmReturnCommand = 0x0100;
    private const uint RestoreCommand = 1;
    private const uint ExitCommand = 2;

    private static long _nextSubclassId = 0x4E4D0000;
    private static int _nextIconId;

    private readonly nint _windowHandle;
    private readonly nint _iconHandle;
    private readonly uint _iconId;
    private readonly nuint _subclassId;
    private readonly uint _taskbarCreatedMessage;
    private readonly SubclassProcedure _subclassProcedure;
    private bool _isVisible;
    private bool _isAdded;
    private bool _usesVersionFourCallbacks;
    private int _disposed;

    public TrayIcon(nint hwnd, string iconPath)
    {
        if (hwnd == nint.Zero || !IsWindow(hwnd))
        {
            throw new ArgumentException("A valid native window handle is required.", nameof(hwnd));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(iconPath);
        string fullIconPath = Path.GetFullPath(iconPath);
        if (!File.Exists(fullIconPath))
        {
            throw new FileNotFoundException("The notification area icon file was not found.", fullIconPath);
        }

        _windowHandle = hwnd;
        _iconId = AllocateIconId();
        _subclassId = unchecked((nuint)Interlocked.Increment(ref _nextSubclassId));
        _taskbarCreatedMessage = RegisterWindowMessageW("TaskbarCreated");
        if (_taskbarCreatedMessage == 0)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to register the taskbar restart message.");
        }

        _iconHandle = LoadImageW(nint.Zero, fullIconPath, ImageIcon, 0, 0, LoadFromFile | LoadDefaultSize);
        if (_iconHandle == nint.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to load the notification area icon.");
        }

        _subclassProcedure = ProcessWindowMessage;
        if (!SetWindowSubclass(_windowHandle, _subclassProcedure, _subclassId, nuint.Zero))
        {
            int error = Marshal.GetLastWin32Error();
            DestroyIcon(_iconHandle);
            throw new Win32Exception(error, "Failed to subscribe to notification area events.");
        }
    }

    public event EventHandler? RestoreRequested;
    public event EventHandler? ExitRequested;

    public void Show()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);

        if (_isAdded)
        {
            _isVisible = true;
            return;
        }

        AddIcon(throwOnFailure: true);
        _isVisible = true;
    }

    public void Hide()
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        _isVisible = false;
        DeleteIcon();
    }

    public void ShowNotification(string title, string message, bool isError = false)
    {
        if (Volatile.Read(ref _disposed) != 0 || !_isAdded)
        {
            return;
        }

        NotifyIconData data = CreateNotifyIconData();
        data.Flags = NifIcon | NifTip | NifInfo;
        data.InfoTitle = LimitText(title, 63);
        data.Info = LimitText(message, 255);
        data.InfoFlags = isError ? NiifError : NiifInfo;
        Shell_NotifyIconW(NimModify, ref data);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _isVisible = false;
        DeleteIcon();
        RemoveWindowSubclass(_windowHandle, _subclassProcedure, _subclassId);
        DestroyIcon(_iconHandle);
        GC.SuppressFinalize(this);
    }

    private nint ProcessWindowMessage(
        nint windowHandle,
        uint message,
        nuint wParam,
        nint lParam,
        nuint subclassId,
        nuint referenceData)
    {
        try
        {
            if (message == _taskbarCreatedMessage)
            {
                _isAdded = false;
                _usesVersionFourCallbacks = false;
                if (_isVisible && Volatile.Read(ref _disposed) == 0)
                {
                    AddIcon(throwOnFailure: false);
                }
            }
            else if (message == TrayCallbackMessage
                && Volatile.Read(ref _disposed) == 0
                && TryReadTrayEvent(wParam, lParam, out uint trayEvent, out NativePoint anchor))
            {
                HandleTrayEvent(trayEvent, anchor);
            }
        }
        catch (Exception)
        {
            // Native window procedures must never let managed exceptions escape.
        }

        return DefSubclassProc(windowHandle, message, wParam, lParam);
    }

    private void HandleTrayEvent(uint trayEvent, NativePoint anchor)
    {
        switch (trayEvent)
        {
            case NinSelect:
            case NinKeySelect:
            case WmLButtonUp:
            case WmLButtonDoubleClick:
                RestoreRequested?.Invoke(this, EventArgs.Empty);
                break;
            case WmContextMenu:
            case WmRButtonUp:
                ShowContextMenu(anchor);
                break;
        }
    }

    private bool TryReadTrayEvent(
        nuint wParam,
        nint lParam,
        out uint trayEvent,
        out NativePoint anchor)
    {
        if (_usesVersionFourCallbacks)
        {
            ulong rawLParam = unchecked((ulong)lParam.ToInt64());
            if ((ushort)(rawLParam >> 16) != (ushort)_iconId)
            {
                trayEvent = 0;
                anchor = default;
                return false;
            }

            trayEvent = (ushort)rawLParam;
            ulong rawWParam = wParam;
            anchor = new NativePoint
            {
                X = unchecked((short)rawWParam),
                Y = unchecked((short)(rawWParam >> 16)),
            };
            return true;
        }

        if ((uint)wParam != _iconId)
        {
            trayEvent = 0;
            anchor = default;
            return false;
        }

        trayEvent = unchecked((uint)lParam.ToInt64());
        GetCursorPos(out anchor);
        return true;
    }

    private void ShowContextMenu(NativePoint anchor)
    {
        if ((anchor.X == -1 && anchor.Y == -1) || (anchor.X == 0 && anchor.Y == 0))
        {
            GetCursorPos(out anchor);
        }

        nint menu = CreatePopupMenu();
        if (menu == nint.Zero)
        {
            return;
        }

        try
        {
            if (!AppendMenuW(menu, MfString, RestoreCommand, "Restore")
                || !AppendMenuW(menu, MfSeparator, 0, null)
                || !AppendMenuW(menu, MfString, ExitCommand, "Exit"))
            {
                return;
            }

            SetForegroundWindow(_windowHandle);
            uint command = TrackPopupMenuEx(
                menu,
                TpmLeftAlign | TpmRightButton | TpmReturnCommand,
                anchor.X,
                anchor.Y,
                _windowHandle,
                nint.Zero);
            PostMessageW(_windowHandle, WmNull, nuint.Zero, nint.Zero);

            if (command == RestoreCommand)
            {
                RestoreRequested?.Invoke(this, EventArgs.Empty);
            }
            else if (command == ExitCommand)
            {
                ExitRequested?.Invoke(this, EventArgs.Empty);
            }
        }
        finally
        {
            DestroyMenu(menu);
        }
    }

    private void AddIcon(bool throwOnFailure)
    {
        NotifyIconData data = CreateNotifyIconData();
        if (!Shell_NotifyIconW(NimAdd, ref data))
        {
            _isAdded = false;
            if (throwOnFailure)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Failed to add the notification area icon.");
            }

            return;
        }

        _isAdded = true;
        data.TimeoutOrVersion = NotifyIconVersion4;
        _usesVersionFourCallbacks = Shell_NotifyIconW(NimSetVersion, ref data);
        if (!_usesVersionFourCallbacks)
        {
            data.Flags = NifMessage | NifIcon | NifTip;
            Shell_NotifyIconW(NimModify, ref data);
        }
    }

    private void DeleteIcon()
    {
        if (!_isAdded)
        {
            return;
        }

        NotifyIconData data = CreateNotifyIconData();
        Shell_NotifyIconW(NimDelete, ref data);
        _isAdded = false;
        _usesVersionFourCallbacks = false;
    }

    private NotifyIconData CreateNotifyIconData()
    {
        return new NotifyIconData
        {
            Size = (uint)Marshal.SizeOf<NotifyIconData>(),
            WindowHandle = _windowHandle,
            IconId = _iconId,
            Flags = NifMessage | NifIcon | NifTip | NifShowTip,
            CallbackMessage = TrayCallbackMessage,
            IconHandle = _iconHandle,
            Tip = "Local Security Audit",
        };
    }

    private static string LimitText(string value, int maximumLength)
    {
        value ??= string.Empty;
        return value.Length <= maximumLength ? value : value[..maximumLength];
    }

    private static uint AllocateIconId()
    {
        uint iconId = unchecked((uint)Interlocked.Increment(ref _nextIconId));
        iconId &= ushort.MaxValue;
        return iconId == 0 ? 1u : iconId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativePoint
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct NotifyIconData
    {
        public uint Size;
        public nint WindowHandle;
        public uint IconId;
        public uint Flags;
        public uint CallbackMessage;
        public nint IconHandle;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string Tip;

        public uint State;
        public uint StateMask;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string Info;

        public uint TimeoutOrVersion;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string InfoTitle;

        public uint InfoFlags;
        public Guid GuidItem;
        public nint BalloonIconHandle;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate nint SubclassProcedure(
        nint windowHandle,
        uint message,
        nuint wParam,
        nint lParam,
        nuint subclassId,
        nuint referenceData);

    [DllImport("shell32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Shell_NotifyIconW(uint message, ref NotifyIconData data);

    [DllImport("comctl32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetWindowSubclass(nint windowHandle, SubclassProcedure procedure, nuint subclassId, nuint referenceData);

    [DllImport("comctl32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RemoveWindowSubclass(nint windowHandle, SubclassProcedure procedure, nuint subclassId);

    [DllImport("comctl32.dll", ExactSpelling = true)]
    private static extern nint DefSubclassProc(nint windowHandle, uint message, nuint wParam, nint lParam);

    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint RegisterWindowMessageW(string message);

    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint LoadImageW(nint instance, string name, uint type, int desiredWidth, int desiredHeight, uint loadFlags);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(nint icon);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern nint CreatePopupMenu();

    [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AppendMenuW(nint menu, uint flags, nuint itemId, string? text);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyMenu(nint menu);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    private static extern uint TrackPopupMenuEx(nint menu, uint flags, int x, int y, nint ownerWindow, nint parameters);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetForegroundWindow(nint windowHandle);

    [DllImport("user32.dll", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostMessageW(nint windowHandle, uint message, nuint wParam, nint lParam);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetCursorPos(out NativePoint point);

    [DllImport("user32.dll", ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindow(nint windowHandle);
}
