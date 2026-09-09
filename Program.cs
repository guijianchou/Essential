using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using LocalSecurityAudit.Helpers;
using LocalSecurityAudit.Models;
using LocalSecurityAudit.Services;

namespace LocalSecurityAudit;

/// <summary>
/// Custom entry point so that launching the app a second time activates the existing
/// window instead of opening another copy. The generated XAML Main is disabled through
/// DISABLE_XAML_GENERATED_MAIN in the project file.
/// </summary>
public static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        WinRT.ComWrappersSupport.InitializeComWrappers();

        using var identity = WindowsIdentity.GetCurrent();
        string? ownerSid = args.FirstOrDefault(argument => argument.StartsWith("--owner-sid=", StringComparison.Ordinal))?["--owner-sid=".Length..];
        if (ownerSid != null && ownerSid != identity.User?.Value)
        {
            // UAC can accept a different administrator's credentials. Do not silently use that profile's settings/database.
            ShowStartupMessage("Full-access mode must be elevated as the same Windows user. Different administrator credentials would open a different data profile.");
            return 1;
        }

        using var instance = new SingleInstanceGuard(identity.User?.Value
            ?? throw new InvalidOperationException("Windows user identity unavailable."));
        if (!instance.TryAcquire())
        {
            instance.ActivateExisting();
            return 0;
        }

        string? modeOverride = args.Contains("--assistant", StringComparer.OrdinalIgnoreCase) ? AppMode.Assistant
            : args.Contains("--full", StringComparer.OrdinalIgnoreCase) ? AppMode.Full
            : args.Contains("--extended", StringComparer.OrdinalIgnoreCase) ? AppMode.Extended : null;
        var settings = new SettingsService(modeOverride);
        bool elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        if (!AppMode.RequiresElevation(settings.ActiveMode) && elevated)
        {
            ShowStartupMessage("Assistant and extended modes run without administrator privileges. Open the app normally from File Explorer, or choose full-access mode.");
            return 1;
        }
        if (AppMode.RequiresElevation(settings.ActiveMode) && !elevated)
        {
            // The same-user elevated child must acquire the same key, not inherit a
            // second mode-specific instance. A canceled prompt reacquires it below.
            instance.Release();
            try
            {
                var start = new ProcessStartInfo(Environment.ProcessPath
                    ?? throw new InvalidOperationException("Executable path unavailable."))
                {
                    UseShellExecute = true,
                    Verb = "runas"
                };
                start.ArgumentList.Add("--full");
                start.ArgumentList.Add($"--owner-sid={identity.User?.Value}");
                using var process = Process.Start(start);
                if (process == null) throw new InvalidOperationException("Launch failed.");
                return 0;
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                ShowStartupMessage("Administrator approval was canceled. Opening assistant mode; the saved startup mode and extended database are unchanged.");
            }
            catch (Exception ex) when (ex is Win32Exception or InvalidOperationException)
            {
                ShowStartupMessage("Full-access mode could not start. Opening assistant mode; the saved startup mode and existing databases are unchanged.");
            }
            if (!instance.TryAcquire())
            {
                instance.ActivateExisting();
                return 0;
            }
            settings = new SettingsService(AppMode.Assistant);
        }

        instance.Listen(OnInstanceActivated);

        Application.Start(parameters =>
        {
            var context = new DispatcherQueueSynchronizationContext(DispatcherQueue.GetForCurrentThread());
            SynchronizationContext.SetSynchronizationContext(context);
            _ = new App(settings);
        });

        return 0;
    }

    private static void ShowStartupMessage(string message) => MessageBox(IntPtr.Zero,
        AppText.Get(message), AppText.Get("Local Security Audit"), 0x40);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBox(IntPtr window, string text, string caption, uint type);

    private static void OnInstanceActivated()
    {
        if (Application.Current is App app)
        {
            app.ActivateMainWindow();
        }
    }

}
