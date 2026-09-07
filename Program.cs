using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;
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
            ShowStartupMessage("Extended mode must be elevated as the same Windows user. Different administrator credentials would open a different data profile. Use assistant mode or sign in with the intended account.");
            return 1;
        }

        string? modeOverride = args.Contains("--assistant", StringComparer.OrdinalIgnoreCase) ? AppMode.Assistant
            : args.Contains("--extended", StringComparer.OrdinalIgnoreCase) ? AppMode.Extended : null;
        var settings = new SettingsService(modeOverride);
        bool elevated = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        if (settings.IsAssistantMode && elevated)
        {
            ShowStartupMessage("Assistant mode must run without administrator privileges. Close this launch and open the app normally from File Explorer.");
            return 1;
        }
        if (!settings.IsAssistantMode && !elevated)
        {
            try
            {
                var start = new ProcessStartInfo(Environment.ProcessPath
                    ?? throw new InvalidOperationException("Executable path unavailable."))
                {
                    UseShellExecute = true,
                    Verb = "runas"
                };
                start.ArgumentList.Add("--extended");
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
                ShowStartupMessage("Extended mode could not start. Opening assistant mode; the saved startup mode and extended database are unchanged.");
            }
            settings = new SettingsService(AppMode.Assistant);
        }

        var activationArguments = AppInstance.GetCurrent().GetActivatedEventArgs();
        var mainInstance = AppInstance.FindOrRegisterForKey($"LocalSecurityAudit.{settings.ActiveMode}");
        if (!mainInstance.IsCurrent)
        {
            RedirectActivation(mainInstance, activationArguments);
            return 0;
        }

        mainInstance.Activated += OnInstanceActivated;

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

    private static void OnInstanceActivated(object? sender, AppActivationArguments e)
    {
        if (Application.Current is App app)
        {
            app.ActivateMainWindow();
        }
    }

    /// <summary>
    /// Hands this launch over to the running instance. The redirect must not be awaited on the
    /// STA thread, so it runs on a worker while this thread pumps COM messages until it is done.
    /// </summary>
    private static void RedirectActivation(AppInstance target, AppActivationArguments arguments)
    {
        IntPtr redirectEvent = CreateEvent(IntPtr.Zero, true, false, null);
        if (redirectEvent == IntPtr.Zero)
        {
            target.RedirectActivationToAsync(arguments).AsTask().Wait();
            return;
        }

        _ = Task.Run(() =>
        {
            try
            {
                target.RedirectActivationToAsync(arguments).AsTask().Wait();
            }
            catch
            {
                // The new launch simply exits; the running instance stays as it was.
            }
            finally
            {
                SetEvent(redirectEvent);
            }
        });

        _ = CoWaitForMultipleObjects(0, 0xFFFFFFFF, 1, new[] { redirectEvent }, out _);
        CloseHandle(redirectEvent);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string? lpName);

    [DllImport("kernel32.dll")]
    private static extern bool SetEvent(IntPtr hEvent);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ole32.dll")]
    private static extern uint CoWaitForMultipleObjects(uint dwFlags, uint dwMilliseconds, ulong nHandles, IntPtr[] pHandles, out uint dwIndex);
}
