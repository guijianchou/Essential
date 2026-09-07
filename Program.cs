using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.Windows.AppLifecycle;

namespace LocalSecurityAudit;

/// <summary>
/// Custom entry point so that launching the app a second time activates the existing
/// window instead of opening another copy. The generated XAML Main is disabled through
/// DISABLE_XAML_GENERATED_MAIN in the project file.
/// </summary>
public static class Program
{
    private const string InstanceKey = "LocalSecurityAudit.Main";

    [STAThread]
    private static int Main(string[] args)
    {
        WinRT.ComWrappersSupport.InitializeComWrappers();

        var activationArguments = AppInstance.GetCurrent().GetActivatedEventArgs();
        var mainInstance = AppInstance.FindOrRegisterForKey(InstanceKey);
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
            _ = new App();
        });

        return 0;
    }

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
