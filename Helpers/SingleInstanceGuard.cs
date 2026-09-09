using System;
using System.IO;
using System.Threading;

namespace LocalSecurityAudit.Helpers;

// A Windows-session/user key, independent of executable path, build or audit mode.
internal sealed class SingleInstanceGuard : IDisposable
{
    private readonly string _name;
    private Mutex? _mutex;
    private EventWaitHandle? _activation;
    private RegisteredWaitHandle? _listener;
    private bool _ownsMutex;

    internal SingleInstanceGuard(string userKey) => _name = @"Local\LocalSecurityAudit." + userKey;

    internal bool TryAcquire()
    {
        if (_ownsMutex) return true;
        try
        {
            _mutex ??= new Mutex(false, _name);
            _ownsMutex = _mutex.WaitOne(0);
        }
        catch (AbandonedMutexException) { _ownsMutex = true; }
        catch (UnauthorizedAccessException) { return false; } // An elevated instance can own the key.
        return _ownsMutex;
    }

    internal bool ActivateExisting()
    {
        try
        {
            using var signal = EventWaitHandle.OpenExisting(_name + ".Activate");
            return signal.Set();
        }
        catch (Exception error) when (error is WaitHandleCannotBeOpenedException or UnauthorizedAccessException or IOException)
        {
            // Startup/exit or a different integrity level must never open a second window.
            return false;
        }
    }

    internal void Listen(Action activate)
    {
        if (!_ownsMutex) throw new InvalidOperationException("Only the primary instance can listen.");
        _activation = new EventWaitHandle(false, EventResetMode.AutoReset, _name + ".Activate");
        _listener = ThreadPool.RegisterWaitForSingleObject(_activation, (_, _) => activate(), null, Timeout.Infinite, false);
    }

    internal void Release()
    {
        _listener?.Unregister(null);
        _listener = null;
        _activation?.Dispose();
        _activation = null;
        if (_ownsMutex)
        {
            _mutex!.ReleaseMutex();
            _ownsMutex = false;
        }
        _mutex?.Dispose();
        _mutex = null;
    }

    public void Dispose() => Release();
}
