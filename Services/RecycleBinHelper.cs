using System;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

namespace LocalSecurityAudit.Services;

/// <summary>
/// Provides safe file deletion by moving files to the Windows Recycle Bin.
/// Uses IFileOperation COM API for modern, reliable recycle bin operations.
/// </summary>
public sealed class RecycleBinHelper
{
    private readonly DiagnosticLogService _diagnosticLogService;

    public RecycleBinHelper(DiagnosticLogService diagnosticLogService)
    {
        _diagnosticLogService = diagnosticLogService;
    }

    /// <summary>
    /// Moves the specified file or directory to the Windows Recycle Bin.
    /// </summary>
    /// <param name="path">Absolute path to the file or directory to delete.</param>
    /// <returns>
    /// A tuple containing:
    /// - success: true if the item was moved to the recycle bin; false otherwise.
    /// - error: null on success; error message on failure.
    /// </returns>
    /// <remarks>
    /// This method handles locked files, access denied errors, and other failures gracefully
    /// by returning false rather than throwing exceptions. Permanent deletion is not supported.
    /// </remarks>
    public (bool success, string? error) MoveToRecycleBin(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return (false, "Path cannot be null or empty");
        }

        if (!System.IO.File.Exists(path) && !System.IO.Directory.Exists(path))
        {
            return (false, "Path does not exist");
        }

        try
        {
            IFileOperation? fileOperation = null;
            IShellItem? shellItem = null;

            try
            {
                // Create IFileOperation instance
                fileOperation = (IFileOperation)new FileOperation();

                // Configure operation: allow undo (recycle bin), no confirmation UI, silent on errors
                fileOperation.SetOperationFlags(
                    FileOperationFlags.FOF_ALLOWUNDO |
                    FileOperationFlags.FOF_NOCONFIRMATION |
                    FileOperationFlags.FOF_SILENT |
                    FileOperationFlags.FOF_NOERRORUI);

                // Create shell item from path
                var hr = NativeMethods.SHCreateItemFromParsingName(
                    path,
                    IntPtr.Zero,
                    typeof(IShellItem).GUID,
                    out shellItem);

                if (hr != 0 || shellItem == null)
                {
                    var errorMsg = $"Failed to create shell item: HRESULT=0x{hr:X8}";
                    _diagnosticLogService.Write($"RecycleBin operation failed: path={System.IO.Path.GetFileName(path)}, {errorMsg}");
                    return (false, errorMsg);
                }

                // Queue delete operation
                fileOperation.DeleteItem(shellItem, IntPtr.Zero);

                // Execute the operation
                hr = fileOperation.PerformOperations();

                if (hr != 0)
                {
                    var errorMsg = $"Failed to perform operation: HRESULT=0x{hr:X8}";
                    _diagnosticLogService.Write($"RecycleBin operation failed: path={System.IO.Path.GetFileName(path)}, {errorMsg}");
                    return (false, errorMsg);
                }

                _diagnosticLogService.Write($"RecycleBin operation succeeded: path={System.IO.Path.GetFileName(path)}");
                return (true, null);
            }
            finally
            {
                // Release COM objects
                if (shellItem != null)
                {
                    Marshal.ReleaseComObject(shellItem);
                }
                if (fileOperation != null)
                {
                    Marshal.ReleaseComObject(fileOperation);
                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            var errorMsg = $"Access denied: {ex.Message}";
            _diagnosticLogService.WriteException($"RecycleBin access denied: path={System.IO.Path.GetFileName(path)}", ex);
            return (false, errorMsg);
        }
        catch (System.IO.IOException ex)
        {
            var errorMsg = $"File is locked or in use: {ex.Message}";
            _diagnosticLogService.WriteException($"RecycleBin IO error: path={System.IO.Path.GetFileName(path)}", ex);
            return (false, errorMsg);
        }
        catch (COMException ex)
        {
            var errorMsg = $"COM error: 0x{ex.HResult:X8} - {ex.Message}";
            _diagnosticLogService.WriteException($"RecycleBin COM error: path={System.IO.Path.GetFileName(path)}", ex);
            return (false, errorMsg);
        }
        catch (Exception ex)
        {
            var errorMsg = $"Unexpected error: {ex.Message}";
            _diagnosticLogService.WriteException($"RecycleBin unexpected error: path={System.IO.Path.GetFileName(path)}", ex);
            return (false, errorMsg);
        }
    }

    #region COM Interop

    [ComImport]
    [Guid("3AD05575-8857-4850-9277-11B85BDB8E09")]
    [ClassInterface(ClassInterfaceType.None)]
    private class FileOperation
    {
    }

    [ComImport]
    [Guid("947AAB5F-0A5C-4C13-B4D6-4BF7836FC9F8")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileOperation
    {
        uint Advise(IntPtr pfops, out uint pdwCookie);
        uint Unadvise(uint dwCookie);
        uint SetOperationFlags(FileOperationFlags dwOperationFlags);
        uint SetProgressMessage([MarshalAs(UnmanagedType.LPWStr)] string pszMessage);
        uint SetProgressDialog(IntPtr popd);
        uint SetProperties(IntPtr pproparray);
        uint SetOwnerWindow(uint hwndOwner);
        uint ApplyPropertiesToItem(IShellItem psiItem);
        uint ApplyPropertiesToItems(IntPtr punkItems);
        uint RenameItem(IShellItem psiItem, [MarshalAs(UnmanagedType.LPWStr)] string pszNewName, IntPtr pfopsItem);
        uint RenameItems(IntPtr pUnkItems, [MarshalAs(UnmanagedType.LPWStr)] string pszNewName);
        uint MoveItem(IShellItem psiItem, IShellItem psiDestinationFolder, [MarshalAs(UnmanagedType.LPWStr)] string pszNewName, IntPtr pfopsItem);
        uint MoveItems(IntPtr punkItems, IShellItem psiDestinationFolder);
        uint CopyItem(IShellItem psiItem, IShellItem psiDestinationFolder, [MarshalAs(UnmanagedType.LPWStr)] string pszCopyName, IntPtr pfopsItem);
        uint CopyItems(IntPtr punkItems, IShellItem psiDestinationFolder);
        uint DeleteItem(IShellItem psiItem, IntPtr pfopsItem);
        uint DeleteItems(IntPtr punkItems);
        uint NewItem(IShellItem psiDestinationFolder, uint dwFileAttributes, [MarshalAs(UnmanagedType.LPWStr)] string pszName, [MarshalAs(UnmanagedType.LPWStr)] string pszTemplateName, IntPtr pfopsItem);
        int PerformOperations();
        uint GetAnyOperationsAborted([MarshalAs(UnmanagedType.Bool)] out bool pfAnyOperationsAborted);
    }

    [ComImport]
    [Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
        uint BindToHandler(IntPtr pbc, [MarshalAs(UnmanagedType.LPStruct)] Guid bhid, [MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv);
        uint GetParent(out IShellItem ppsi);
        uint GetDisplayName(uint sigdnName, [MarshalAs(UnmanagedType.LPWStr)] out string ppszName);
        uint GetAttributes(uint sfgaoMask, out uint psfgaoAttribs);
        uint Compare(IShellItem psi, uint hint, out int piOrder);
    }

    [Flags]
    private enum FileOperationFlags : uint
    {
        FOF_ALLOWUNDO = 0x0040,
        FOF_NOCONFIRMATION = 0x0010,
        FOF_SILENT = 0x0004,
        FOF_NOERRORUI = 0x0400
    }

    private static class NativeMethods
    {
        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int SHCreateItemFromParsingName(
            [MarshalAs(UnmanagedType.LPWStr)] string pszPath,
            IntPtr pbc,
            [MarshalAs(UnmanagedType.LPStruct)] Guid riid,
            [MarshalAs(UnmanagedType.Interface)] out IShellItem? ppv);
    }

    #endregion
}
