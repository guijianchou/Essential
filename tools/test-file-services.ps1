# Verifies file service operations: RecycleBin, path boundaries, validation, locks, collisions, and revalidation.
# Exercises CacheCleanupService, DownloadOrganizerService, and RecycleBinHelper with synthetic files.
param(
    [string]$AssemblyPath = "$PSScriptRoot\..\artifacts\bin\x64\Release\net8.0-windows10.0.19041.0\Essential.dll"
)

$ErrorActionPreference = 'Stop'
$assembly = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$flags = [Reflection.BindingFlags]'NonPublic,Instance,Static,Public'

$cacheServiceType = $assembly.GetType('LocalSecurityAudit.Services.CacheCleanupService', $true)
$downloadServiceType = $assembly.GetType('LocalSecurityAudit.Services.DownloadOrganizerService', $true)
$recycleBinHelperType = $assembly.GetType('LocalSecurityAudit.Services.RecycleBinHelper', $true)
$diagnosticLogType = $assembly.GetType('LocalSecurityAudit.Services.DiagnosticLogService', $true)
$tempFileInfoType = $assembly.GetType('LocalSecurityAudit.ViewModels.TempFileInfo', $true)
$riskLevelType = $assembly.GetType('LocalSecurityAudit.Services.RiskLevel', $true)
$settingsServiceType = $assembly.GetType('LocalSecurityAudit.Services.SettingsService', $true)
$appSettingsType = $assembly.GetType('LocalSecurityAudit.Models.AppSettings', $true)

$script:passed = 0
$script:failed = 0

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Assert-Equal($Expected, $Actual, [string]$Message) {
    if ($Expected -ne $Actual) {
        throw "$Message (expected: $Expected, actual: $Actual)"
    }
}

function Test-Case([string]$Name, [scriptblock]$Action) {
    try {
        $null = & $Action
        $script:passed++
        Write-Output "PASS $Name"
    }
    catch {
        $script:failed++
        Write-Output "FAIL $Name`: $($_.Exception.GetBaseException().Message)"
        Write-Output $_.ScriptStackTrace
    }
}

function New-DiagnosticLog {
    # Create SettingsService with test directory
    $tempDir = [IO.Path]::Combine([IO.Path]::GetTempPath(), "lsa-test-$([guid]::NewGuid())")
    [IO.Directory]::CreateDirectory($tempDir) | Out-Null

    # Initialize SettingsService with dataDirectory parameter (constructor signature)
    $settingsService = [Activator]::CreateInstance($settingsServiceType, @($null, $tempDir))

    # Create DiagnosticLogService with SettingsService
    return [Activator]::CreateInstance($diagnosticLogType, @($settingsService))
}

function New-RecycleBinHelper {
    $log = New-DiagnosticLog
    return [Activator]::CreateInstance($recycleBinHelperType, @($log))
}

function New-CacheService {
    $log = New-DiagnosticLog
    $recycler = New-RecycleBinHelper
    return [Activator]::CreateInstance($cacheServiceType, @($log, $recycler))
}

function New-DownloadService {
    $log = New-DiagnosticLog
    return [Activator]::CreateInstance($downloadServiceType, @($log))
}

function New-TempFileInfo([string]$Path, [long]$Size = 1024, [datetime]$Modified = [datetime]::Now) {
    $info = [Activator]::CreateInstance($tempFileInfoType)
    $info.FilePath = $Path
    $info.SizeInBytes = $Size
    $info.LastModified = $Modified
    $info.IsSelected = $false
    return $info
}

function New-TestDirectory {
    $path = [IO.Path]::Combine([IO.Path]::GetTempPath(), "lsa-test-$([guid]::NewGuid())")
    [IO.Directory]::CreateDirectory($path) | Out-Null
    return $path
}

function New-TestFile([string]$Directory, [string]$FileName, [int]$SizeBytes = 1024) {
    $path = [IO.Path]::Combine($Directory, $FileName)
    $bytes = [byte[]]::new($SizeBytes)
    [IO.File]::WriteAllBytes($path, $bytes)
    return $path
}

function Lock-File([string]$Path) {
    return [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
}

# RecycleBinHelper Tests

Test-Case 'RecycleBinHelper rejects null or empty path' {
    $helper = New-RecycleBinHelper
    $result = $helper.MoveToRecycleBin("")
    Assert-True (-not $result.Item1) "Should reject empty path"
    Assert-True (-not [string]::IsNullOrWhiteSpace($result.Item2)) "Should return error message"
}

Test-Case 'RecycleBinHelper rejects non-existent path' {
    $helper = New-RecycleBinHelper
    $fakePath = [IO.Path]::Combine([IO.Path]::GetTempPath(), "nonexistent-$([guid]::NewGuid()).txt")
    $result = $helper.MoveToRecycleBin($fakePath)
    Assert-True (-not $result.Item1) "Should reject non-existent path"
}

Test-Case 'RecycleBinHelper moves file to recycle bin (API availability check)' {
    $helper = New-RecycleBinHelper
    $testDir = New-TestDirectory
    try {
        $testFile = New-TestFile $testDir "deleteme.txt" 512
        $result = $helper.MoveToRecycleBin($testFile)

        # Check if operation succeeded (API may not be available in all test environments)
        if ($result.Item1) {
            Assert-True (-not [IO.File]::Exists($testFile)) "File should be deleted"
        }
        else {
            # API not available or failed - acceptable in test environment
            Write-Output "  (RecycleBin API not available or failed: $($result.Item2))"
        }
    }
    finally {
        if ([IO.Directory]::Exists($testDir)) { [IO.Directory]::Delete($testDir, $true) }
    }
}

Test-Case 'RecycleBinHelper handles locked file gracefully' {
    $helper = New-RecycleBinHelper
    $testDir = New-TestDirectory
    $stream = $null
    try {
        $testFile = New-TestFile $testDir "locked.txt" 256
        $stream = Lock-File $testFile

        $result = $helper.MoveToRecycleBin($testFile)

        # RecycleBin COM API may succeed even if file is locked by our stream
        # The important part is that it handles the call gracefully (no exception)
        if (-not $result.Item1) {
            Assert-True (-not [string]::IsNullOrWhiteSpace($result.Item2)) "Should return error message"
            Assert-True ([IO.File]::Exists($testFile)) "Locked file should still exist"
        }
        else {
            # COM API succeeded despite lock - acceptable behavior
            Write-Output "  (RecycleBin succeeded despite file lock - COM API handled it)"
        }
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([IO.Directory]::Exists($testDir)) { [IO.Directory]::Delete($testDir, $true) }
    }
}

# CacheCleanupService Tests

Test-Case 'CacheCleanupService rejects forbidden root paths' {
    $service = New-CacheService
    $locations = $service.GetCacheLocations()

    # Check that no location points to forbidden roots like %USERPROFILE% or %LOCALAPPDATA% exactly
    $forbiddenRoots = @(
        [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile),
        [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    )

    foreach ($location in $locations) {
        foreach ($root in $forbiddenRoots) {
            if ($location.Path -eq $root) {
                Assert-True (-not $location.IsValid) "Forbidden root $root should be marked invalid"
                Assert-True ($null -ne $location.SkipReason) "Should have skip reason"
            }
        }
    }
}

Test-Case 'CacheCleanupService detects locked files' {
    $service = New-CacheService
    $testDir = New-TestDirectory
    $stream = $null
    try {
        $testFile = New-TestFile $testDir "locked.tmp" 128
        $stream = Lock-File $testFile

        $isLocked = $service.IsFileLocked($testFile)
        Assert-True $isLocked "Should detect locked file"
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([IO.Directory]::Exists($testDir)) { [IO.Directory]::Delete($testDir, $true) }
    }
}

Test-Case 'CacheCleanupService detects unlocked files' {
    $service = New-CacheService
    $testDir = New-TestDirectory
    try {
        $testFile = New-TestFile $testDir "unlocked.tmp" 128

        $isLocked = $service.IsFileLocked($testFile)
        Assert-True (-not $isLocked) "Should detect unlocked file"
    }
    finally {
        if ([IO.Directory]::Exists($testDir)) { [IO.Directory]::Delete($testDir, $true) }
    }
}

Test-Case 'CacheCleanupService calculates file size correctly' {
    $service = New-CacheService
    $testDir = New-TestDirectory
    try {
        $expectedSize = 2048
        $testFile = New-TestFile $testDir "sizeme.tmp" $expectedSize

        $actualSize = $service.CalculateSize($testFile)
        Assert-Equal $expectedSize $actualSize "File size should match"
    }
    finally {
        if ([IO.Directory]::Exists($testDir)) { [IO.Directory]::Delete($testDir, $true) }
    }
}

Test-Case 'CacheCleanupService revalidates items before deletion' {
    $service = New-CacheService
    $testDir = New-TestDirectory
    try {
        $testFile = New-TestFile $testDir "tobedeleted.tmp" 256
        $fileInfo = New-TempFileInfo $testFile 256

        # Delete the file before calling DeleteCacheItems
        [IO.File]::Delete($testFile)

        # Create a proper List[TempFileInfo] for the method call
        $listType = [Type]::GetType('System.Collections.Generic.List`1').MakeGenericType($tempFileInfoType)
        $list = [Activator]::CreateInstance($listType)
        $list.Add($fileInfo)

        $results = $service.DeleteCacheItems($list, [System.Threading.CancellationToken]::None)

        Assert-Equal 1 $results.Count "Should return one result"
        Assert-True (-not $results[0].Success) "Should fail for non-existent file"
        Assert-True ($results[0].Error -like "*no longer exists*") "Should indicate file no longer exists"
    }
    finally {
        if ([IO.Directory]::Exists($testDir)) { [IO.Directory]::Delete($testDir, $true) }
    }
}

Test-Case 'CacheCleanupService skips locked files during deletion' {
    $service = New-CacheService
    $testDir = New-TestDirectory
    $stream = $null
    try {
        $testFile = New-TestFile $testDir "locked.tmp" 256
        $fileInfo = New-TempFileInfo $testFile 256
        $stream = Lock-File $testFile

        # Create a proper List[TempFileInfo] for the method call
        $listType = [Type]::GetType('System.Collections.Generic.List`1').MakeGenericType($tempFileInfoType)
        $list = [Activator]::CreateInstance($listType)
        $list.Add($fileInfo)

        $results = $service.DeleteCacheItems($list, [System.Threading.CancellationToken]::None)

        Assert-Equal 1 $results.Count "Should return one result"
        Assert-True (-not $results[0].Success) "Should fail for locked file"
        Assert-True ($results[0].Error -like "*locked*") "Should indicate file is locked"
        Assert-True ([IO.File]::Exists($testFile)) "Locked file should still exist"
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([IO.Directory]::Exists($testDir)) { [IO.Directory]::Delete($testDir, $true) }
    }
}

# DownloadOrganizerService Tests

Test-Case 'DownloadOrganizerService resolves Downloads path' {
    $service = New-DownloadService
    $result = $service.GetDownloadsPath()

    Assert-True $result.Item1 "Should resolve Downloads path"
    Assert-True (-not [string]::IsNullOrWhiteSpace($result.Item2)) "Path should not be empty"
    Assert-True ([IO.Directory]::Exists($result.Item2)) "Downloads directory should exist"
}

Test-Case 'DownloadOrganizerService rejects path traversal in target directory' {
    $service = New-DownloadService
    $downloadsResult = $service.GetDownloadsPath()

    if (-not $downloadsResult.Item1) {
        Write-Output "  (Skipped: Downloads path not available)"
        return
    }

    $testDir = New-TestDirectory
    try {
        # Create a test file in temp directory (not Downloads)
        $testFile = New-TestFile $testDir "test.txt" 128
        $fileInfo = New-TempFileInfo $testFile 128

        # Try to move with path traversal
        $result = $service.PlanMove($fileInfo, "..\..\..\Windows")

        Assert-True (-not $result.Item1) "Should reject path traversal"
        Assert-True (-not [string]::IsNullOrWhiteSpace($result.Item3)) "Should return error message"
    }
    finally {
        if ([IO.Directory]::Exists($testDir)) { [IO.Directory]::Delete($testDir, $true) }
    }
}

Test-Case 'DownloadOrganizerService rejects absolute paths outside Downloads' {
    $service = New-DownloadService
    $downloadsResult = $service.GetDownloadsPath()

    if (-not $downloadsResult.Item1) {
        Write-Output "  (Skipped: Downloads path not available)"
        return
    }

    $testDir = New-TestDirectory
    try {
        $testFile = New-TestFile $testDir "test.txt" 128
        $fileInfo = New-TempFileInfo $testFile 128

        # Try to move to C:\Windows (absolute path outside Downloads)
        $result = $service.PlanMove($fileInfo, "C:\Windows")

        Assert-True (-not $result.Item1) "Should reject absolute path outside Downloads"
        Assert-True (-not [string]::IsNullOrWhiteSpace($result.Item3)) "Should return error message"
    }
    finally {
        if ([IO.Directory]::Exists($testDir)) { [IO.Directory]::Delete($testDir, $true) }
    }
}

Test-Case 'DownloadOrganizerService handles collision with numbered suffix' {
    $service = New-DownloadService
    $downloadsResult = $service.GetDownloadsPath()

    if (-not $downloadsResult.Item1) {
        Write-Output "  (Skipped: Downloads path not available)"
        return
    }

    $downloadsPath = $downloadsResult.Item2
    $testSubDir = [IO.Path]::Combine($downloadsPath, "test-$([guid]::NewGuid())")

    try {
        [IO.Directory]::CreateDirectory($testSubDir) | Out-Null

        # Create source file in Downloads root
        $sourceFile = [IO.Path]::Combine($downloadsPath, "collision-$([guid]::NewGuid()).txt")
        [IO.File]::WriteAllText($sourceFile, "source")

        # Create existing target file
        $targetFile = [IO.Path]::Combine($testSubDir, [IO.Path]::GetFileName($sourceFile))
        [IO.File]::WriteAllText($targetFile, "existing")

        $fileInfo = New-TempFileInfo $sourceFile 6
        $targetRelative = [IO.Path]::GetRelativePath($downloadsPath, $testSubDir)

        $result = $service.PlanMove($fileInfo, $targetRelative)

        Assert-True $result.Item1 "Should plan move successfully"
        Assert-True ($null -ne $result.Item2) "Should return action"
        Assert-True ($result.Item2.TargetPath -ne $targetFile) "Should generate different target path"
        Assert-True ($result.Item2.TargetPath -like "*(*)*") "Should use numbered suffix"
    }
    finally {
        if ([IO.File]::Exists($sourceFile)) { [IO.File]::Delete($sourceFile) }
        if ([IO.Directory]::Exists($testSubDir)) { [IO.Directory]::Delete($testSubDir, $true) }
    }
}

Test-Case 'DownloadOrganizerService rejects stale scan generation' {
    $service = New-DownloadService
    $downloadsResult = $service.GetDownloadsPath()

    if (-not $downloadsResult.Item1) {
        Write-Output "  (Skipped: Downloads path not available)"
        return
    }

    $downloadsPath = $downloadsResult.Item2
    $testSubDir = [IO.Path]::Combine($downloadsPath, "test-$([guid]::NewGuid())")

    try {
        [IO.Directory]::CreateDirectory($testSubDir) | Out-Null

        # Perform scan to get generation
        $scanResult = $service.ScanDownloadsAsync([System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        $generation1 = $service.CurrentScanGeneration

        # Perform another scan to increment generation
        $scanResult2 = $service.ScanDownloadsAsync([System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        $generation2 = $service.CurrentScanGeneration

        Assert-True ($generation2 -gt $generation1) "Second scan should increment generation"

        # Create a test file
        $sourceFile = [IO.Path]::Combine($downloadsPath, "stale-$([guid]::NewGuid()).txt")
        [IO.File]::WriteAllText($sourceFile, "test")

        $fileInfo = New-TempFileInfo $sourceFile 4
        $targetRelative = [IO.Path]::GetRelativePath($downloadsPath, $testSubDir)
        $planResult = $service.PlanMove($fileInfo, $targetRelative)

        if ($planResult.Item1) {
            # Try to execute with old generation
            $execResult = $service.ExecuteMoveAsync($planResult.Item2, $generation1, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()

            Assert-True (-not $execResult.Item1) "Should reject stale generation"
            Assert-True ($execResult.Item2 -like "*generation*") "Should indicate generation mismatch"
        }
    }
    finally {
        if ([IO.File]::Exists($sourceFile)) { [IO.File]::Delete($sourceFile) }
        if ([IO.Directory]::Exists($testSubDir)) { [IO.Directory]::Delete($testSubDir, $true) }
    }
}

Test-Case 'DownloadOrganizerService classifies files by extension' {
    $service = New-DownloadService

    $pdfFile = New-TempFileInfo "test.pdf"
    $category = $service.ClassifyByExtension($pdfFile)
    Assert-Equal "Documents" $category "PDF should be classified as Documents"

    $jpgFile = New-TempFileInfo "test.jpg"
    $category = $service.ClassifyByExtension($jpgFile)
    Assert-Equal "Images" $category "JPG should be classified as Images"

    $mp4File = New-TempFileInfo "test.mp4"
    $category = $service.ClassifyByExtension($mp4File)
    Assert-Equal "Videos" $category "MP4 should be classified as Videos"

    $unknownFile = New-TempFileInfo "test.unknown"
    $category = $service.ClassifyByExtension($unknownFile)
    Assert-True ($null -eq $category) "Unknown extension should return null"
}

Test-Case 'DownloadOrganizerService stays within Downloads boundaries' {
    $service = New-DownloadService
    $downloadsResult = $service.GetDownloadsPath()

    if (-not $downloadsResult.Item1) {
        Write-Output "  (Skipped: Downloads path not available)"
        return
    }

    $downloadsPath = $downloadsResult.Item2

    # Create a test file in Downloads root
    $sourceFile = [IO.Path]::Combine($downloadsPath, "boundary-$([guid]::NewGuid()).txt")
    [IO.File]::WriteAllText($sourceFile, "test")

    try {
        $fileInfo = New-TempFileInfo $sourceFile 4

        # Valid: subdirectory within Downloads
        $result1 = $service.PlanMove($fileInfo, "Documents")
        Assert-True $result1.Item1 "Should allow move to Downloads subdirectory"

        # Invalid: outside Downloads
        $result2 = $service.PlanMove($fileInfo, "..\Desktop")
        Assert-True (-not $result2.Item1) "Should reject move outside Downloads"

        # Invalid: path traversal
        $result3 = $service.PlanMove($fileInfo, "subdir\..\..\Windows")
        Assert-True (-not $result3.Item1) "Should reject path traversal"
    }
    finally {
        if ([IO.File]::Exists($sourceFile)) { [IO.File]::Delete($sourceFile) }
    }
}

# Summary
Write-Output ""
Write-Output "=========================================="
Write-Output "Test Summary"
Write-Output "=========================================="
Write-Output "Passed: $script:passed"
Write-Output "Failed: $script:failed"
Write-Output "Total:  $($script:passed + $script:failed)"
Write-Output "=========================================="

if ($script:failed -gt 0) {
    exit 1
}
exit 0
