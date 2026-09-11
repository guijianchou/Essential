# Compile the real XAML with a separate test entry point and only synthetic services.
# This never launches Program.Main, starts a scan, or reads the user's settings/database.
param([string]$OutputRoot = (Join-Path ([IO.Path]::GetTempPath()) ('lsa-ui-regression-' + [guid]::NewGuid().ToString('N'))))
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($OutputRoot)
if (Test-Path -LiteralPath $root) { throw 'Choose a new, empty output directory for UI regression.' }
$null = [IO.Directory]::CreateDirectory($root)
$targets = Join-Path $root 'test.targets'
$source = [Security.SecurityElement]::Escape((Join-Path $PSScriptRoot 'WorkflowUiRegression.cs.txt'))
@"
<Project>
  <ItemGroup>
    <Compile Include="$source" />
    <Content Remove="codex-x86_64-pc-windows-msvc.exe.zip;pi-windows-x64.zip" />
  </ItemGroup>
</Project>
"@ | Set-Content -LiteralPath $targets -Encoding utf8
$output = Join-Path $root 'app'
$project = Join-Path (Split-Path -Parent $PSScriptRoot) 'LocalSecurityAudit.csproj'
& dotnet build $project --no-restore --nologo -c Debug -p:Platform=x64 -p:StartupObject=LocalSecurityAudit.WorkflowUiRegression "-p:CustomAfterMicrosoftCommonTargets=$targets" "-p:OutputPath=$output/" "-p:IntermediateOutputPath=$root/obj/"
if ($LASTEXITCODE -ne 0) { throw 'The isolated UI regression build failed.' }
$executable = Join-Path $output 'Essential.exe'
$previous = $env:LSA_UI_TEST_ROOT
try {
    $env:LSA_UI_TEST_ROOT = $root
    $process = Start-Process -FilePath $executable -WorkingDirectory (Split-Path -Parent $executable) -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(45000)) { $process.Kill($true); throw 'UI regression timed out.' }
    $result = Join-Path $root 'result.txt'
    if (Test-Path -LiteralPath $result) { Get-Content -LiteralPath $result }
    if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $result)) { throw "UI regression failed; see $root" }
    "UI regression artifacts: $root"
}
finally { $env:LSA_UI_TEST_ROOT = $previous }
