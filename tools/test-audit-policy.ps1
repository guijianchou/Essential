# Policy migration uses only generated configuration under the temporary directory.
param([string]$AssemblyPath = "$PSScriptRoot\..\artifacts\bin\x64\Debug\net8.0-windows10.0.19041.0\Essential.dll")
$ErrorActionPreference = 'Stop'
$null = [Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$root = Join-Path ([IO.Path]::GetTempPath()) ('lsa-policy-regression-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($root)
function Assert-True([bool]$value, [string]$message) { if (-not $value) { throw $message }; "PASS $message" }
function New-Profile([string]$name, [hashtable]$settings = @{}) {
    $path = Join-Path $root $name
    $null = [IO.Directory]::CreateDirectory($path)
    $settings.AutoScanEnabled = $false
    $settings | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $path 'settings.json') -Encoding utf8
    return $path
}

$path = New-Profile 'legacy-file' @{AgentInstructions='Legacy JSON policy'}
$legacy = Join-Path $path 'AGENTS.md'
$original = "# Custom Windows audit policy`r`n保留自定义规则。`r`n"
[IO.File]::WriteAllText($legacy, $original)
$service = [LocalSecurityAudit.Services.SettingsService]::new($null, $path)
Assert-True ($service.Current.SecurityAuditInstructions -ceq $original) 'Legacy AGENTS.md takes precedence over the old JSON copy.'
Assert-True ($service.SecurityAuditInstructionsPath -eq (Join-Path $path 'chains/security-audit/AGENTS.md')) 'Audit policy has its own chain path.'
Assert-True ([IO.File]::ReadAllText($service.SecurityAuditInstructionsPath) -ceq $original) 'Migration preserves custom policy text and line endings.'
$service.Current.SecurityAuditInstructions = '# New audit-only policy'
$service.Save($service.Current)
Assert-True ([IO.File]::ReadAllText($legacy) -ceq $original) 'Saving scoped policy leaves the old shared file untouched.'
$stored = [IO.File]::ReadAllText((Join-Path $path 'settings.json')) | ConvertFrom-Json
Assert-True ($stored.SecurityAuditInstructions -eq '# New audit-only policy' -and $stored.PSObject.Properties.Name -notcontains 'AgentInstructions') 'New saves contain only the security-audit policy field.'
[IO.File]::Delete($service.SecurityAuditInstructionsPath)
$reloaded = [LocalSecurityAudit.Services.SettingsService]::new($null, $path)
Assert-True ($reloaded.Current.SecurityAuditInstructions -eq '# New audit-only policy') 'Missing scoped file restores the scoped JSON copy instead of reimporting old rules.'
[IO.File]::WriteAllText($service.SecurityAuditInstructionsPath, '# Edited audit file')
$reloaded = [LocalSecurityAudit.Services.SettingsService]::new($null, $path)
Assert-True ($reloaded.Current.SecurityAuditInstructions -eq '# Edited audit file') 'Scoped AGENTS.md takes precedence on restart.'

$path = New-Profile 'legacy-json' @{AgentInstructions='# JSON-only custom rules'}
$service = [LocalSecurityAudit.Services.SettingsService]::new($null, $path)
Assert-True ($service.Current.SecurityAuditInstructions -eq '# JSON-only custom rules') 'Old JSON-only custom policy migrates without loss.'

$path = Join-Path $root 'file-only'
$null = [IO.Directory]::CreateDirectory($path)
[IO.File]::WriteAllText((Join-Path $path 'AGENTS.md'), '# Existing custom rules without settings')
$service = [LocalSecurityAudit.Services.SettingsService]::new($null, $path)
Assert-True ($service.Current.SecurityAuditInstructions -eq '# Existing custom rules without settings') 'Existing rules survive a missing settings file.'

$path = New-Profile 'new-profile'
$service = [LocalSecurityAudit.Services.SettingsService]::new($null, $path)
Assert-True ($service.Current.SecurityAuditInstructions -eq [LocalSecurityAudit.Services.SettingsService]::DefaultSecurityAuditInstructions) 'New profiles receive the built-in security-audit policy.'
Assert-True (-not [IO.File]::Exists((Join-Path $path 'AGENTS.md'))) 'New profiles do not create a shared AGENTS.md.'
Assert-True ([LocalSecurityAudit.Models.HubTaskCatalog]::Tasks.Count -eq 1) 'Hub lists only implemented tasks.'
Assert-True ($service.GetTaskInstructions('security-audit') -eq $service.Current.SecurityAuditInstructions -and
    $service.GetTaskInstructionsPath('security-audit') -eq $service.SecurityAuditInstructionsPath) 'Security audit resolves its own instructions and path.'
foreach ($method in 'GetTaskInstructions', 'GetTaskInstructionsPath') {
    $rejected = $false
    try { $null = $service.$method('file-organization') }
    catch { $rejected = $_.Exception.GetBaseException() -is [ArgumentException] }
    Assert-True $rejected "$method rejects an unknown task rather than applying audit rules."
}
"Policy regression artifacts: $root"
