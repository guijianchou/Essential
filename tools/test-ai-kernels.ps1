param(
    [string]$AssemblyPath = "$PSScriptRoot\..\artifacts\bin\x64\Debug\net8.0-windows10.0.19041.0\Essential.dll"
)
$ErrorActionPreference = 'Stop'
$assembly = [System.Reflection.Assembly]::LoadFrom((Resolve-Path -LiteralPath $AssemblyPath).Path)
$flags = [System.Reflection.BindingFlags]'NonPublic,Static'
$type = $assembly.GetType('LocalSecurityAudit.Services.AiAnalysisService', $true)

function Assert-True([bool]$condition, [string]$message) {
    if (-not $condition) { throw $message }
    Write-Output "PASS $message"
}

$extract = $type.GetMethod('ExtractKernelOutput', $flags)
$codexOutput = '{"type":"item.completed","item":{"type":"agent_message","text":"{\"issues\":[]}"}}'
$codexResult = $extract.Invoke($null, [object[]]@([string]'codex', [string](Join-Path $env:TEMP 'missing-last-message.txt'), [string]$codexOutput))
Assert-True ($codexResult -eq '{"issues":[]}') 'Codex JSONL text is extracted as the findings payload.'

$piOutput = '{"type":"message_end","message":{"role":"assistant","stopReason":"stop","content":[{"type":"text","text":"{\"issues\":[]}"}]}}'
$piResult = $extract.Invoke($null, [object[]]@([string]'pi', [string](Join-Path $env:TEMP 'missing-pi.txt'), [string]$piOutput))
Assert-True ($piResult -eq '{"issues":[]}') 'Pi JSONL nested text is extracted as the findings payload.'

$configure = $type.GetMethod('ConfigureKernelProcess', $flags)
$targetType = $assembly.GetType('LocalSecurityAudit.Models.AiTargetSettings', $true)
$target = [Activator]::CreateInstance($targetType)
$target.BaseUrl = 'https://example.invalid'
$target.ApiKey = 'synthetic-key'
$target.Model = 'gpt-5.6-luna'
$target.Mode = 'responses'
$target.Effort = 'medium'
$startInfo = [Diagnostics.ProcessStartInfo]::new()
$root = Join-Path ([IO.Path]::GetTempPath()) "lsa-kernel-test-$([guid]::NewGuid().ToString('N'))"
try {
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $configure.Invoke($null, [object[]]@($startInfo, [string]'codex', $target, [string]'synthetic system prompt', [string](Join-Path $root 'user.txt'), [string](Join-Path $root 'last.txt'), [string](Join-Path $root 'codex-home'), [string](Join-Path $root 'pi-home')))
    Assert-True ($startInfo.ArgumentList -contains '--ephemeral' -and $startInfo.Environment['CODEX_HOME']) 'Codex process uses an ephemeral read-only invocation and isolated CODEX_HOME.'
    Assert-True ([IO.File]::ReadAllText((Join-Path $root 'AGENTS.md')) -eq 'synthetic system prompt') 'Codex reads the request policy through a working-directory AGENTS.md.'
    Assert-True ($startInfo.Environment['LOCAL_SECURITY_AUDIT_API_KEY'] -eq 'synthetic-key') 'Codex API key is passed only through the child environment.'
    $piInfo = [Diagnostics.ProcessStartInfo]::new()
    $configure.Invoke($null, [object[]]@($piInfo, [string]'pi', $target, [string]'synthetic system prompt', [string](Join-Path $root 'user.txt'), [string](Join-Path $root 'last.txt'), [string](Join-Path $root 'codex-home'), [string](Join-Path $root 'pi-home')))
    Assert-True ($piInfo.ArgumentList -contains '--no-tools' -and $piInfo.ArgumentList -contains '--no-session') 'Pi process disables tools and sessions for an audit batch.'
    Assert-True ($piInfo.ArgumentList -contains '--append-system-prompt' -and $piInfo.ArgumentList -contains (Join-Path $root 'AGENTS.md') -and $piInfo.ArgumentList -contains ('@' + (Join-Path $root 'user.txt'))) 'Pi receives policy and user data through explicit files without Windows command-line truncation.'
    Assert-True ($piInfo.Environment['PI_CODING_AGENT_DIR'] -eq (Join-Path $root 'pi-home') -and $piInfo.Environment['OPENAI_API_KEY'] -eq 'synthetic-key') 'Pi uses an isolated configuration directory and explicit API key.'
    $piConfig = Get-Content -LiteralPath (Join-Path $root 'pi-home\models.json') -Raw | ConvertFrom-Json
    Assert-True ($piConfig.providers.localsecurityaudit.apiKey -ceq '$OPENAI_API_KEY' -and $piConfig.providers.localsecurityaudit.authHeader) 'Pi resolves its credential from the environment and enables the bearer header.'
    Assert-True ($piInfo.ArgumentList -contains 'localsecurityaudit' -and $piInfo.ArgumentList -contains 'medium' -and (Get-Content -LiteralPath (Join-Path $root 'pi-home\models.json') -Raw).Contains('"reasoning":true')) 'Pi preserves the selected reasoning effort in its isolated provider configuration.'
}
finally {
    if ([IO.Directory]::Exists($root)) { [IO.Directory]::Delete($root, $true) }
}
