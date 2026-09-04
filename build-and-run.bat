@echo off
echo ========================================
echo 本地安全审计系统 - 构建脚本
echo 版本: 0.1.0
echo ========================================
echo.

REM 检查是否以管理员身份运行
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [错误] 此脚本需要管理员权限运行
    echo 请右键点击脚本，选择"以管理员身份运行"
    pause
    exit /b 1
)

echo [1/4] 恢复 NuGet 包...
dotnet restore
if %errorLevel% neq 0 (
    echo [错误] NuGet 包恢复失败
    pause
    exit /b 1
)

echo.
echo [2/4] 构建项目...
dotnet build --configuration Release
if %errorLevel% neq 0 (
    echo [错误] 项目构建失败
    pause
    exit /b 1
)

echo.
echo [3/4] 检查 API 配置...
if not exist "..\API.txt" (
    echo [警告] 未找到 API.txt 文件
    echo 请在项目上级目录创建 API.txt 文件，格式如下：
    echo.
    echo https://api.falsemeet.site
    echo your-api-key-here
    echo.
    echo 按任意键继续（没有 API 密钥将无法进行 AI 分析）...
    pause
)

echo.
echo [4/4] 启动应用程序...
dotnet run --configuration Release

pause
