# 本地安全审计系统 (LocalSecurityAudit)

版本: 0.3.8

## 项目概述

这是一个基于 WinUI 3 的 Windows 本地审计展示工具。默认辅助模式由外部 Claude/Codex 分析并写入结果，程序只读展示；拓展模式普通权限采集日志并调用 AI Hub；全量模式额外提权读取 Security。

## 0.3.8 发布入口

发布包为 `bin\publish\LocalSecurityAudit-0.3.8-x64.zip`，完整解压后普通打开其中的 `LocalSecurityAudit.exe`，不要只复制 exe。x64 发布包含 .NET 与 Windows App SDK 运行依赖，无需管理员安装。旧配置没有模式字段时默认进入辅助模式，已有配置和历史保留。

Responses 模式遵循标准 OpenAI `/v1/responses` 协议：策略使用 `instructions`，日志使用 `input`，开启 SSE 并设置 `store: false`。只有 `response.completed` 中已完成的 `output` 才是最终结果；文本片段结束、`[DONE]` 或连接关闭不代表请求完成。Base URL 可为站点根、`/v1` 或带前缀的 `/v1/`。已有 Chat Completions 模式保持独立，不自动切换模型、推理强度或线路。

诊断记录 HTTP 状态、安全格式的 `x-request-id`、白名单错误码及本地取消/超时状态，不记录上游错误全文、原始事件或凭据。协议修正不绕过 TLS 验证，也不能保证修复远端网关或代理的连接故障。

“设置 → 模式”选择辅助、拓展或全量，点击“保存并退出”，再从文件资源管理器普通打开程序。模式不会在运行中切换数据库；关闭到托盘不算完全退出。仅全量模式请求同一 Windows 账号的 UAC，取消则进入辅助模式，不改写启动偏好。辅助和拓展都不接受继承的管理员令牌。

同一 Windows 会话、同一账号只保留一个程序实例，Debug / Release、不同目录及不同模式共用单实例锁。重复启动不会再打开独立窗口；正常权限下会唤回已有窗口。首次更新到这一版本前请完全退出旧版（包括托盘实例），不要同时保留旧版和新版。

| 模式 | 程序行为 | 数据库（相对数据目录） |
| --- | --- | --- |
| 辅助（默认） | 普通权限、只读结果；外部工具默认跳过 Security | `assistant\audit_data.db` |
| 拓展 | 普通权限，跳过 Security，采集其余四类日志并调用 AI Hub | `audit_data.db`（沿用旧库） |
| 全量 | 同账号 UAC 授权，采集五类日志（含 Security）并调用 AI Hub | 与拓展共用原库 |

数据目录默认为 `%LOCALAPPDATA%\LocalSecurityAudit`，两库表结构一致，互不迁移或覆盖。

程序目录只放可执行文件、运行依赖、资源和随附的只读协议/工具，不存放用户配置、分析日志或结果。`settings.json`、可编辑的 AI Hub 策略 `AGENTS.md`、可选的 `API.txt` 和 `diagnostic.log` 都在上述用户数据目录中；两个结果库维持表中路径。外部审计的证据及结果 JSON 放在程序目录和源码之外的独立工作目录，不随构建分发。程序目录内的 `*.runtimeconfig.json` / `*.deps.json` 是必要运行依赖，不是用户配置。

### 让 Claude / Codex 生成辅助结果

在“设置 → 模式”点击“复制审计提示词”，粘贴到你自己的 Claude/Codex 会话。程序不会启动智能体。
提示词会要求显式读取随程序分发的 [AGENTS.md](AGENTS.md)，按规范调用采集器、分析脱敏证据、校验并发布结果；无需为辅助模式配置 API Key。

full / bypass 不等于 Windows 管理员权限。辅助采集默认不尝试 Security，标为“限定范围”（limited）；其余四通道完整且有已分析证据时显示明确排除 Security 的“日常范围分数”，不是整体安全评估。无权读取或截断标为“覆盖不完整”（partial），不显示分数，但保留活动统计及问题。用户另行明确要求并已有权限时，外部采集可加 `-IncludeSecurity`，该开关不会申请提权。v2 协议支持五通道并兼容旧 v1 结果。辅助窗口约每 2 秒检测外部提交（含 WAL），保留日期、范围、来源和严重程度筛选。

外部工具需要 PowerShell 7 和 Python 3.11+，只使用标准库；展示程序自身不依赖 Python。AGENTS.md 和两个工具会复制到 Debug / Release / publish 输出目录。辅助协议与数据目录里供 AI Hub 使用的旧版策略 AGENTS.md 分开，不覆盖自定义策略。

## 主要功能

- **自动审计（拓展 / 全量模式）**: 每 4 小时自动执行一次审计
- **日志分析**: 默认读取 Application、Setup、System 和 ForwardedEvents；全量额外读取 Security 及其中的防火墙审计。保留安全事件 ID 白名单与其他通道的 Critical / Error / Warning 筛选；每通道最多 2,000 条，超限标记截断。“全量”不代表读取所有级别或 Applications and Services Logs。
- **AI 驱动分析**: 支持 gpt-5.6-luna / terra / sol、gpt-6-astra 及网关的 gpt-5.6 别名，统一 256k 上下文；保留各入口的推理强度
- **历史优化（拓展模式）**: 设置中选择明确型号，按 Luna → Terra → Sol → Astra 向上优化并保存双语结果、模型标签和优化时间；未标注记录及网关别名仅允许 Astra 优化，不改变原始日志证据
- **数据可视化**: 
  - 统一健康概览卡整合当前审计分数、详情和全部 / 30 天 / 7 天统计，汇总审计次数、累计问题、活跃天数及全量平均分
  - 日期热力图按审计次数着色，非安全程度；选中高亮，完整日期在选中或悬浮时显示，点击查看当天最近审计，“最近审计”返回自动跟随
  - 总览以及五类 Windows 日志来源标签，联动问题数量和严重程度筛选
  - 问题严重程度分布饼图
  - 1D / 7D / 30D 趋势、区间汇总和可点击的问题历史
- **自动加载**: 展示最新可用审计，跳过损坏记录；扫描完成和历史补译后自动更新
- **数据保留（拓展模式）**: 默认保留最近 30 个本地自然日，旧版 7 天配置首次升级时迁移为 30 天；辅助模式不自动删除外部记录
- **Mica 设计**: 使用 Windows 11 Mica 材质的现代化界面

趋势区间包含今天：1D 按本地小时汇总，7D / 30D 按本地日期汇总。重复发现按每次扫描分别计数，健康均值排除 limited / partial / 未评估记录。活动卡的“全部”统计所有可读历史；热力图最多展示最近 365 天并提示范围限制。范围筛选控制活动统计，健康卡始终明确标注所选的单次审计。

最近 15 天等多日辅助回溯按 AGENTS.md 拆成最长 24 小时的独立窗口，校验后逐批追加。真实发布时间不回填为历史日期，活动格统计审计执行日期；每批的日志区间保留在详情中。

Fast scan 在范围为“自上次扫描以来”时从当前模式的 ScanEnd 继续；拓展进度不能用来跳过全量模式的 Security 读取，读取失败或截断也不推进进度。无相应历史时按扫描间隔回溯。24 小时扫描（元数据仍为 Full Scan）与是否提权的“全量模式”是两个不同选项。

## 技术栈

- **UI 框架**: WinUI 3 (Windows App SDK 1.4)
- **架构模式**: MVVM (使用 CommunityToolkit.Mvvm)
- **数据库**: SQLite (Microsoft.Data.Sqlite)
- **图表库**: LiveCharts2
- **依赖注入**: Microsoft.Extensions.DependencyInjection
- **AI API**: OpenAI 兼容接口 (api.falsemeet.site)

## 项目结构

```
LocalSecurityAudit/
├── Models/                  # 数据模型
│   ├── SecurityEvent.cs     # 日志事件模型
│   ├── AuditIssue.cs        # 审计问题模型
│   └── AuditResult.cs       # 审计结果模型
├── Services/                # 业务逻辑服务
│   ├── EventLogService.cs   # Windows 事件日志读取
│   ├── AiAnalysisService.cs # AI 分析服务
│   ├── DataStorageService.cs # SQLite 数据存储
│   └── AuditSchedulerService.cs # 定时审计调度
├── ViewModels/              # MVVM ViewModels
│   ├── MainViewModel.cs
│   ├── DashboardViewModel.cs # 仪表盘 ViewModel
│   └── TrendsViewModel.cs   # 趋势分析 ViewModel
├── Views/                   # XAML 视图
│   ├── MainWindow.xaml      # 主窗口
│   ├── DashboardPage.xaml   # 今日审计页面
│   └── TrendsPage.xaml      # 趋势分析页面
├── Helpers/                 # 辅助类
│   ├── EventLogParser.cs    # 事件日志解析器
│   └── Converters.cs        # XAML 值转换器
├── App.xaml                 # 应用程序定义
└── LocalSecurityAudit.csproj
```

## 构建和运行

### 先决条件

1. Windows 11 (用于 Mica 效果)
2. Visual Studio 2022 或更高版本
3. .NET 8 SDK
4. 项目引用的 Windows App SDK 1.4 依赖
5. 辅助和拓展无需管理员权限；全量模式需要同账号 UAC 授权

### 构建步骤

1. 克隆或打开项目目录
2. 恢复 NuGet 包：
   ```powershell
   dotnet restore -p:Platform=x64
   ```

3. 构建项目：
   ```powershell
   dotnet build --no-restore -p:Platform=x64 -c Release
   ```

4. 普通运行（遵循保存的模式，首次默认辅助）：
   ```powershell
   .\bin\x64\Release\LocalSecurityAudit-0.3.8\net8.0-windows10.0.19041.0\LocalSecurityAudit.exe
   ```

或者在 Visual Studio 中：
- 普通权限运行 Visual Studio
- 打开 `LocalSecurityAudit.csproj`
- 按 F5 运行

`--assistant` / `--extended` / `--full` 可临时指定本次模式，不改写启动偏好；`RunAsAdmin.bat` 指定 Debug 全量模式，提权由程序请求。

### x64 自包含发布

在 Visual Studio Developer PowerShell 中运行（当前 Win2D 依赖使用 `win10-x64` RID，Windows 11 同样适用）：

```powershell
MSBuild LocalSecurityAudit.csproj /restore /t:Publish /p:Configuration=Release /p:Platform=x64 /p:RuntimeIdentifier=win10-x64 /p:SelfContained=true /p:WindowsPackageType=None /p:PublishSingleFile=false /p:PublishTrimmed=false /p:PublishProfile= /p:PublishDir=bin\publish\LocalSecurityAudit-0.3.8-x64
```

将 Visual Studio 的 `VC\Redist\MSVC\<版本>\x64\Microsoft.VC*.CRT` 中 `msvcp140.dll`、`vcruntime140.dll`、`vcruntime140_1.dll` 随包分发；不要从 System32 复制系统文件。打包前执行 `tools/test-publish.ps1 -PublishDirectory <发布目录>`，ZIP 生成后附加 `-ZipPath <ZIP 路径>` 校验每个文件。只压缩已验证的版本发布目录，不压缩整个 bin 或源码目录；已存在的同名发布包不要直接覆盖。

### 代码回归（不启动程序，不读取真实日志）

```powershell
pwsh -NoProfile -File tools/test-modes.ps1
python tools/test-assistant-workflow.py
pwsh -NoProfile -File tools/test-history.ps1
pwsh -NoProfile -File tools/test-analysis.ps1
pwsh -NoProfile -File tools/test-ai-transport.ps1
pwsh -NoProfile -File tools/test-workflow.ps1
pwsh -NoProfile -File tools/test-workflow.ps1 -SimulateConcurrentEdit
```

PowerShell 测试默认加载 Debug，可用 `-AssemblyPath` 指向 Release 或自包含发布目录里的 LocalSecurityAudit.dll。新模式测试只用合成日志、临时目录和模拟的 Get-WinEvent；网络回归只使用本机 loopback。实际 UAC、窗口显示、真实日志及真实 AI 调用需用户另行实机测试。

### API 配置

拓展和全量模式需要配置 AI Hub，可在“设置 → AI 分析”编辑 Main 和可选 Fallback。初始化/重置默认入口时，仅支持从 `%LOCALAPPDATA%\LocalSecurityAudit\API.txt` 读取，不再搜索程序目录、当前工作目录或父目录；已保存的入口不受影响，不自动搬移旧文件。格式如下（不要提交真实凭据）：

```
https://api.falsemeet.site
<your-api-key>
```

## 功能详解

### 今日审计页面

- **健康评分**: 0-100 分，基于发现的问题数量和严重程度
  - 高危问题：每项 -15 分，该级最多扣 60 分
  - 中危问题：每项 -6 分，该级最多扣 25 分
  - 低危问题：每项 -1.5 分，合计按远离零四舍五入，该级最多扣 15 分
  - 覆盖不完整或完全未分析时不显示分数；三种模式使用相同算法，日常范围明确排除 Security
- **问题列表**: 显示所有检测到的安全问题，包括：
  - 问题描述
  - 严重程度（High/Medium/Low）
  - 问题类别（Login/Privilege/Firewall/System）
  - 根本原因分析
  - 修复建议
- **手动审计**: 点击"立即审计"按钮触发即时审计

### 趋势分析页面

- **时间区间**: 1D / 7D / 30D，均包含今天
- **问题数量趋势图**: 堆叠柱状图按小时或日期显示各严重程度的问题报告数
- **健康评分趋势图**: 折线图显示各时段有效评估的平均健康评分
- **统计指标**: 扫描数、平均健康评分、问题报告总数和首末评分变化
- **问题明细**: 按扫描时间倒序分页，支持严重程度筛选及来源和解决方案详情

### 拓展 / 全量模式审计流程

1. **日志收集**: Full scan 固定覆盖过去 24 小时；Fast scan 按配置的小时范围或上次扫描结束时间增量读取
   - Security（仅全量模式）: 登录、账户与组、权限、策略和审计日志变更事件
   - System / Application / Setup / ForwardedEvents: Critical、Error 和 Warning 级别事件，包含 Kernel-Power 41
   - Firewall（仅全量模式）: 从 Security 读取 5152、5157、4946-4950 等防火墙和 Windows Filtering Platform 审计事件

2. **AI 分析**: 按配置的 Main / Fallback 入口与模型分批分析

3. **结果存储**: 保存到本地 SQLite 数据库

4. **自动清理**: 按设置的保留期清理，默认保留最近 30 个本地自然日

侧栏百分比依据已完成的读取分组、分析批次及流程阶段计算，不代表预计耗时。等待模型生成时显示请求耗时和输出信息；展开或收起侧栏均可查看阶段完成度。

## 数据存储

两个数据库的位置：
```
%LOCALAPPDATA%\LocalSecurityAudit\audit_data.db
%LOCALAPPDATA%\LocalSecurityAudit\assistant\audit_data.db
```

数据库架构：
```sql
CREATE TABLE AuditResults (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    Timestamp DATETIME NOT NULL,
    HealthScore INTEGER NOT NULL,
    FindingsJson TEXT NOT NULL,
    MetadataJson TEXT
);
```

## 权限要求

`app.manifest` 为 `asInvoker`，默认窗口不请求额外权限。仅全量模式主动请求同一账号的管理员授权，以读取 Security 等受保护日志；辅助窗口禁止内部采集、AI 请求和数据库写入。外部 Claude/Codex 的权限由用户单独管理，不能从其 full / bypass 设置推断 Windows 权限。

## 已知限制

1. 需要 Windows 11 才能获得最佳 Mica 效果（Windows 10 可以运行但无 Mica）
2. 首次运行需要下载较大的 NuGet 包
3. 拓展 AI 分析依赖于网络连接和配置入口的可用性；辅助分析依赖用户选择的外部工具
4. 防火墙日志可能需要额外配置才能访问

## 故障排除

### 无法读取事件日志
- 只有全量模式需要确认 UAC；辅助 / 拓展默认跳过 Security，其他日志若不可读则查看通道覆盖状态，不要给普通展示窗口提权
- 检查 Windows 事件查看器服务是否正常运行

### AI 分析失败
- 拓展模式检查“设置 → AI 分析”的入口和密钥；辅助模式检查外部会话和发布器返回的错误
- 验证网络连接到自己配置的入口
- 查看日志中的详细错误信息

### 数据库错误
- 检查 `%LOCALAPPDATA%\LocalSecurityAudit` 目录的写入权限
- 核对当前模式及数据库路径。先备份并检查损坏原因，不直接删除任何审计数据库

## 开发路线图

- [ ] 实时日志监控（EventLogWatcher）
- [ ] 更多可定制的审计规则
- [ ] 导出审计报告（PDF/Excel）
- [ ] 电子邮件/推送通知
- [ ] 多语言支持
- [ ] 暗色/亮色主题切换

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！
