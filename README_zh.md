# Essential（工具箱）

[English](README.md) | [简体中文](README_zh.md)

版本: 0.4.3

## 项目概述

Essential（工具箱）是基于 WinUI 3 的 Windows 本地工具箱。主要链路为 Codex / Pi → 对应任务的 AGENTS.md → 分析总结 → 操作建议。当前提供安全审计：默认拓展模式以普通权限采集日志并调用配置的 AI Hub；全量模式额外提权读取 Security。

## 0.4.3 发布入口

发布包为 `artifacts\publish\Essential-0.4.3-x64.zip`，完整解压后普通打开其中的 `Essential.exe`，不要只复制 exe。x64 发布包含 .NET 与 Windows App SDK 运行依赖，无需管理员安装。旧配置的辅助模式或空模式迁移为拓展模式，HTTP 内核选项迁移为 Codex；已有入口配置和历史保留。

问题总览提供“优先查看／全部问题”切换。优先查看明确显示前五条占总数的比例；全部问题展开分类，切换日志来源或严重度也会自动展开匹配结果。可以按事件 ID、提供程序或当前语言的标题搜索，例如 `WindowsUpdateClient 20`、`Volsnap` 或 `36`；纯数字精确匹配事件 ID。

“设置 → AI 分析”只提供 Codex / Pi 内核，支持安装、下载更新和检查官方最新版本。“下载或更新”先读取真实 CLI 版本并比较官方版本，同版或本地版本更高时不下载；资源不完整时重新安装。下载包通过 SHA-256 和 CLI 版本校验后才替换旧安装，Pi 同时安装主题等运行资源。版本进程退出后的短暂文件占用会有限重试，失败保留旧安装。Codex 使用 Responses API，Pi 支持 Responses 与 Chat Completions。程序为每次调用生成独立的临时配置，保留所选模型与推理强度，调用结束后清理临时目录。

连接测试使用设置页当前选择的内核与入口，发送最小请求并验证结果。左侧显示测试或扫描的进度、成功/失败和 token；内核返回用量时显示输入/输出实数，尚未返回时标注输入估算。Codex 的重连与错误状态会即时显示，重试由 Codex 自身管理；只有收到完整完成事件才接受结果。设置页反馈固定在顶部，不随入口编辑区滚出视野。

“设置 → Hub”按左侧任务逐项管理 AGENTS.md；当前为安全审计规则卡，策略编辑器默认折叠。任务入口与规则卡共享同一任务标识，由 Codex / Pi 加载对应规则，完成分析总结并给出操作建议。策略保存到数据目录的 `chains\security-audit\AGENTS.md`，旧通用 AGENTS.md 或旧配置中的自定义内容会在首次升级时复制迁入，原文件保留。重置 AI 连接设置不再重置审计规则。每个审计请求将该策略与输出契约写入隔离工作目录的 AGENTS.md，由 Codex 标准链路加载；Pi 使用同一份有效审计规则。

侧栏使用顶部原生折叠按钮，安全审计入口固定靠上，设置位于底部。收起后点击 Token 图标可直接查看总计与周期用量。Token 总计在空闲时也可查看；“设置 → 外观 → Token 统计显示”选择本地自然日、周一开始的自然周或自然月，在总计下显示所选周期用量。只统计内核实际返回的输入、输出用量，按请求去重并写入原数据库的新 TokenUsage 表，重启和审计历史清理后保留。扫描、连接测试、历史补译及失败但已返回用量的请求均计入，输入估算不计入；升级前没有保存的用量无法补算。

Codex 对 AI Hub 使用标准 Responses 协议。程序从已安装内核导出内置模型目录，通过其 model_catalog_json 配置关闭内部 Responses-Lite，保留模型原有信息、推理强度、AGENTS.md 读取及原生流重试。这避免公开转发接口不支持内部 Lite 请求头和 reasoning.context 组合时的 unsupported_value 错误。

“设置 → 模式”选择拓展或全量，点击“保存并退出”，再普通打开程序。只有全量请求同一 Windows 账号的 UAC；取消后进入拓展模式，不改写启动偏好。拓展模式使用普通权限。配置的密钥只传给本次子进程，诊断对该密钥脱敏，并记录执行状态、模型及错误摘要。

同一 Windows 会话、同一账号只保留一个程序实例，Debug / Release、不同目录及不同模式共用单实例锁。重复启动不会再打开独立窗口；正常权限下会唤回已有窗口。首次更新到这一版本前请完全退出旧版（包括托盘实例），不要同时保留旧版和新版。

| 模式 | 程序行为 | 数据库（相对数据目录） |
| --- | --- | --- |
| 拓展（默认） | 普通权限，跳过 Security，采集其余四类日志并调用 AI Hub | `audit_data.db`（沿用旧库） |
| 全量 | 同账号 UAC 授权，采集五类日志（含 Security）并调用 AI Hub | 与拓展共用原库 |

应用英文名为 Essential，中文名为工具箱；程序文件改为 Essential.exe，继续沿用已有数据目录、配置、内核、历史与单实例身份。

数据目录默认为 `%LOCALAPPDATA%\LocalSecurityAudit`。新结果写入 `audit_data.db`；旧 `assistant\audit_data.db` 仅作为经过格式校验的只读历史来源，不迁移或覆盖原记录。

程序目录只放可执行文件、运行依赖和资源。`settings.json`、安全审计策略 `chains\security-audit\AGENTS.md`、可选的 `API.txt` 和 `diagnostic.log` 位于用户数据目录。构建文件集中到 `artifacts`：`bin` 放可运行文件，`obj` 放编译缓存，`publish` 放版本发布包；Debug / Release 各用一份固定目录。Debug 可以附带两个内核 ZIP，Release / publish 不包含内核包和已退役的辅助采集/发布工具。源码里的旧协议和工具保留用于历史格式回归，不是当前版本的运行入口。

## 主要功能

- **自动审计（拓展 / 全量模式）**: 每 4 小时自动执行一次审计
- **日志分析**: 默认读取 Application、Setup、System 和 ForwardedEvents；全量额外读取 Security 及其中的防火墙审计。保留安全事件 ID 白名单与其他通道的 Critical / Error / Warning 筛选；每通道最多 2,000 条，超限标记截断。“全量”不代表读取所有级别或 Applications and Services Logs。
- **AI 驱动分析**: 支持 gpt-5.6-luna / terra / sol、gpt-6-astra 及网关的 gpt-5.6 别名，统一 256k 上下文；保留各入口的推理强度
- **模型覆盖**: 等级固定为 Luna < Terra < Sol < Astra。更高等级只替代已完整分析的时间与日志范围；同级或更低等级继续增量。未知型号、覆盖缺失和未分析批次不清除已知问题；备用路由与零问题响应保留实际完成的模型。
- **安全审计页面**:
  - Health 区显示所选审计的评分、High / Medium / Low 数量与首要处理建议；保留全部 / 30 天 / 7 天的审计次数、累计问题、活跃天数与对应范围均分
  - 日期选择与历史统计周期分区显示；日常和全量均分独立统计，未评估或覆盖不完整的结果不计入均分
  - 日期选择器查看当天最近审计，“最近审计”返回自动跟随；问题来源、严重程度筛选及操作建议集中展示
- **自动加载**: 展示最新可用审计，跳过损坏记录；扫描完成和历史补译后自动更新
- **数据保留（拓展模式）**: 默认保留最近 30 个本地自然日，旧版 7 天配置首次升级时迁移为 30 天；只读旧库不参与清理
- **Mica 设计**: 使用 Windows 11 Mica 材质的现代化界面

活动统计包含今天；“全部”统计所有可读历史，重复问题按每次扫描分别计数。均分的评估范围与所选审计一致：日常范围排除 Security，全量只包含完整评估；无有效评估时不显示分数。本次审计的风险数量与首要建议独立于下方历史问题的来源及严重度筛选。

Fast Scan 和 Full Scan 都从有效 ScanEnd 增量继续；首次 Full Scan 或升级模型时使用所选 1d / 2d / 1w 范围。模型等级不会因较低模型的后续扫描而下降；已有进度早于回溯边界时保留未扫描缺口。包含 Security 的全量进度独立计算，读取失败或截断不推进进度。扫描时间范围与是否使用管理员权限是两个独立选项。

增量窗口没有事件时不会调用 AI，侧栏显示“未进行 AI 分析”及跳过原因。切换内核并保存设置后，可用扫描按钮旁的“⋯ → 重新分析所选范围”，通过当前内核重新分析所选 1d / 2d / 1w 范围，同时补齐更早的未扫描缺口。这次操作会清除分析缓存；不同内核的缓存也独立区分。诊断日志记录本次请求的内核、扫描原因与无事件跳过原因。

修改记录：[docs/CHANGES.md](docs/CHANGES.md)；事件参考：[docs/EVENT_ID_REFERENCE.md](docs/EVENT_ID_REFERENCE.md)。

## 技术栈

- **UI 框架**: WinUI 3 (Windows App SDK 1.4)
- **架构模式**: MVVM (使用 CommunityToolkit.Mvvm)
- **数据库**: SQLite (Microsoft.Data.Sqlite)
- **图表库**: LiveCharts2
- **依赖注入**: Microsoft.Extensions.DependencyInjection
- **AI API**: OpenAI 兼容接口 (api.falsemeet.site)

## 项目结构

```
Essential/
├── Models/                  # 数据模型
│   ├── SecurityEvent.cs     # 日志事件模型
│   ├── AuditIssue.cs        # 审计问题模型
│   ├── AuditResult.cs       # 审计结果模型
│   ├── HubTaskCatalog.cs    # Hub 任务定义与目录
│   ├── AiKernelCatalog.cs   # Codex 与 Pi 内核目录
│   └── AppSettings.cs       # 应用配置与审计策略字段
├── Services/                # 业务逻辑服务
│   ├── EventLogService.cs   # Windows 事件日志读取
│   ├── AiAnalysisService.cs # AI 分析服务（Codex/Pi 进程调用与结果解析）
│   ├── KernelManagerService.cs # Codex / Pi 内核管理、安装与版本更新
│   ├── DataStorageService.cs # SQLite 数据存储与 TokenUsage 表
│   ├── AuditSchedulerService.cs # 定时审计调度与后台状态
│   └── SettingsService.cs   # 配置与 Hub 策略持久化
├── ViewModels/              # MVVM ViewModels
│   ├── MainViewModel.cs     # 主窗口导航、单实例与 Token 显示
│   ├── DashboardViewModel.cs # 统一安全审计页面 ViewModel
│   └── SettingsViewModel.cs # Hub 策略、AI 分析与应用设置 ViewModel
├── Views/                   # XAML 视图
│   ├── MainWindow.xaml      # 主窗口（顶部折叠侧栏与状态底栏）
│   ├── DashboardPage.xaml   # 统一安全审计页面（评分、分类展开与多维筛选）
│   ├── SettingsPage.xaml    # Hub、内核与应用设置
│   ├── FindingDetailsDialog.xaml # 问题详情与事件证据对话框
│   └── TrayIcon.cs          # 系统托盘图标与右键菜单
├── Helpers/                 # 辅助类
│   ├── EventLogParser.cs    # 事件日志解析器
│   └── Converters.cs        # XAML 值转换器
├── docs/                    # 修改记录 (CHANGES.md) 与事件 ID 参考 (EVENT_ID_REFERENCE.md)
├── tools/                   # 开发、测试与回归脚本
├── artifacts/               # 生成文件（不提交 Git）
│   ├── bin/x64/Debug/       # 调试程序
│   ├── bin/x64/Release/     # 发布构建
│   ├── obj/                # NuGet 与编译缓存
│   └── publish/            # 当前版本目录与 ZIP；archive 存历史包
├── Directory.Build.props    # 统一构建输出与默认平台
├── App.xaml                 # 应用程序定义
└── LocalSecurityAudit.csproj # 项目工程文件 (输出 Essential.exe)
```

## 构建和运行

### 先决条件

1. Windows 11 (用于 Mica 效果)
2. Visual Studio 2022 或更高版本
3. .NET 8 SDK
4. 项目引用的 Windows App SDK 1.4 依赖
5. 拓展无需管理员权限；全量模式需要同账号 UAC 授权

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

4. 普通运行（遵循保存的模式，首次默认拓展）：
   ```powershell
   .\artifacts\bin\x64\Release\net8.0-windows10.0.19041.0\Essential.exe
   ```

或者在 Visual Studio 中：
- 普通权限运行 Visual Studio
- 打开 `LocalSecurityAudit.csproj`
- 按 F5 运行

`--extended` / `--full` 可临时指定本次模式，不改写启动偏好；全量模式的提权由程序请求。

### x64 自包含发布

在 Visual Studio Developer PowerShell 中运行（当前 Win2D 依赖使用 `win10-x64` RID，Windows 11 同样适用）：

```powershell
MSBuild LocalSecurityAudit.csproj /restore /t:Publish /p:Configuration=Release /p:Platform=x64 /p:RuntimeIdentifier=win10-x64 /p:SelfContained=true /p:WindowsPackageType=None /p:PublishSingleFile=false /p:PublishTrimmed=false /p:PublishProfile= /p:PublishDir=artifacts\publish\Essential-0.4.3-x64
```

将 Visual Studio 的 `VC\Redist\MSVC\<版本>\x64\Microsoft.VC*.CRT` 中 `msvcp140.dll`、`vcruntime140.dll`、`vcruntime140_1.dll` 随包分发；不要从 System32 复制系统文件。打包前执行 `tools/test-publish.ps1 -PublishDirectory <发布目录>`，ZIP 生成后附加 `-ZipPath <ZIP 路径>` 校验每个文件。只压缩已验证的版本发布目录，不压缩整个 artifacts 或源码目录；已存在的同名发布包不要直接覆盖。

### 合成回归（不读取真实日志或调用远程 AI）

```powershell
pwsh -NoProfile -File tools/test-modes.ps1
python tools/test-assistant-workflow.py
pwsh -NoProfile -File tools/test-history.ps1
pwsh -NoProfile -File tools/test-analysis.ps1
pwsh -NoProfile -File tools/test-ai-transport.ps1
pwsh -NoProfile -File tools/test-ai-kernels.ps1
pwsh -NoProfile -File tools/test-audit-policy.ps1
pwsh -NoProfile -File tools/test-bundled-kernels.ps1
pwsh -NoProfile -File tools/test-kernel-updates.ps1
pwsh -NoProfile -File tools/test-token-usage.ps1
pwsh -NoProfile -File tools/test-single-instance.ps1
pwsh -NoProfile -File tools/test-workflow.ps1
pwsh -NoProfile -File tools/test-workflow.ps1 -SimulateConcurrentEdit
pwsh -NoProfile -File tools/test-workflow-ui.ps1
```

程序集回归默认加载 Debug，可用 `-AssemblyPath` 指向 Release 或自包含发布目录里的 Essential.dll。模式测试只用合成日志、临时目录和模拟的 Get-WinEvent；进程回归使用生成的模拟内核；bundled-kernels 回归校验本地 ZIP 后用真实内核调用本机 loopback 合成接口。workflow-ui 单独编译测试入口，在真实 WinUI 窗口中注入合成进度和临时数据库，验证侧栏及设置页面，输出布局截图；不启动正常入口或扫描调度器。UAC、真实日志及远程 AI 仍需另行实机验证。

### API 配置

拓展和全量模式需要配置 AI Hub，可在“设置 → AI 分析”编辑 Main 和可选 Fallback。初始化/重置默认入口时，仅支持从 `%LOCALAPPDATA%\LocalSecurityAudit\API.txt` 读取，不再搜索程序目录、当前工作目录或父目录；已保存的入口不受影响，不自动搬移旧文件。格式如下（不要提交真实凭据）：

```
https://api.falsemeet.site
<your-api-key>
```

## 功能详解

### 统一安全审计页面

- **健康评分**: 0-100 分，基于发现的问题数量和严重程度
  - 高危问题：每项 -15 分，该级最多扣 60 分
  - 中危问题：每项 -6 分，该级最多扣 25 分
  - 低危问题：每项 -1.5 分，合计按远离零四舍五入，该级最多扣 15 分
  - 覆盖不完整或完全未分析时不显示分数；两种模式使用相同算法，日常范围明确排除 Security
- **问题列表**: 显示所有检测到的安全问题，包括：
  - 问题描述
  - 严重程度（High/Medium/Low）
  - 问题类别（Login/Privilege/Firewall/System）
  - 根本原因分析
  - 修复建议
- **手动审计**: 点击“快速扫描”或“全量扫描”触发即时审计

### 拓展 / 全量模式审计流程

1. **日志收集**: 两种扫描按钮按共享进度增量读取，首次或模型升级使用所选回溯范围
   - Security（仅全量模式）: 登录、账户与组、权限、策略和审计日志变更事件
   - System / Application / Setup / ForwardedEvents: Critical、Error 和 Warning 级别事件，包含 Kernel-Power 41
   - Firewall（仅全量模式）: 从 Security 读取 5152、5157、4946-4950 等防火墙和 Windows Filtering Platform 审计事件

2. **AI 分析**: Codex / Pi 加载 Hub 中的安全审计 AGENTS.md，按 Main / Fallback 入口与模型分批分析，输出总结及操作建议

3. **结果存储**: 保存到本地 SQLite 数据库

4. **自动清理**: 按设置的保留期清理，默认保留最近 30 个本地自然日

侧栏百分比依据已完成的读取分组、分析批次及流程阶段计算，不代表预计耗时。等待模型生成时显示请求耗时和输出信息；展开或收起侧栏均可查看阶段完成度。

## 数据存储

当前数据库及只读旧库的位置：
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
CREATE INDEX idx_timestamp ON AuditResults(Timestamp DESC);

CREATE TABLE TokenUsage (
    RequestId TEXT PRIMARY KEY NOT NULL,
    Timestamp DATETIME NOT NULL,
    InputTokens INTEGER NOT NULL,
    OutputTokens INTEGER NOT NULL
);
CREATE INDEX idx_token_usage_timestamp ON TokenUsage(Timestamp);

CREATE TABLE ScanCheckpoints (
    Scope TEXT NOT NULL,
    ModelRank INTEGER NOT NULL,
    ScanEnd DATETIME NOT NULL,
    PRIMARY KEY (Scope, ModelRank)
);
```

## 权限要求

`app.manifest` 为 `asInvoker`，默认窗口不请求额外权限。仅全量模式主动请求同一账号的管理员授权，以读取 Security 等受保护日志。内核权限与 Windows 管理员权限相互独立。

## 已知限制

1. 需要 Windows 11 才能获得最佳 Mica 效果（Windows 10 可以运行但无 Mica）
2. 首次运行需要下载较大的 NuGet 包
3. 拓展 AI 分析依赖于网络连接和配置入口的可用性；缺少内核时需先在设置中下载
4. 防火墙日志可能需要额外配置才能访问

## 故障排除

### 无法读取事件日志
- 只有全量模式需要确认 UAC；拓展默认跳过 Security，其他日志若不可读则查看通道覆盖状态，不要给普通展示窗口提权
- 检查 Windows 事件查看器服务是否正常运行

### AI 分析失败
- 检查“设置 → AI 分析”选择的内核、入口、API 模式和密钥，并运行连接测试
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
- [x] 暗色/亮色主题与 logo 跟随系统变化

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request！
