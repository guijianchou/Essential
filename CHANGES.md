# 项目修改记录

## 0.3.7 / 2026-09-08

- 重排左侧工作流：扫描状态和进度在概览、趋势之后居中显示，长详情独立滚动，不再遮挡趋势；底部收起操作保留为纯图标。
- 批次进度改用 `steps / 步`，并保持中英文随系统语言切换。
- 按严重程度调整 AI 分析深度：高风险补充证据链、溯源和处置验证，中风险给出模式解释与核对路径，低风险保持简洁。

## 0.3.6 / 2026-09-08

- Responses 请求采用独立 instructions/input、标准 reasoning/max_output_tokens/stream 字段及 store:false；兼容根地址、/v1 和带前缀的 Base URL，避免重复 /v1 或丢失路径。
- SSE 必须收到 response.completed 后才能成功；不再因 output_text.done、完整 JSON 片段或提前 EOF 关闭并接受结果。按最终 response.output 读取全部 assistant/output_text，忽略 reasoning，不把拒绝、不完整或取消当作无问题。
- 记录安全格式的 x-request-id、白名单错误码和本地取消/总超时状态；不输出上游错误全文或原始日志。保留 TLS 校验、既有超时和有界重试策略，不擅自改模型、推理强度或配置。
- 使用标准 Responses 对象和合成 SSE 增加协议回归，覆盖延迟完成、文本结束后失败、断流、分片 UTF-8、拒绝、错误脱敏及 Base URL；0.3.6 x64 自包含包独立发布，保留 0.3.5。

## 0.3.5 / 2026-09-08

- 用户配置、可编辑分析策略、诊断日志和结果库继续保存在 LocalAppData 数据目录，不与程序文件混放；外部证据和分析 JSON 使用程序/源码之外的独立工作目录。
- 可选 API.txt 仅从 settings.json 所在的用户数据目录读取，移除程序目录、工作目录和父目录的自动搜寻；保留已保存配置，不自动移动或清理历史文件。
- 增加使用合成配置的路径隔离回归，确认更换工作目录不会改变默认入口，也不会把配置或结果写入程序目录。
- 首个 x64 自包含 ZIP 发布放入 bin/publish，仅打包程序、运行依赖、资源及随附的协议和工具，不包含用户配置、日志、证据或数据库。
- 补齐发布中的图标资源和旧 Win2D 包的 Windows x64 原生依赖；命令行回归兼容自包含发布目录的 SQLite 布局。

## 0.3.4 beta1 日常范围与活动卡更新 / 2026-09-07

- 健康分数、活动统计和审计详情统一为紧凑概览卡，日期格缩小并均衡排列；全部 / 30 天 / 7 天切换保留所选日期。修正日期切换期间旧结果与新标题混用，刷新保留焦点及筛选，“最近审计”恢复跟随最新结果。
- 辅助外部采集默认跳过 Security；拓展改为普通权限；新增同账号 UAC 的全量模式，覆盖五个 Windows 日志通道。扫描时长独立于模式选择，保留现有事件/级别筛选。
- 拓展与全量共用原历史，但增量进度按模式隔离；逐通道保存成功、失败、截断或主动跳过，不因单个通道失败丢弃其余结果。
- AGENTS.md 升至 v2，新增 ForwardedEvents、skipped/not_requested 和 limited，保留 v1 读写兼容；补充 15 天等多日回溯的有界逐批流程。仅明确跳过 Security 且其余四通道完整、有分析证据时显示日常范围分数，不混入全量均分；真实失败或截断仍不显示分数。
- 单实例锁按当前 Windows 会话和账号共享，不再按模式或构建路径分开；重复启动只唤回已有窗口，不读取配置或触发额外 UAC。增加跨目录、并发启动、释放交接及异常退出恢复回归。
- 修正 WinUI 位移动画在启用 Translation 前停止属性动画的异常，避免刷新停在加载状态、日期切换不更新。
- 增加普通/全量权限分支、默认不查询 Security、覆盖状态、五通道证据、分模式进度及活动范围的合成回归；真实多日审计仅在用户明确授权后按协议单独执行，不混入测试数据。

## 0.3.4 beta1 / 2026-09-07

- 新增辅助 / 拓展双模式，“设置 → 模式”切换并提供保存退出入口；默认辅助，旧配置不含模式字段时同样默认辅助，保留 AI Hub 配置。
- 可执行文件改为 asInvoker；辅助模式不申请提权且拒绝继承管理员令牌。拓展模式由程序请求同一用户的 UAC 授权，取消后以辅助模式打开，不改写启动偏好或混用用户数据。
- 辅助库为 `%LOCALAPPDATA%\LocalSecurityAudit\assistant\audit_data.db`，拓展继续使用原 `audit_data.db`；同表结构，进程运行期间固定模式及数据库，不迁移或覆盖旧记录。
- 辅助窗口只读显示，服务层阻止采集、AI 连接测试、补译、优化及数据库修改；无自动扫描或保留期清理。隐藏扫描按钮，显示模式及工作流提示，提供外部结果刷新。
- 新增随程序分发的 AGENTS.md v1，规范 Claude / Codex 的采集范围、权限边界、证据引用、双语分析、统一字段和发布流程；程序不会启动智能体。
- 增加 PowerShell 外部采集器与 Python 标准库发布器：通道缺失 / 截断如实记录，常见凭据脱敏，校验结果与证据后补齐来源及统计，使用参数化事务、WAL 和 RunId 幂等保护。
- 辅助窗口通过 SQLite data_version 检测外部提交并刷新首页及趋势，保留已选日期和筛选；不完整覆盖保留 findings，但不显示健康分数、不计入趋势均值。
- 新增合成日志、模式拦截、独立库、Python → C# 读取、WAL 刷新、并发发布及回滚回归；真实 UAC / 窗口 / 日志 / AI 测试留给用户实机验证。

## 0.3.4 / 2026-09-07

- 七日日期选择移至 Health score 卡片右上角，仅保留日期数字，选中使用强调色；完整日期随选中显示，悬浮可查看日期与扫描次数。
- 日期控件独立于结果区域的加载过渡，支持连续切换；重复点击当前日期不再触发额外加载。
- 来源筛选收进问题卡片，统一筛选按钮形状；问题预览压缩为标题、建议和来源，保留模型标签、重复次数与时间，增加打开详情的箭头及原生悬浮反馈。
- 分类明细默认收起并保留用户展开状态；空问题时隐藏优先列表，修正历史空日期和来源／严重程度筛选的提示，评分扣分说明改为悬浮提示。

## 0.3.3 / 2026-09-07

- AI 分析支持 GPT-5.6 Luna / Terra / Sol、GPT-6 Astra 及 gpt-5.6 网关别名；统一 256k 上下文，保留现有 effort。
- 设置新增“优化”标签，按 Luna → Terra → Sol → Astra 单向优化历史双语分析；未知型号受保护，未标注与别名记录仅允许 Astra 优化。备用入口也必须请求选定型号。
- 每条分析保存并显示模型标签、原模型与优化时间；优化逐批保存、校验双语完整性和键对应关系，保留原始证据及未知字段，拒绝并发覆盖并更新健康评分。
- Fast scan 重启后恢复最近成功审计的 ScanEnd，避免回到初始四小时窗口；Full scan 保持 24 小时。
- 首页 Health Score 上方增加最近七天日期按钮，联动当天最近一份可读审计、评分、来源分类和问题详情，空日期显示空态。
- 1D / 7D / 30D 切换只发布一次结果，复用图表序列、固定分类图高度，加入短淡入与位移动画，并遵循系统动画设置。

## 0.3.2 / 2026-09-07

- Settings 的 AI analysis 将 Endpoints 移到 Audit policy 上方。
- AI 流式和普通 JSON 响应统一检查失败、取消及不完整状态；远端取消或输出不完整时停止扫描，不再重复请求。输出 token 用尽时给出明确提示。
- 某个并行批次最终失败后取消其他请求及排队批次，保留原始失败原因，避免远端失败后仍长时间显示处理中。
- 临时网络故障最多尝试两次；请求超时不在同一入口重复等待，仍支持可用的 Fallback。连接等待显示耗时，重试显示等待时间和次数。
- 增加本地 HTTP 模拟回归，覆盖流式取消、失败切换、重试上限、并行停止与慢响应进度；服务端原始错误内容不再写入界面或诊断日志。

## 0.3.1 / 2026-09-07

- 修复 System / Application 查询漏掉 Critical 事件的问题，补齐 Setup 采集和 Security 审计事件；防火墙审计改从正确的 Security 通道读取。Full scan 仍固定为 24 小时。
- 区分 System BugCheck 1001 与 Application 1001；问题合并保留日志和来源边界，AI 提示明确分析 Kernel-Power 41 等异常重启事件，不把事件本身当作电源故障证据。
- 首页增加总览、Application、Security、Setup、System 来源标签，联动问题数量、严重程度筛选和详情。
- 侧栏显示阶段完成度百分比、当前阶段百分比及批次数；读取分组更新不会重置流程，失败不会显示为 100%。

## 0.3.0 / 2026-09-07

- 移除 Dashboard 顶部重复扫描指示和手动刷新；最新记录损坏时回退到最近可用记录，读取失败时保留已展示结果。
- 趋势页提供 1D / 7D / 30D 切换，按本地自然日统一查询和清理边界；汇总全部扫描的问题报告和有效评估均值。
- 增加历史问题分页、严重程度筛选及来源和解决方案详情；扫描完成、历史补译及语言切换后自动更新，旧请求不会覆盖新选择。
- 默认保留 30 天，旧版 7 天配置一次性迁移；保留手动自定义的 3 天和 14 天选项。

## 0.2.1 / 2026-09-07

- 扫描开始前隐藏侧栏流程和历史保存提示，移除左下角语言说明；扫描结束后保留本次结果状态。
- 折叠入口改用三横线图标，六个阶段使用一致的高度；批次数字与进度条同行显示。
- 默认字体调整为 Segoe UI Variable Small、9pt（12 DIP）；趋势图补齐中文字体回退，覆盖日期、分类和浮动提示。

## 0.2.0 / 2026-09-07

- 扫描进度和保存时间移入可折叠侧栏，显示路由、批次、双语分析和历史补译的实际状态。
- 侧栏节点固定高度，流式详情附批次编号并限频刷新；状态淡入和真实批次进度平滑过渡，遵循系统动画设置。
- 设置支持中英切换；AI 同次生成并保存两种语言，旧结果在下一次扫描后后台补译，已完成的批次可断点保存。
- 问题详情区分分析与建议、原始日志证据；补全来源、记录号、账号、IP 和时间，避免同 ID 事件误匹配。
- 保留独立日志证据，限制重复事件采样，显示收集、实际分析和过滤数量；未分析的扫描不计为健康满分。
- 修复管理员启动时过早访问 WinUI 资源导致的主窗口崩溃，保留 requireAdministrator。

## 修改日期: 2026-09-03

### 修改 1: Logo 集成
- **状态**: ✅ 完成
- **描述**: 将主目录的 logo.png 复制到 Assets 文件夹
- **文件位置**: `Assets\logo.png`
- **用途**: 可在应用程序中引用作为项目图标

### 修改 2: 项目结构重组
- **状态**: ✅ 完成
- **描述**: 将 LocalSecurityAudit 子文件夹的所有文件移动到主目录
- **主目录**: `C:\Users\Zen\Repos\Codings\Locals\`
- **项目名称**: `LocalSecurityAudit` (保持不变)
- **移动的文件夹**:
  - Assets/
  - Helpers/
  - Models/
  - Services/
  - ViewModels/
  - Views/
  - 所有 .cs、.xaml、.csproj、.md 文件

### 修改 3: 扫描功能增强
- **状态**: ✅ 完成
- **描述**: 实现增量扫描和全量扫描功能

#### 功能说明

**Fast Scan (快速扫描)**
- 增量扫描模式
- 仅扫描自上次扫描时间以来的新事件日志
- 首次运行时扫描过去 4 小时
- 适合日常快速检查

**Full Scan (完整扫描)**
- 全量扫描模式
- 扫描过去 24 小时的所有事件日志
- 提供更全面的安全审计
- 适合深度检查和问题排查

**数据显示规则**
- 仪表盘 (DashboardPage): 仅显示今日最新的审计结果
- 趋势分析 (TrendsPage): 显示过去 7 天的趋势数据
- 数据库自动保留 7 天数据，超过 7 天自动清理

#### 代码变更

**1. Views/DashboardPage.xaml**
```xml
<!-- 原按钮 -->
<Button Content="立即审计" Command="{x:Bind ViewModel.RunManualAuditCommand}"/>

<!-- 修改为 -->
<Button Content="Fast Scan" Command="{x:Bind ViewModel.RunFastScanCommand}"/>
<Button Content="Full Scan" Command="{x:Bind ViewModel.RunFullScanCommand}"/>
```

**2. ViewModels/DashboardViewModel.cs**
```csharp
// 新增命令
[RelayCommand]
private async Task RunFastScanAsync()
{
    IsLoading = true;
    StatusMessage = "正在执行快速扫描（增量数据）...";
    await _schedulerService.ExecuteAuditAsync(fastScan: true);
    await LoadDataCommand.ExecuteAsync(null);
}

[RelayCommand]
private async Task RunFullScanAsync()
{
    IsLoading = true;
    StatusMessage = "正在执行完整扫描（全量数据）...";
    await _schedulerService.ExecuteAuditAsync(fastScan: false);
    await LoadDataCommand.ExecuteAsync(null);
}
```

**3. Services/AuditSchedulerService.cs**
```csharp
// 添加字段跟踪上次扫描时间
private DateTime _lastScanTime = DateTime.MinValue;

// 修改方法签名，添加 fastScan 参数
public async Task ExecuteAuditAsync(bool fastScan = true)
{
    DateTime endTime = DateTime.Now;
    DateTime startTime;

    if (fastScan)
    {
        // 增量扫描：自上次扫描以来的新数据
        startTime = _lastScanTime == DateTime.MinValue
            ? endTime.AddHours(-4)
            : _lastScanTime;
    }
    else
    {
        // 完整扫描：过去 24 小时全量数据
        startTime = endTime.AddHours(-24);
    }
    
    // ... 执行扫描逻辑
    
    // 更新上次扫描时间
    _lastScanTime = endTime;
}
```

**4. Services/DataStorageService.cs**
- `GetTodayResultAsync()` - 已经实现仅返回今日数据 (`WHERE DATE(Timestamp) = DATE('now')`)
- `GetTrendsAsync(int days = 7)` - 返回指定天数的趋势数据
- `CleanupOldDataAsync()` - 自动删除 7 天前的数据
- `SaveAuditResultAsync()` - 保存时自动清理旧数据

#### 元数据追踪

每次扫描会在 Metadata 中记录：
```json
{
    "EventCount": 123,
    "TimeRange": "2026-09-03 00:00 - 2026-09-03 02:00",
    "ScanType": "Fast Scan" | "Full Scan"
}
```

---

## 构建状态

### 构建环境
- **MSBuild**: Visual Studio 2026 Enterprise (版本 18.9.1)
- **平台**: x64
- **.NET**: 8.0
- **Windows SDK**: 10.0.19041.0

### 构建结果
- ✅ Debug 构建成功
- ✅ Release 构建成功
- ⚠️ 1 个警告 (NETSDK1206 - 信息性，不影响功能)

### 输出位置
- Debug: `bin\x64\Debug\net8.0-windows10.0.19041.0\LocalSecurityAudit.exe`
- Release: `bin\x64\Release\net8.0-windows10.0.19041.0\LocalSecurityAudit.exe`

---

## 运行说明

### 前置条件
1. 创建 API.txt 文件在 `C:\Users\Zen\Repos\Codings\Locals\`
   ```
   https://api.falsemeet.site
   your-api-key-here
   ```

2. 以管理员身份运行（读取 Security 日志需要管理员权限）

### 运行命令
```powershell
# Release 版本（推荐）
Start-Process "bin\x64\Release\net8.0-windows10.0.19041.0\LocalSecurityAudit.exe" -Verb RunAs

# Debug 版本
Start-Process "bin\x64\Debug\net8.0-windows10.0.19041.0\LocalSecurityAudit.exe" -Verb RunAs
```

### 使用说明

**首次运行**
- 应用启动后 10 秒自动执行首次快速扫描
- 每 4 小时自动执行一次快速扫描

**手动扫描**
- **Fast Scan**: 点击快速扫描按钮，扫描自上次扫描以来的新日志
- **Full Scan**: 点击完整扫描按钮，扫描过去 24 小时的全部日志

**数据查看**
- **今日审计**: 查看当天最新的审计结果和问题列表
- **7 天趋势**: 查看过去 7 天的问题数量和健康评分趋势

---

## 技术细节

### 增量扫描逻辑
1. 首次扫描：扫描过去 4 小时
2. 后续 Fast Scan：从 `_lastScanTime` 到当前时间
3. Full Scan：无论上次扫描时间，始终扫描过去 24 小时

### 数据保留策略
- 保留时长：7 天
- 清理时机：
  - 应用启动时
  - 每次保存新审计结果时
- 清理策略：`DELETE FROM AuditResults WHERE Timestamp < (当前时间 - 7 天)`

### 显示逻辑
- **今日数据**: `WHERE DATE(Timestamp) = DATE('now')` - SQLite 自动处理时区
- **趋势数据**: `WHERE Timestamp >= (当前时间 - 7 天)`
- **数据排序**: 按时间倒序，最新的在前

---

## 相关文档
- [BUILD_SUCCESS.md](BUILD_SUCCESS.md) - 构建成功报告
- [FINAL_SUMMARY.md](FINAL_SUMMARY.md) - 项目交付总结
- [README.md](README.md) - 完整使用说明
- [QUICK_START.md](QUICK_START.md) - 5 分钟快速入门
- [IMPLEMENTATION.md](IMPLEMENTATION.md) - 技术实施细节

---

**修改完成时间**: 2026-09-03 02:28  
**状态**: ✅ 所有修改已完成并测试通过
