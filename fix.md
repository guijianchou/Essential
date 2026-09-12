# Essential 优化工具实施规格（核心范围）

> **核心目标**：在侧栏增加第二个稳定入口“优化”（`system-optimization`），完成 Downloads 整理与用户目录缓存清理；安全审计（`security-audit`）保持可用、零破坏。  
> **代码行为基线**：Essential 0.4.3（git `f1d71b0`）；当前 HEAD `51dd359` 仅包含文档变化，工作树另有 README、changelog 和本文件改动。当前只更新 `fix.md`，不改业务代码。  
> **实施原则**：先只读扫描，再给出建议；只有用户勾选并确认后才能写入；宿主程序必须重新校验所有路径、动作和 AI 建议。

## 0. 核心需求与边界

### 必须交付
1. 侧栏第二入口“优化”，可打开独立的 `OptimizationPage`。
2. **Downloads 整理**：扫描元数据、生成分类预览、用户勾选后移动。
3. **缓存清理**：扫描明确白名单、显示路径/大小/风险，用户勾选后移入回收站。
4. 使用 Codex / Pi 与任务专属 `chains/system-optimization/AGENTS.md` 生成分类和风险建议；AI 只提供建议，不获得执行权。
5. 安全审计原有页面、调度、AI 契约、数据库历史、策略迁移和单实例行为不被破坏。

### 明确不做
- 不增加第三个侧栏入口或未来实验页面。
- 不抽象 MainViewModel 的审计底栏，不把优化任务塞入审计阶段。
- 不引入 `TaskResults`、`TokenUsage.TaskId` 或任何本迭代之外的数据库迁移；优化历史持久化另立变更。
- 不读取文件内容，不修改用户文件中的凭据/配置/数据库/程序目录，不自动申请 UAC。应用自有策略文件是本迭代明确允许写入的例外。
- 不支持永久删除；不执行真实系统审计，开发验证只用合成目录、临时数据和现有回归脚本。

## 1. 当前代码事实（实现前不可误写成“已完成”）

| 位置 | 当前事实 | 本迭代改造 |
| :-- | :-- | :-- |
| `Models/HubTaskCatalog.cs:7-20` | 3 字段 record（`Id/Title/Glyph`），只登记 `security-audit` | 增加 `PageType`，登记两个稳定入口；保留 `Get`，补 `TryGet` |
| `Views/MainWindow.xaml.cs:50-57, 238-267, 600` | 菜单和路由硬编码，只处理安全审计 | 按目录创建两个入口并路由；保留现有 2 参数 `NavigateIfNeeded` |
| `Views/MainWindow.xaml.cs:292-305` | 语言切换直接刷新任务文本 | 刷新两个稳定任务的本地化文本；不引入 Preview Badge |
| `App.xaml.cs:28-45` | 只注册现有审计/设置服务与 VM；优化页、VM、服务不存在 | 注册优化服务与 VM；页面按现有 `DashboardPage` 的 App 服务解析方式接入 |
| `SettingsPage.xaml:328-367` / `SettingsService.cs:334-351` | 静态 `SecurityAuditTaskCard`；策略读写只支持安全审计 | 按任务目录生成两张策略卡，路径严格限定为 `chains/{taskId}/AGENTS.md` |
| `DataStorageService.cs:52-82` | 只有 `AuditResults`、`ScanCheckpoints`、`TokenUsage`；无迁移框架 | MVP 不改数据库 schema；优化结果只保留当前运行报告，持久化历史另立变更 |
| `DataStorageService.History.cs:15-46` | 当前库与 `assistant\audit_data.db` 合并读取；assistant 库以只读连接校验 | 不迁移、不写入、不清理 assistant 历史库；保留审计策略旧文件迁移兼容 |
| `KernelManagerService` / `AiAnalysisService` | 前者负责安装、状态和 `RequireExecutable`；Codex/Pi 临时目录、环境、参数和进程调用在后者私有实现 | `TaskAiClient` 使用独立有界 runner；只调用公开内核能力，不复用审计私有方法、缓存或阶段状态 |
| `Resources/Strings.zh-CN.json:503` | `"Optimization": "优化"` key 已存在但未被任何代码引用 | W1 菜单标题直接复用该 key；仅新增优化页文案 key，勿重复创建 |

## 2. 功能规格

### 2.1 Downloads 整理

- 路径解析优先使用 Windows Downloads known-folder API；失败时仅回退当前用户 `%USERPROFILE%\Downloads` 并校验 User Shell Folders。解析失败即停止，不猜测其他目录。
- 默认只处理 Downloads 根目录内的文件；不跨出根目录，不自动处理已有子目录，不覆盖目标文件。
- 宿主扫描快照可保存完整路径用于 UI 和执行；每项生成本次扫描唯一 `itemId`。发送给 AI 的只有 `itemId`、扩展名/类别、大小、修改时间和经脱敏的名称提示，不发送绝对路径或原始敏感文件名。
- 先用本地扩展名/文件类型规则分类；只有歧义项进入 AI。结果必须展示目标相对目录、碰撞处理和理由。
- 用户逐项勾选；移动前重新校验扫描代次、源路径仍在 Downloads 内、目标仍在 Downloads 内且目标不存在。
- 不覆盖、不静默改名；碰撞只允许跳过或可预测编号后缀，并在当前运行报告中记录源/目标和结果。

### 2.2 用户目录缓存清理

- 初始白名单是**拟定清单，启用前逐路径验证**：当前用户临时目录、`%LOCALAPPDATA%\Temp`、Chrome/Edge/Firefox 缓存、npm/pip/nuget/pnpm 缓存、缩略图/图标缓存。优化代码当前不存在，不能把此清单写成现状。
- 禁止把整个 `%LOCALAPPDATA%`、用户文档、凭据目录、应用数据库、程序目录或系统目录作为扫描根；白名单外一律跳过。
- 输出路径、大小、修改时间、类别、占用状态、风险和跳过原因；系统级或需管理员权限的项目只显示“跳过”，不提权。
- 删除默认经过 `RecycleBinHelper`；禁止用 `File.Delete` 替代回收站；永久删除不属于本迭代。
- 用户确认前只读；只处理勾选项；占用、路径变化、白名单失效或风险未知时逐项跳过并报告。

### 2.3 AI 建议

- `TaskAiClient` 必须自带独立有界 runner：临时工作目录、环境变量、Codex/Pi 参数、超时、输出读取和清理均由它负责；`KernelManagerService` 只提供安装/状态/可执行文件解析能力。
- 输入只包含受限元数据和任务上下文；使用 `itemId` 而不是绝对路径，名称提示先脱敏；宿主保存 `itemId → 本地路径` 映射，不发送给模型。
- 输出严格 JSON；解析失败、未知 `itemId`、非法动作、越界目标、扫描代次不匹配、风险或理由缺失时，整项拒绝执行并标为人工处理。
- AI 不能授权写操作。宿主程序重新校验 `itemId`、`targetRelative`、`action`、白名单和扫描代次。
- 英文和简体中文理由同时保存；路径、大小、扩展名等事实来自本地快照，不能由模型编造。

## 3. 安全契约（不可妥协）

1. **扫描和分析只读**：未进入“用户确认”状态，不得移动、删除、改名或创建目录。
2. **确认绑定快照**：确认时冻结选中 `itemId` 和扫描代次；执行前重新校验，任一项变化即跳过，不扩大执行范围。
3. **路径边界**：Downloads 只能在 Downloads 内移动；缓存只能在白名单内处理；使用规范化绝对路径和目录边界判断，防止路径穿越。
4. **隐私边界**：不读取文件内容、不上传文件；AI 只接收脱敏元数据，不接收绝对路径、用户目录名或秘密；日志不得写入 API Key、Cookie、Token 或私钥。
5. **可恢复删除**：默认回收站；永久删除完全不在范围内；当前运行报告记录每个动作、结果、错误和回滚信息。
6. **权限边界**：优化功能不触发 UAC；管理员路径、系统路径和被占用文件跳过并说明原因。
7. **审计隔离**：不修改 `AiAnalysisService`、`AuditSchedulerService` 的审计契约和阶段；不改变既有 `AuditResults`；assistant 历史库始终只读。
8. **失败闭合**：未扫描、未分析、已跳过、未知和部分失败不得显示成“安全”或“已清理”。

## 4. 最小架构改造

### 4.1 任务目录、导航和 DI

使用最小定义：`HubTaskDefinition(string Id, string Title, string Glyph, Type PageType)`。只登记：
- `security-audit` → “Security audit” → 现有 `DashboardPage`。
- `system-optimization` → “Optimization” → 新建 `OptimizationPage`，Glyph 使用 `\uE771`。

`MainWindow.xaml.cs` 统一构建菜单；点击通过 `TryGet(taskId)` 获取定义，再调用现有 `NavigateIfNeeded(def.PageType, item)`。不引入分组头、Preview Badge 或通用底栏。`App.xaml.cs` 注册优化服务和 `OptimizationViewModel`；页面按 `DashboardPage` 的 `Loaded/Unloaded` 模式订阅和解绑，服务生命周期由 DI 管理。

### 4.2 页面和服务

- `OptimizationPage.xaml(.cs)`：Downloads / 缓存两个功能区，扫描结果、勾选、确认挂起、执行结果和错误列表；使用页面内局部进度。
- `OptimizationViewModel.cs`：管理扫描快照、选择状态、扫描代次、确认、执行状态和当前运行报告。
- `DownloadOrganizerService.cs`：路径解析、元数据枚举、确定性分类、碰撞规划、移动和回滚记录。
- `CacheCleanupService.cs`：白名单扫描、大小统计、占用检测、风险状态和删除计划。
- `RecycleBinHelper.cs`：封装 Windows 回收站 API；所有删除统一经过该服务。
- `TaskAiClient.cs`：独立 runner、策略加载、元数据格式化、JSON 校验和双语理由归一化；不执行文件操作。

### 4.3 Settings Hub

- 将静态 `SecurityAuditTaskCard` 改为按任务目录生成两张卡；显示任务名、策略路径、查看/编辑/保存/恢复默认。
- `SettingsService.GetTaskInstructions` 和 `GetTaskInstructionsPath` 按任务 ID 解析路径；未知 ID 拒绝，禁止任意路径传入。
- 安全审计策略沿用现有旧文件迁移和 scoped `chains/security-audit/AGENTS.md` 兼容逻辑；优化策略首次使用写入应用自有默认模板。

### 4.4 存储边界

- MVP 不新增表、不改 `AuditResults`、`ScanCheckpoints`、`TokenUsage`，不增加 `TokenUsage.TaskId`，不切换 WAL，不写或迁移 `assistant\audit_data.db`。
- 优化结果只在当前页面显示；持久化优化历史另开数据库变更，不在本迭代夹带。

## 5. 策略文件与输出契约

策略路径：`%LOCALAPPDATA%\LocalSecurityAudit\chains\system-optimization\AGENTS.md`。它必须声明：只接收脱敏元数据；Downloads 以本地规则为主；缓存仅限白名单；写操作必须用户确认；删除默认回收站；不处理凭据/配置/数据库/程序目录；输出双语理由。

最小 JSON 契约：

```json
{
  "recommendations": [
    {
      "itemId": "scan-local-id",
      "action": "move|delete|skip",
      "targetRelative": "relative target or null",
      "risk": "low|medium|high",
      "reasonEn": "evidence-based reason",
      "reasonZh": "基于证据的理由"
    }
  ]
}
```

宿主必须验证：`itemId` 属于当前扫描、扫描代次未变化、动作属于允许集合、目标在边界内、删除对象仍在缓存白名单内。JSON 不合法或验证失败时不得执行。

## 6. W1–W6 实施顺序

| 阶段 | 交付内容 | 主要文件 | 完成条件 |
| :-- | :-- | :-- | :-- |
| W1 | 任务目录、导航、DI 注册 | `HubTaskCatalog.cs`、`MainWindow.xaml.cs`、`App.xaml.cs` | 两入口可显示/切换；安全审计默认启动；服务可解析 |
| W2 | 优化页骨架和状态机 | `OptimizationPage`、`OptimizationViewModel` | 两功能区可扫描；`Loaded/Unloaded` 正确；确认前零写入 |
| W3 | 文件服务和回收站 | `DownloadOrganizerService`、`CacheCleanupService`、`RecycleBinHelper` | 白名单、边界、碰撞、占用、回滚和回收站合成测试通过 |
| W4 | 独立 AI runner、策略和设置卡 | `TaskAiClient`、策略文件、`SettingsPage`、`SettingsService` | 严格 JSON、脱敏输入、双语理由、编辑/保存/恢复默认；审计管线零改动 |
| W5 | 本地化 | `Strings.zh-CN.json` 及新增文案 | 新增文案无裸英文；复用已存在的 `Optimization` key；补唯一确认缺失的 `Database vacuum failed: {0}`；纯数字格式串不新增资源项 |
| W6 | 安全回归 | `tools/` 合成测试和现有审计测试 | 构建、导航、单实例、审计回归、安全红线和失败闭合全部通过 |

## 7. 验收与回归

- `dotnet build -p:Platform=x64` 成功；不引入新的编译错误或警告。
- 手动导航：安全审计 → 优化 → 设置；重启后仍默认进入安全审计。
- 现有 Fast/Full Scan、增量水位、Token 统计、单实例、语言切换和 assistant 只读历史回归通过。
- 合成 Downloads：已知/未知类型、目标碰撞、路径越界、锁定文件、取消、快照过期和回滚。
- 合成缓存：白名单内外路径、空目录、锁定项、系统级跳过、大小统计和回收站恢复。
- 强制确认：扫描、AI 解析、取消、未勾选、确认前关闭页面均不得产生写操作。
- AI 异常：非法 JSON、未知 ID、越界目标、缺少风险/理由、超时和无模型均失败闭合。
- 结果与日志：只保存脱敏 itemId/状态/错误，不保存文件内容、绝对路径或秘密；不产生任何数据库 schema 变化。
- 权限：普通用户运行优化功能，不出现 UAC；无权限项目显示跳过原因。

## 8. 延后事项

持久化优化历史、第三个入口、实验页面、通用底栏、WAL 切换、审计技术债和任何真实系统审计均另开变更，不扩大本次安全边界。

**执行路径**：读第 0 节确认边界 → 按第 6 节实施 → 用第 3 节安全契约约束代码 → 以第 7 节验收。
