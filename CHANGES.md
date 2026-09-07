# 项目修改记录

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
