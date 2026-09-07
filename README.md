# 本地安全审计系统 (LocalSecurityAudit)

版本: 0.3.0

## 项目概述

这是一个基于 WinUI 3 的 Windows 本地安全审计和监控工具。它读取 Windows 事件日志（安全、系统、应用程序、防火墙），使用 AI 模型（Luna）分析潜在的安全问题，并通过可视化仪表板展示结果。

## 主要功能

- **自动审计**: 每 4 小时自动执行一次安全审计
- **日志分析**: 读取 Windows Security、System、Application 和 Firewall 日志
- **AI 驱动分析**: 使用 Luna 模型识别异常登录、权限提升、防火墙异常等安全问题
- **数据可视化**: 
  - 健康评分仪表盘
  - 问题严重程度分布饼图
  - 1D / 7D / 30D 趋势、区间汇总和可点击的问题历史
- **自动加载**: 展示最新可用审计，跳过损坏记录；扫描完成和历史补译后自动更新
- **数据保留**: 默认保留最近 30 个本地自然日，旧版 7 天配置首次升级时迁移为 30 天
- **Mica 设计**: 使用 Windows 11 Mica 材质的现代化界面

趋势区间包含今天：1D 按本地小时汇总，7D / 30D 按本地日期汇总。统计和问题列表包含区间内全部扫描，重复发现按每次扫描分别计数；健康均值只包含有效评估，未扫描或未评估的时段留空。仪表盘继续展示最新一次可用审计。

## 技术栈

- **UI 框架**: WinUI 3 (Windows App SDK 1.5)
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
4. Windows App SDK 1.5+
5. 管理员权限（读取安全日志需要）

### 构建步骤

1. 克隆或打开项目目录
2. 恢复 NuGet 包：
   ```bash
   dotnet restore
   ```

3. 构建项目：
   ```bash
   dotnet build
   ```

4. 运行（需要管理员权限）：
   ```bash
   dotnet run
   ```

或者在 Visual Studio 中：
- 以管理员身份运行 Visual Studio
- 打开 `LocalSecurityAudit.csproj`
- 按 F5 运行

### API 配置

项目需要一个 API 密钥来访问 Luna 模型。在项目根目录的上一级创建 `API.txt` 文件：

```
https://api.falsemeet.site
<your-api-key>
```

## 功能详解

### 今日审计页面

- **健康评分**: 0-100 分，基于发现的问题数量和严重程度
  - 高危问题：-20 分
  - 中危问题：-10 分
  - 低危问题：-5 分
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

### 审计流程

1. **日志收集**: 读取过去 4 小时的关键事件
   - Security: 4624(成功登录), 4625(失败登录), 4648(显式凭据), 4672(特权分配), 4720(创建账户), 4732(添加到组)
   - System: 所有 Error 和 Warning 级别事件
   - Application: 所有 Error 和 Warning 级别事件
   - Firewall: 5152(阻止数据包), 5157(阻止连接)

2. **AI 分析**: 将事件批量发送给 Luna 模型（每批 30 个事件）

3. **结果存储**: 保存到本地 SQLite 数据库

4. **自动清理**: 按设置的保留期清理，默认保留最近 30 个本地自然日

## 数据存储

数据库位置：
```
%LOCALAPPDATA%\LocalSecurityAudit\audit_data.db
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

应用程序需要**管理员权限**才能：
- 读取 Security 事件日志
- 读取某些 System 和 Application 事件
- 读取防火墙日志

`app.manifest` 已配置为 `requireAdministrator`。

## 已知限制

1. 需要 Windows 11 才能获得最佳 Mica 效果（Windows 10 可以运行但无 Mica）
2. 首次运行需要下载较大的 NuGet 包
3. AI 分析依赖于网络连接和 API 可用性
4. 防火墙日志可能需要额外配置才能访问

## 故障排除

### 无法读取事件日志
- 确保以管理员身份运行应用程序
- 检查 Windows 事件查看器服务是否正常运行

### AI 分析失败
- 检查 `API.txt` 文件是否存在且包含有效的 API 密钥
- 验证网络连接到 api.falsemeet.site
- 查看日志中的详细错误信息

### 数据库错误
- 检查 `%LOCALAPPDATA%\LocalSecurityAudit` 目录的写入权限
- 尝试删除 `audit_data.db` 重新创建

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
