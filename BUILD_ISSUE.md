# 🐛 已知构建问题

## 问题描述
**症状**: `dotnet build` 失败，报错 `XamlCompiler.exe exited with code 1`

**根本原因**: WindowsAppSDK 1.5.240802000 的 XAML 编译器在 Pass 2 阶段生成空的 `.g.cs` 文件，导致编译失败。

## 诊断结果

经过详细调试发现：
1. ✅ **XAML 文件语法正确** - 所有 XAML 文件通过 XML 验证
2. ✅ **XAML Pass 1 成功** - 编译器成功解析所有 XAML 并生成 `.xbf` 二进制文件
3. ❌ **Pass 2 失败** - 生成的 `XamlTypeInfo.g.cs` 和 `App.g.cs` 为空文件（0 字节）
4. ✅ **所有手写 C# 代码正确** - Models、Services、ViewModels 代码无语法错误

## 可能的原因

1. **Windows App SDK 版本兼容性问题**
   - 当前使用: 1.5.240802000
   - 可能的解决方案: 降级到稳定版本

2. **.NET SDK 或运行时问题**
   - 当前系统: .NET 10.0.400 SDK
   - XAML 编译器依赖: .NET Framework 4.7.2 (XamlCompiler.exe)

3. **系统环境问题**
   - 缺少必要的 Visual C++ Redistributable
   - Windows SDK 组件缺失或损坏

## 解决方案

### 方案 1: 降级 WindowsAppSDK（推荐）

```xml
<PackageReference Include="Microsoft.WindowsAppSDK" Version="1.4.231115000" />
```

1. 编辑 `LocalSecurityAudit.csproj`
2. 将 WindowsAppSDK 版本改为 `1.4.231115000`（上一个稳定版本）
3. 删除 `obj` 和 `bin` 目录
4. 运行 `dotnet restore`
5. 运行 `dotnet build`

### 方案 2: 使用 Visual Studio 2022

Visual Studio 的构建工具可能比命令行 `dotnet build` 更好地处理 XAML 编译：

1. 安装 Visual Studio 2022（Community 版免费）
2. 安装工作负载：".NET Desktop Development" 和 "Windows application development"
3. 以管理员身份打开 Visual Studio
4. 打开 `LocalSecurityAudit.csproj`
5. 选择 "Build" → "Rebuild Solution"

### 方案 3: 修复系统环境

安装必要组件：
1. **Visual C++ Redistributable**
   - 下载: https://aka.ms/vs/17/release/vc_redist.x64.exe
   - 安装所有缺失的版本

2. **Windows SDK**
   - 确保安装了 Windows SDK 10.0.19041.0 或更高版本
   - 通过 Visual Studio Installer 安装

### 方案 4: 使用预构建二进制（最后手段）

如果以上方案都失败，可以在另一台能够成功构建的机器上：
1. 构建项目
2. 复制 `bin\Debug\net8.0-windows10.0.19041.0\` 目录
3. 在目标机器上直接运行 `.exe` 文件

## 验证步骤

成功构建后验证：
```bash
# 检查生成的文件
dir bin\x64\Debug\net8.0-windows10.0.19041.0\*.exe

# 以管理员身份运行
.\bin\x64\Debug\net8.0-windows10.0.19041.0\LocalSecurityAudit.exe
```

## 临时解决方案记录

尝试过但**未解决**的方法：
- ❌ 禁用 XBF 生成
- ❌ 禁用 XAML 代码生成
- ❌ 设置 SelfContained 模式
- ❌ 简化 XAML（移除 LiveCharts）
- ❌ 手动创建 XamlTypeInfo.g.cs
- ❌ 清理 NuGet 缓存

## 相关日志

XAML 编译器日志显示 Pass 1 完全成功：
- ✅ 创建类型系统
- ✅ 加载所有 XAML 文件
- ✅ 验证 XAML 语法
- ✅ 生成 XBF 二进制文件
- ✅ 写入 output.json

但生成的 `.g.cs` 文件为空（0 字节），这表明问题出在代码生成阶段。

## 下一步行动

**立即尝试**: 方案 1（降级 WindowsAppSDK）
**如果失败**: 方案 2（使用 Visual Studio 2022）
**最终方案**: 方案 3（修复系统环境）

---

**问题状态**: 🔴 阻塞构建  
**优先级**: 高  
**更新时间**: 2026-09-03
