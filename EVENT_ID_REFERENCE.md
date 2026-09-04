# Windows 事件 ID 参考

## Security Log 事件

### 登录相关
| Event ID | 描述 | 严重性 |
|----------|------|--------|
| 4624 | 成功登录 | Information |
| 4625 | 登录失败 | Warning |
| 4634 | 注销 | Information |
| 4647 | 用户发起的注销 | Information |
| 4648 | 使用显式凭据尝试登录 | Information |

### 账户管理
| Event ID | 描述 | 严重性 |
|----------|------|--------|
| 4720 | 创建了用户账户 | Information |
| 4722 | 启用了用户账户 | Information |
| 4723 | 尝试更改账户密码 | Information |
| 4724 | 尝试重置账户密码 | Information |
| 4725 | 禁用了用户账户 | Information |
| 4726 | 删除了用户账户 | Information |
| 4738 | 更改了用户账户 | Information |
| 4740 | 锁定了用户账户 | Information |
| 4767 | 解锁了用户账户 | Information |

### 组管理
| Event ID | 描述 | 严重性 |
|----------|------|--------|
| 4727 | 创建了全局组 | Information |
| 4731 | 创建了本地组 | Information |
| 4732 | 将成员添加到本地组 | Information |
| 4733 | 从本地组删除成员 | Information |
| 4756 | 将成员添加到全局组 | Information |
| 4757 | 从全局组删除成员 | Information |

### 权限和特权
| Event ID | 描述 | 严重性 |
|----------|------|--------|
| 4672 | 为新登录分配了特殊权限 | Information |
| 4673 | 调用了特权服务 | Information |
| 4674 | 尝试对特权对象执行操作 | Information |

### 审计策略
| Event ID | 描述 | 严重性 |
|----------|------|--------|
| 4719 | 更改了系统审计策略 | Information |

### 对象访问
| Event ID | 描述 | 严重性 |
|----------|------|--------|
| 4663 | 尝试访问对象 | Information |
| 4656 | 请求了对象的句柄 | Information |

## System Log 常见错误

| Event ID | Source | 描述 |
|----------|--------|------|
| 1014 | DNS-Client | DNS 客户端无法解析名称 |
| 1001 | BugCheck | 蓝屏死机 (BSOD) |
| 7000 | Service Control Manager | 服务启动失败 |
| 7001 | Service Control Manager | 服务依赖失败 |
| 7031 | Service Control Manager | 服务意外终止 |
| 7034 | Service Control Manager | 服务意外终止 |
| 10016 | DistributedCOM | DCOM 权限错误 |

## Firewall Log 事件

| Event ID | 描述 | 严重性 |
|----------|------|--------|
| 5152 | Windows 筛选平台阻止了数据包 | Information |
| 5153 | 限制性更强的筛选平台筛选器已阻止数据包 | Information |
| 5154 | Windows 筛选平台已允许应用程序或服务侦听端口上的传入连接 | Information |
| 5155 | Windows 筛选平台已阻止应用程序或服务侦听端口上的传入连接 | Information |
| 5156 | Windows 筛选平台已允许连接 | Information |
| 5157 | Windows 筛选平台已阻止连接 | Warning |
| 5158 | Windows 筛选平台已允许绑定到本地端口 | Information |
| 5159 | Windows 筛选平台已阻止绑定到本地端口 | Warning |

## Application Log 常见事件

| Event ID | Source | 描述 |
|----------|--------|------|
| 1000 | Application Error | 应用程序崩溃 |
| 1001 | Windows Error Reporting | 应用程序挂起 |
| 1002 | Application Hang | 应用程序无响应 |

## 安全审计重点关注

### 高危信号
1. **频繁的 4625** (登录失败) - 可能是暴力破解攻击
2. **非工作时间的 4624** - 异常登录时间
3. **4720** (创建账户) - 未授权的账户创建
4. **4732** (添加到管理员组) - 权限提升
5. **4672** (特殊权限) - 敏感权限分配
6. **5152/5157** (防火墙阻止) - 异常网络连接尝试

### 中危信号
1. **多次 4648** - 可能是凭据泄露
2. **4738** (账户更改) - 未授权的账户修改
3. **7031/7034** (服务崩溃) - 系统稳定性问题
4. **1000** (应用崩溃) - 应用稳定性问题

### 审计最佳实践
1. 监控失败登录次数（如 > 5 次/小时）
2. 关注非工作时间的活动（22:00-6:00）
3. 跟踪权限变更
4. 监控新账户创建
5. 检查异常的网络连接

## PowerShell 查询示例

### 查询最近的登录失败
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10
```

### 查询账户创建
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4720} -MaxEvents 10
```

### 查询特权分配
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4672} -MaxEvents 10
```

### 查询系统错误
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; Level=2} -MaxEvents 10
```

## 参考资源

- [Microsoft Security Auditing Events](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Windows Event Log Reference](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
