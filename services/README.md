# 卡片管理服务

## 简介
- 卡片管理服务
用于管理系统中所添加卡片的常驻代理服务，包括卡片对象的管理与使用，以及卡片周期性刷新等。

## 目录

```
foundation/ability/form_fwk/services
│── config                          # form 管理服务配置文件及解析实现
│── form_render_service             # form_render_service.hap(FRS)实现
├── include                         # form 管理服务依赖头文件
└── src                             # form 管理服务业务实现
   ├── ams_mgr                      # 负责与AMS模块交付: 建立连接、拉起ability等
   ├── bms_mgr                      # 负责与BMS模块交付: 获取bundle信息、注册包管理监听等
   ├── common                       # 公共事务处理模块: 通用工具类、定时器管理、打点上报等
   ├── data_center                  # 管理所有的卡片缓存信息、数据库表、与底层RDB交付等
   ├── feature                      # 功能特性: 包含新开发的功能特性业务处理逻辑，例如应用锁
   ├── form_host                    # 卡片使用方业务处理: 使用方回调、任务调度等
   ├── form_mgr                     # 外部接口代理: 作为FMS入口，接收外部请求并进行调度
   ├── form_observer                # 观察者业务处理: 观察者回调、任务调度等
   ├── form_provider                # 卡片提供方业务处理: 提供方回调、任务调度等
   ├── form_refresh                 # 卡片刷新管理：刷新请求的校验和调度
   ├── form_render                  # 卡片渲染业务处理: formRender回调、任务调度等
   └── status_mgr_center            # 状态管理中心: 任务队列的管理、状态机的管理等
```