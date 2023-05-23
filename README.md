# 卡片管理

## 简介

卡片是一种界面展示形式，可以将应用的重要信息或操作前置到卡片，以达到服务直达的目的。

卡片常用于嵌入到其他应用（当前只支持系统应用）中作为其界面的一部分显示，并支持拉起页面，发送消息等基础的交互功能。

卡片的基本概念：

- 卡片提供方
提供卡片显示内容原子化服务，定义卡片的显示内容、控件布局以及控件点击事件。
- 卡片使用方
显示卡片内容的应用，可自由配置应用中卡片展示的位置。
- 卡片管理服务
用于管理系统中所添加卡片的常驻代理服务，包括卡片对象的管理与使用，以及卡片周期性刷新等。

开发者仅需作为卡片提供方进行卡片内容的开发，卡片使用方和卡片管理服务由系统自动处理。

> ![icon-note.gif](figures/icon-note.gif) **说明：**
> 卡片使用方和提供方不要求常驻运行，在需要添加/删除/请求更新卡片时，卡片管理服务会拉起卡片提供方获取卡片信息。

**部件内子模块职责**

| 子模块名称       | 职责                                                         |
| ---------------- | ------------------------------------------------------------|
| 卡片JS_Napikit模块| 提供外部接口，与卡片管理服务交互，负责事件通知的调度，通过ArkUI更新卡片视图。           |
| 卡片管理服务模块   | 管理系统中所添加卡片的常驻代理服务，管理卡片的生命周期，并维护卡片信息以及卡片事件的调度。 |

## 目录

```
foundation/ability/form_fwk
├── frameworks
│   └── js
│       └── napi					# form_fwk的napi代码实现
├── interfaces
│   ├── inner_api 				    # form_fwk的系统内部件间接口 
│   └── kits
│       └── native				    # form_fwk的对外接口  
├── services                        # form管理服务框架代码
└── test							# 测试目录
```

## 使用说明
​ 卡片框架模型具有两种形态：
-   第一种形态为FA模型。API 8及其更早版本的应用程序只能使用FA模型进行开发，卡片使用FormAbility开发。
-   第二种形态为Stage模型。从API 9开始，Ability框架引入了Stage模型作为第二种应用框架形态，卡片使用FormExtensionAbility开发。

**FA卡片开发**
基于[FA模型](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/application-models/fa-model-development-overview.md)的卡片提供方开发，主要涉及如下功能逻辑：

-   开发卡片生命周期回调函数LifecycleForm。
-   创建卡片数据FormBindingData对象。
-   通过FormProvider更新卡片。
-   开发卡片页面。

开发步骤可参考[开发指南](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/application-models/widget-development-fa.md)

**Stage卡片开发**
基于[Stage模型](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/application-models/stage-model-development-overview.md)的卡片提供方开发，主要涉及如下功能逻辑：

- 卡片生命周期回调函数FormExtension开发。
- 创建卡片数据FormBindingData对象。
- 通过FormProvider更新卡片。
- 卡片页面开发。

开发步骤可参考[开发指南](https://gitee.com/openharmony/docs/blob/master/zh-cn/application-dev/application-models/service-widget-overview.md)

## 相关仓
元能力子系统

[ability_base](https://gitee.com/openharmony/ability_ability_base)

[ability_runtime](https://gitee.com/openharmony/ability_ability_runtime)

[dmsfwk](https://gitee.com/openharmony/ability_dmsfwk)

[**form_fwk**](https://gitee.com/openharmony/ability_form_fwk)

[idl_tool](https://gitee.com/openharmony/ability_idl_tool)
