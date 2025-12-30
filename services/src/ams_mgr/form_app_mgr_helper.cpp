/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ams_mgr/form_app_mgr_helper.h"

#include "ability_manager_interface.h"
#include "if_system_ability_manager.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
FormAppMgrHelper::FormAppMgrHelper()
{}

FormAppMgrHelper::~FormAppMgrHelper()
{}

sptr<OHOS::AppExecFwk::IAppMgr> FormAppMgrHelper::GetAppMgr()
{
    sptr<ISystemAbilityManager> systemMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemMgr == nullptr) {
        HILOG_ERROR("connect systemAbilityManager failed");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObject = systemMgr->GetSystemAbility(APP_MGR_SERVICE_ID);
    if (remoteObject == nullptr) {
        HILOG_ERROR("connect appMgrService failed");
        return nullptr;
    }
    return iface_cast<OHOS::AppExecFwk::IAppMgr>(remoteObject);
}

bool FormAppMgrHelper::IsAbilityForeground(const std::string &bundleName, ExtensionAbilityType extensionAbilityType)
{
    HILOG_INFO("bundleName:%{public}s, extensionAbilityType:%{public}d", bundleName.c_str(), extensionAbilityType);
    auto appMgrProxy = GetAppMgr();
    if (!appMgrProxy) {
        HILOG_ERROR("Get app mgr failed");
        return false;
    }
    std::vector<AppExecFwk::AppStateData> list;
    if (IN_PROCESS_CALL(appMgrProxy->GetForegroundApplications(list)) != ERR_OK) {
        HILOG_ERROR("get foreground app failed");
        return false;
    }
    
    HILOG_WARN("foreground ui abilities size:%{public}lu", list.size());
    for (const auto &stateData : list) {
        HILOG_WARN("stateData bundle:%{public}s extensionType:%{public}d",
            stateData.bundleName.c_str(), stateData.extensionType);
        if (stateData.bundleName == bundleName && stateData.extensionType == extensionAbilityType) {
            return true;
        }
    }
    return false;
}

bool FormAppMgrHelper::GetRunningProcessInfo(
    const std::string &bundleName, int32_t userId, RunningProcessInfo &info, const std::string &processNameSuffix)
{
    if (bundleName.empty()) {
        HILOG_ERROR("Empty bundle name");
        return false;
    }
    auto appMgr = GetAppMgr();
    if (!appMgr) {
        HILOG_ERROR("Get app mgr failed");
        return false;
    }

    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int32_t ret = appMgr->GetRunningProcessInformation(bundleName, userId, infos);
    if (ret != ERR_OK) {
        HILOG_ERROR("Get running process info failed");
        return false;
    }
    std::string targetProcessName = bundleName + processNameSuffix;
    for (std::vector<AppExecFwk::RunningProcessInfo>::iterator iter = infos.begin(); iter != infos.end(); iter++) {
        if ((*iter).processName_ != targetProcessName) {
            continue;
        }
        info = *iter;
        return true;
    }
    HILOG_ERROR("App is not running");
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
