/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include <unordered_map>

#include "form_ability_connection_reporter.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_util.h"
#include "iremote_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#ifdef RES_SCHEDULE_ENABLE
#include "res_sched_client.h"
#include "res_type.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string FORM_CONNECTION_PROCESS_NAME_SUFFIX = ":form";
}

FormAbilityConnectionReporter::FormAbilityConnectionReporter()
{
    HILOG_INFO("Called.");
}

FormAbilityConnectionReporter::~FormAbilityConnectionReporter()
{
    HILOG_INFO("Called.");
}

void FormAbilityConnectionReporter::ReportFormAbilityConnection(const sptr<FormAbilityConnection> &connection)
{
    if (!connection) {
        HILOG_ERROR("Invalid connection!");
        return;
    }
    std::string connectionProviderKey = connection->GetProviderKey();
    std::lock_guard<std::mutex> lock(formConnectionInfoMapMutex_);
    auto iter = formConnectionInfoMap_.find(connectionProviderKey);
    if (iter != formConnectionInfoMap_.end()) {
        FormConnectionInfo &connectionInfo = iter->second;
        connectionInfo.connectCount_++;
        return;
    }
    auto appMgr = GetAppMgr();
    std::string bundleName = connection->GetBundleName();
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int32_t userId = FormUtil::GetCurrentAccountId();
    int32_t ret = appMgr->GetRunningProcessInformation(bundleName, userId, infos);
    if (ret != ERR_OK) {
        HILOG_ERROR("Get running process info failed!");
        return;
    }
    HILOG_INFO("Connection name: %{public}s, the size of current bundle's process infos  is %{public}zu.",
        connectionProviderKey.c_str(), infos.size());
    AddFormAbilityConnectProcessInfo(bundleName, connectionProviderKey, infos);
    ReportConnectionInfosToRss(connectionProviderKey, true);
}

void FormAbilityConnectionReporter::ReportFormAbilityDisconnection(const sptr<FormAbilityConnection> &connection)
{
    if (!connection) {
        HILOG_ERROR("Invalid connection!");
        return;
    }
    std::string connectionProviderKey = connection->GetProviderKey();
    std::lock_guard<std::mutex> lock(formConnectionInfoMapMutex_);
    auto iter = formConnectionInfoMap_.find(connectionProviderKey);
    if (iter == formConnectionInfoMap_.end()) {
        HILOG_ERROR("Disconnect ability connection: %{public}s, but without created connection notified!",
            connectionProviderKey.c_str());
        return;
    }
    int count = iter->second.connectCount_ - 1;
    if (count > 0) {
        formConnectionInfoMap_[connectionProviderKey].connectCount_ = count;
        return;
    }

    ReportConnectionInfosToRss(connectionProviderKey, false);
    formConnectionInfoMap_.erase(connectionProviderKey);
    HILOG_INFO("Reporter disconnection info, connection's name: %{public}s.",
        connectionProviderKey.c_str());
}

sptr<OHOS::AppExecFwk::IAppMgr> FormAbilityConnectionReporter::GetAppMgr()
{
    if (appManager_ == nullptr) {
        sptr<ISystemAbilityManager> systemMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemMgr == nullptr) {
            HILOG_ERROR("Fail to connect system ability manager.");
            return nullptr;
        }
        sptr<IRemoteObject> remoteObject = systemMgr->GetSystemAbility(APP_MGR_SERVICE_ID);
        if (remoteObject == nullptr) {
            HILOG_ERROR(" Fail to connect app mgr service.");
            return nullptr;
        }
        HILOG_INFO("Connect app mgr service sucess.");
        appManager_ = iface_cast<OHOS::AppExecFwk::IAppMgr>(remoteObject);
    }
    return appManager_;
}

void FormAbilityConnectionReporter::AddFormAbilityConnectProcessInfo(const std::string& bundleName,
    const std::string& connectionProviderKey, std::vector<AppExecFwk::RunningProcessInfo>& infos)
{
    if (bundleName.empty()) {
        HILOG_WARN("Empty bundle name.");
        infos.clear();
        return;
    }
    std::string targetProceName = bundleName + FORM_CONNECTION_PROCESS_NAME_SUFFIX;
    for (std::vector<AppExecFwk::RunningProcessInfo>::iterator iter = infos.begin(); iter != infos.end(); iter++) {
        if ((*iter).processName_ != targetProceName) {
            continue;
        }
        HILOG_INFO("Get running process: %{public}s, pid: %{public}" PRId32 ".", targetProceName.c_str(),
            (*iter).pid_);
        FormConnectionInfo connectionInfo;
        connectionInfo.bundleName_ = bundleName;
        connectionInfo.pid_ = (*iter).pid_;
        connectionInfo.connectCount_ = 1;
        formConnectionInfoMap_.emplace(connectionProviderKey, connectionInfo);
        return;
    }
}

void FormAbilityConnectionReporter::ReportConnectionInfosToRss(const std::string &connectionProviderKey,
    bool isConnected)
{
    auto iter = formConnectionInfoMap_.find(connectionProviderKey);
    if (iter == formConnectionInfoMap_.end()) {
        HILOG_WARN("Report connection info failed, empty info, connection name: %{public}s.",
            connectionProviderKey.c_str());
        return;
    }
#ifdef RES_SCHEDULE_ENABLE
    auto status = isConnected ? ResourceSchedule::ResType::FormCreateStatus::FormCreateStart
        : ResourceSchedule::ResType::FormCreateStatus::FormCreateEnd;
    std::unordered_map<std::string, std::string> payload = {
        {"saId", std::to_string(FORM_MGR_SERVICE_ID)},
        {"pid", std::to_string(iter->second.pid_)}
    };
    ResourceSchedule::ResSchedClient::GetInstance().ReportData(
        ResourceSchedule::ResType::RES_TYPE_FORM_STATE_CHANGE_EVENT, status, payload);
#endif
}
}  // namespace AppExecFwk
}  // namespace OHOS