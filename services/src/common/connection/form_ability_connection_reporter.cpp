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

#include "common/connection/form_ability_connection_reporter.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"
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
    HILOG_INFO("Call");
}

FormAbilityConnectionReporter::~FormAbilityConnectionReporter()
{
    HILOG_INFO("Call");
}

void FormAbilityConnectionReporter::ReportFormAbilityConnection(const std::string &bundleName)
{
    if (bundleName.empty()) {
        HILOG_ERROR("Invalid bundleName");
        return;
    }
    std::lock_guard<std::mutex> lock(formConnectionInfoMapMutex_);
    auto iter = formConnectionInfoMap_.find(bundleName);
    if (iter != formConnectionInfoMap_.end()) {
        FormConnectionInfo &connectionInfo = iter->second;
        connectionInfo.connectCount_++;
        return;
    }
    auto appMgr = GetAppMgr();
    if (appMgr == nullptr) {
        HILOG_ERROR("AppMgr is nullptr");
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int32_t userId = FormUtil::GetCurrentAccountId();
    int32_t ret = appMgr->GetRunningProcessInformation(bundleName, userId, infos);
    if (ret != ERR_OK) {
        HILOG_ERROR("Get running process info failed");
        return;
    }
    HILOG_INFO("BundleName:%{public}s, infosSize:%{public}zu",
        bundleName.c_str(), infos.size());
    AddFormAbilityConnectProcessInfo(bundleName, infos);
    ReportConnectionInfosToRss(bundleName, true);
}

void FormAbilityConnectionReporter::ReportFormAbilityDisconnection(const std::string &bundleName)
{
    if (bundleName.empty()) {
        HILOG_ERROR("Invalid bundleName");
        return;
    }
    std::lock_guard<std::mutex> lock(formConnectionInfoMapMutex_);
    auto iter = formConnectionInfoMap_.find(bundleName);
    if (iter == formConnectionInfoMap_.end()) {
        HILOG_ERROR("Disconnect ability connection:%{public}s, but without created connection notified!",
            bundleName.c_str());
        return;
    }
    int count = iter->second.connectCount_ - 1;
    if (count > 0) {
        formConnectionInfoMap_[bundleName].connectCount_ = count;
        return;
    }

    ReportConnectionInfosToRss(bundleName, false);
    formConnectionInfoMap_.erase(bundleName);
    HILOG_INFO("bundleName:%{public}s", bundleName.c_str());
}

sptr<OHOS::AppExecFwk::IAppMgr> FormAbilityConnectionReporter::GetAppMgr()
{
    if (appManager_ == nullptr) {
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
        HILOG_INFO("ConnectAMS succeed");
        appManager_ = iface_cast<OHOS::AppExecFwk::IAppMgr>(remoteObject);
    }
    return appManager_;
}

void FormAbilityConnectionReporter::AddFormAbilityConnectProcessInfo(const std::string& bundleName,
    std::vector<AppExecFwk::RunningProcessInfo>& infos)
{
    if (bundleName.empty()) {
        HILOG_WARN("Empty bundle name");
        infos.clear();
        return;
    }
    std::string targetProceName = bundleName + FORM_CONNECTION_PROCESS_NAME_SUFFIX;
    for (std::vector<AppExecFwk::RunningProcessInfo>::iterator iter = infos.begin(); iter != infos.end(); iter++) {
        if ((*iter).processName_ != targetProceName) {
            continue;
        }
        HILOG_INFO("Get running process:%{public}s, pid:%{public}" PRId32, targetProceName.c_str(),
            (*iter).pid_);
        FormConnectionInfo connectionInfo;
        connectionInfo.pid_ = (*iter).pid_;
        connectionInfo.connectCount_ = 1;
        formConnectionInfoMap_.emplace(bundleName, connectionInfo);
        return;
    }
}

void FormAbilityConnectionReporter::ReportConnectionInfosToRss(const std::string &bundleName,
    bool isConnected)
{
    auto iter = formConnectionInfoMap_.find(bundleName);
    if (iter == formConnectionInfoMap_.end()) {
        HILOG_WARN("Report connection info failed, empty info, bundle name:%{public}s",
            bundleName.c_str());
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