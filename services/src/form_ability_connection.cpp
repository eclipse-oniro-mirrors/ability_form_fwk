
/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_ability_connection.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_data_mgr.h"
#include "form_db_cache.h"
#include "form_event_report.h"
#include "form_info.h"
#include "form_info_mgr.h"
#include "form_supply_callback.h"
#include "form_timer_mgr.h"
#include "form_util.h"
#include "iremote_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
 * @param element service ability's ElementName.
 * @param remoteObject the session proxy of service ability.
 * @param resultCode ERR_OK on success, others on failure.
 */
void FormAbilityConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    if (resultCode != ERR_OK) {
        HILOG_ERROR("%{public}s, formId:%{public}" PRId64 ", resultCode:%{public}d",
            __func__, formId_, resultCode);
        return;
    }

    HILOG_INFO("%{public}s, free install is %{public}d.", __func__, isFreeInstall_);
    if (!isFreeInstall_) {
        return;
    }

    std::vector<FormInfo> targetForms;
    if (FormInfoMgr::GetInstance().GetFormsInfoByBundle(bundleName_, targetForms) != ERR_OK) {
        HILOG_ERROR("%{public}s error, failed to get forms info for %{public}s.", __func__, bundleName_.c_str());
        return;
    }

    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId_, formRecord)) {
        HILOG_ERROR("%{public}s error, not exist such form:%{public}" PRId64 ".", __func__, formId_);
        return;
    }

    FormDataMgr::GetInstance().SetRecordNeedFreeInstall(formId_, false);
    FormInfo updatedForm;
    if (FormDataMgr::GetInstance().GetUpdatedForm(formRecord, targetForms, updatedForm)) {
        HILOG_INFO("%{public}s, refresh form", __func__);
        FormDataMgr::GetInstance().SetNeedRefresh(formId_, true);
        FormBmsHelper::GetInstance().NotifyModuleNotRemovable(formRecord.bundleName, formRecord.moduleName);
        return;
    }

    // delete form
    if (formRecord.formTempFlag) {
        FormDataMgr::GetInstance().DeleteTempForm(formId_);
    } else {
        FormDbCache::GetInstance().DeleteFormInfo(formId_);
    }
    FormDataMgr::GetInstance().DeleteFormRecord(formId_);
    const std::vector<int64_t> removedForms {formId_};
    FormDataMgr::GetInstance().CleanHostRemovedForms(removedForms);
    FormTimerMgr::GetInstance().RemoveFormTimer(formId_);
}

/**
 * @brief OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
 * @param element service ability's ElementName.
 * @param resultCode ERR_OK on success, others on failure.
 */
void FormAbilityConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    HILOG_INFO("%{public}s, element:%{public}s, resultCode:%{public}d",
        __func__, element.GetURI().c_str(), resultCode);
    if (connectId_ != 0) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId_);
        connectId_ = 0;
    } else {
        HILOG_ERROR("%{public}s fail, invalid connectId_: %{public}d", __func__, connectId_);
    }
    ReportFormAppUnbindEvent();
}

/**
 * @brief Remote object died event.
 * @param remoteObject the remote object of service ability.
 */
void FormAbilityConnection::OnConnectDied(const wptr<IRemoteObject> &remoteObject)
{
    if (connectId_ != 0) {
        FormSupplyCallback::GetInstance()->RemoveConnection(connectId_);
        connectId_ = 0;
    } else {
        HILOG_ERROR("%{public}s fail, connectId_ invalidate. connectId_: %{public}d", __func__, connectId_);
    }
}

sptr<OHOS::AppExecFwk::IAppMgr> FormAbilityConnection::GetAppMgr()
{
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
    return iface_cast<OHOS::AppExecFwk::IAppMgr>(remoteObject);
}

bool FormAbilityConnection::onFormAppConnect()
{
    std::string bundleName = GetBundleName();
    if (bundleName.empty()) {
        HILOG_ERROR("Empty bundle name.");
        return false;
    }
    auto appMgr = GetAppMgr();
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    int32_t userId = FormUtil::GetCurrentAccountId();
    int32_t ret = appMgr->GetRunningProcessInformation(bundleName, userId, infos);
    if (ret != ERR_OK) {
        HILOG_ERROR("Get running process info failed!");
        return false;
    }
    std::string targetProcessName = bundleName + ":form";
    for (std::vector<AppExecFwk::RunningProcessInfo>::iterator iter = infos.begin(); iter != infos.end(); iter++) {
        if ((*iter).processName_ != targetProcessName) {
            continue;
        }
        appFormPid_ = (*iter).pid_;
        return true;
    }
    return false;
}

void FormAbilityConnection::ReportFormAppUnbindEvent()
{
    FormEventInfo eventInfo;
    eventInfo.timeStamp = FormUtil::GetNowMillisecond();
    eventInfo.formId = GetFormId();
    eventInfo.bundleName = GetBundleName() + ":form";
    eventInfo.formAppPid = GetAppFormPid();
    HILOG_INFO("bundleName:%{public}s, formId:%{public}" PRId64 ",pid: %{public}" PRId32 ",timstamp:%{public}" PRId64,
        eventInfo.bundleName.c_str(), eventInfo.formId, eventInfo.formAppPid, eventInfo.timeStamp);
    FormEventReport::SendThirdFormEvent(FormEventName::UNBIND_FORM_APP, HiSysEventType::BEHAVIOR, eventInfo);
}

/**
 * @brief Set connectId.
 * @param connectId The ability connection id.
 */
void FormAbilityConnection::SetConnectId(int32_t connectId)
{
    HILOG_INFO("%{public}s, connectId_: %{public}d", __func__, connectId);
    connectId_ = connectId;
}

/**
 * @brief Get connectId.
 * @return The ability connection id.
 */
int32_t FormAbilityConnection::GetConnectId() const
{
    return connectId_;
}

/**
 * @brief Get the provider Key
 *
 * @return The provider Key
 */
std::string FormAbilityConnection::GetProviderKey() const
{
    if (bundleName_.empty() || abilityName_.empty()) {
        return "";
    }
    return bundleName_ + "::" + abilityName_;
}

/**
 * @brief Set the Provider Key
 *
 * @param bundleName bundleName
 * @param abilityName abilityName
 */
void FormAbilityConnection::SetProviderKey(const std::string &bundleName, const std::string &abilityName)
{
    bundleName_ = bundleName;
    abilityName_ = abilityName;
}

void FormAbilityConnection::SetFreeInstall(bool isFreeInstall)
{
    isFreeInstall_ = isFreeInstall;
}

void FormAbilityConnection::SetFormId(int64_t formId)
{
    formId_ = formId;
}

int64_t FormAbilityConnection::GetFormId() const
{
    return formId_;
}

void FormAbilityConnection::SetHostToken(const sptr<IRemoteObject> hostToken)
{
    hostToken_ = hostToken;
}

sptr<IRemoteObject> FormAbilityConnection::GetHostToken() const
{
    return hostToken_;
}

void FormAbilityConnection::SetProviderToken(const sptr<IRemoteObject> providerToken)
{
    providerToken_ = providerToken;
}

sptr<IRemoteObject> FormAbilityConnection::GetProviderToken() const
{
    return providerToken_;
}

std::string FormAbilityConnection::GetBundleName()
{
    return bundleName_;
}

int32_t FormAbilityConnection::GetAppFormPid()
{
    return appFormPid_;
}

} // namespace AppExecFwk
} // namespace OHOS