/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "form_mgr/form_visibility_adapter.h"

#include "accesstoken_kit.h"
#include "ashmem.h"
#include "hitrace_meter.h"
#include "ipc_skeleton.h"
#include "js_form_state_observer_interface.h"
#include "want.h"

#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/event/form_event_notify_connection.h"
#include "common/util/form_util.h"
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/form_record/form_record.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#include "feature/bundle_lock/form_exempt_lock_mgr.h"
#include "form_constants.h"
#include "form_host/form_host_callback.h"
#include "form_host/form_host_record.h"
#include "form_mgr_errors.h"
#include "form_mgr/form_common_adapter.h"
#include "form_provider/form_provider_mgr.h"
#include "form_render/form_render_mgr.h"
#include "status_mgr_center/form_status.h"

namespace OHOS {
namespace AppExecFwk {

constexpr const char *EMPTY_BUNDLE = "";

FormVisibilityAdapter::FormVisibilityAdapter(
    FormDataMgr* formDataMgr,
    FormCacheMgr* formCacheMgr,
    RefreshCacheMgr* refreshCacheMgr,
    FormInfoMgr* formInfoMgr,
    FormRenderMgr* formRenderMgr,
    FormMgrQueue* formMgrQueue,
    FormCommonAdapter* commonAdapter)
    : formDataMgr_(formDataMgr),
      formCacheMgr_(formCacheMgr),
      refreshCacheMgr_(refreshCacheMgr),
      formInfoMgr_(formInfoMgr),
      formRenderMgr_(formRenderMgr),
      formMgrQueue_(formMgrQueue),
      commonAdapter_(commonAdapter),
      visibleNotifyDelay_(Constants::DEFAULT_VISIBLE_NOTIFY_DELAY)
{
}

ErrCode FormVisibilityAdapter::NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, const int32_t formVisibleType)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("call, formIds size:%{public}zu", formIds.size());
    if (callerToken == nullptr) {
        HILOG_ERROR("null callerToken");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    int64_t matchedFormId = 0;
    int callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = FormUtil::GetCallerUserId(callingUid);
    std::map<std::string, std::vector<int64_t>> eventMaps = {};
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::vector<int64_t> checkFormIds;

    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_WARN("formId %{public}" PRId64 " is less than 0", formId);
            continue;
        }
        matchedFormId = formDataMgr_->FindMatchedFormId(formId);
        FormRecord formRecord;

        if (!isFormShouldUpdateProviderInfoToHost(matchedFormId, userId, callerToken, formRecord)) {
            continue;
        }
        SetVisibleChange(matchedFormId, formVisibleType, userId);
        PaddingNotifyVisibleFormsMap(formVisibleType, matchedFormId, formInstanceMaps);
        checkFormIds.push_back(formId);
        if ((!UpdateProviderInfoToHost(matchedFormId, userId, callerToken, formVisibleType, formRecord)) ||
            (!formRecord.isSystemApp)) {
            continue;
        }

        bool appFormVisibleNotify = false;
        auto ret = formInfoMgr_->GetAppFormVisibleNotifyByBundleName(
            formRecord.bundleName, formRecord.providerUserId, appFormVisibleNotify);
        if (ret != ERR_OK) {
            HILOG_ERROR("get app formVisibleNotify failed");
            return ret;
        }
        if (!appFormVisibleNotify) {
            HILOG_DEBUG("the value of formVisibleNotify is false");
            continue;
        }
        if (!CreateHandleEventMap(matchedFormId, formRecord, eventMaps)) {
            continue;
        }
    }
    PostVisibleNotify(
        (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE)) ? checkFormIds : formIds,
        formInstanceMaps, eventMaps, formVisibleType, visibleNotifyDelay_, callerToken);
    return ERR_OK;
}

bool FormVisibilityAdapter::HasFormVisible(const uint32_t tokenId)
{
    HILOG_DEBUG("call");
    Security::AccessToken::HapTokenInfo hapTokenInfo;
    int ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapTokenInfo);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        HILOG_ERROR("GetHapTokenInfo error with ret:%{public}d", ret);
        return false;
    }

    std::string bundleName = hapTokenInfo.bundleName;
    int32_t userId = hapTokenInfo.userID;
    HILOG_DEBUG("bundleName:%{public}s, userId:%{public}d, instIndex:%{public}d", bundleName.c_str(), userId,
        hapTokenInfo.instIndex);

    if (hapTokenInfo.instIndex != 0) {
        HILOG_INFO("The app is a clone application.");
        return false;
    }

    std::vector<FormRecord> formInfos;
    if (!formDataMgr_->GetFormRecord(bundleName, formInfos)) {
        return false;
    }

    for (const auto& formRecord : formInfos) {
        HILOG_DEBUG("query record, visible:%{public}d, userId:%{public}d", formRecord.formVisibleNotifyState, userId);
        if (formRecord.formVisibleNotifyState == static_cast<int32_t>(FormVisibilityType::VISIBLE) &&
            formRecord.userId == userId) {
                return true;
        }
    }

    return false;
}

int FormVisibilityAdapter::NotifyFormsVisible(const std::vector<int64_t> &formIds,
    bool isVisible, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("isVisible:%{public}d", isVisible);
    int32_t callerUserId = commonAdapter_->GetCallingUserId();
    return formDataMgr_->NotifyFormsVisible(formIds, isVisible, callerToken, callerUserId);
}

void FormVisibilityAdapter::SetVisibleChange(const int64_t formId, const int32_t formVisibleType, const int32_t userId)
{
    if (formId <= 0 || (formVisibleType != Constants::FORM_VISIBLE && formVisibleType != Constants::FORM_INVISIBLE)) {
        HILOG_WARN("param is not right");
        return;
    }

    bool isVisible = (formVisibleType == Constants::FORM_VISIBLE) ? true : false;
    formRenderMgr_->SetVisibleChange(formId, isVisible, userId);

    formDataMgr_->SetFormVisible(formId, isVisible);
    if (isVisible) {
        formDataMgr_->SetExpectRecycledStatus(formId, false);
        refreshCacheMgr_->ConsumeRenderTask(formId);
    }
}

void FormVisibilityAdapter::PaddingNotifyVisibleFormsMap(const int32_t formVisibleType, int64_t formId,
    std::map<std::string, std::vector<FormInstance>> &formInstanceMaps)
{
    std::string specialFlag = "#";
    bool isVisibility = (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE));
    FormInstance formInstance;
    formDataMgr_->GetFormInstanceById(formId, false, formInstance);
    std::string formHostName = formInstance.formHostName;
    std::string formAllHostName = EMPTY_BUNDLE;
    if (formVisibleType == static_cast<int32_t>(formInstance.formVisiblity)) {
        return;
    }
    std::lock_guard<std::mutex> lock(formObserversMutex_);
    for (auto formObserver : formObservers_) {
        if (formObserver.first == formHostName + specialFlag + std::to_string(isVisibility) ||
            formObserver.first == formAllHostName + specialFlag + std::to_string(isVisibility)) {
            auto observer = formInstanceMaps.find(formObserver.first);
            if (observer == formInstanceMaps.end()) {
                std::vector<FormInstance> formInstances;
                formInstance.formVisiblity = static_cast<FormVisibilityType>(formVisibleType);
                formInstances.emplace_back(formInstance);
                formInstanceMaps.emplace(formObserver.first, formInstances);
            } else {
                observer->second.emplace_back(formInstance);
            }
        }
    }
}

void FormVisibilityAdapter::HandlerNotifyWhetherVisibleForms(const std::vector<int64_t> &formIds,
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps,
    std::map<std::string, std::vector<int64_t>> eventMaps, const int32_t formVisibleType,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("start, formVisibleType:%{public}d", formVisibleType);
    FilterDataByVisibleType(formInstanceMaps, eventMaps, formVisibleType);
    std::map<std::string, std::vector<sptr<IRemoteObject>>> formObserversTemp;
    {
        std::lock_guard<std::mutex> lock(formObserversMutex_);
        formObserversTemp = formObservers_;
    }
    for (auto const &formObserver : formObserversTemp) {
        NotifyWhetherFormsVisible(formObserver.first, formObserver.second, formInstanceMaps, formVisibleType);
    }
    for (auto iter = eventMaps.begin(); iter != eventMaps.end(); iter++) {
        if (HandleEventNotify(iter->first, iter->second, formVisibleType) != ERR_OK) {
            HILOG_WARN("HandleEventNotify error, key is %{public}s", iter->first.c_str());
        }
    }
    if (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE)) {
        FormDataProxyMgr::GetInstance().EnableSubscribeFormData(formIds);
    } else if (formVisibleType == static_cast<int32_t>(FormVisibilityType::INVISIBLE)) {
        FormDataProxyMgr::GetInstance().DisableSubscribeFormData(formIds);
    }

    int32_t userId = commonAdapter_->GetCallingUserId();
    std::vector<int64_t> needConFormIds;
    if (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE)) {
        formRenderMgr_->checkConnectionsFormIds(formIds, userId, needConFormIds);
    }

    for (std::vector<int64_t>::iterator itFormId = needConFormIds.begin(); itFormId != needConFormIds.end();) {
        if (!formDataMgr_->ExistFormRecord(*itFormId)) {
            HILOG_WARN("not exist such form:%{public}" PRId64, *itFormId);
            itFormId = needConFormIds.erase(itFormId);
        } else {
            itFormId++;
        }
    }

    if (!needConFormIds.empty()) {
        HILOG_ERROR("reAddConnections, size: %{public}zu", needConFormIds.size());
        formRenderMgr_->reAddConnections(needConFormIds, userId, callerToken);
    }
}

void FormVisibilityAdapter::NotifyWhetherFormsVisible(const std::string &bundleName,
    const std::vector<sptr<IRemoteObject>> &remoteObjects,
    std::map<std::string, std::vector<FormInstance>> &formInstanceMaps, const int32_t formVisibleType)
{
    HILOG_DEBUG("bundleName:%{public}s, remoteObjects:%{public}d", bundleName.c_str(), (int)remoteObjects.size());
    for (auto remoteObject : remoteObjects) {
        sptr<AbilityRuntime::IJsFormStateObserver> remoteJsFormStateObserver =
            iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject);
        auto observer = formInstanceMaps.find(bundleName);
        if (observer != formInstanceMaps.end()) {
            if (formVisibleType == static_cast<int32_t>(FormVisibilityType::VISIBLE)) {
                remoteJsFormStateObserver->NotifyWhetherFormsVisible(FormVisibilityType::VISIBLE,
                    bundleName, observer->second);
            } else if (formVisibleType == static_cast<int32_t>(FormVisibilityType::INVISIBLE)) {
                remoteJsFormStateObserver->NotifyWhetherFormsVisible(FormVisibilityType::INVISIBLE,
                    bundleName, observer->second);
            }
        }
    }
}

void FormVisibilityAdapter::FilterDataByVisibleType(std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
    std::map<std::string, std::vector<int64_t>> &eventMaps, const int32_t formVisibleType)
{
    HILOG_DEBUG("start");
    std::map<int64_t, FormRecord> restoreFormRecords;
    FilterFormInstanceMapsByVisibleType(formInstanceMaps, formVisibleType, restoreFormRecords);
    FilterEventMapsByVisibleType(eventMaps, formVisibleType, restoreFormRecords);

    for (auto formRecordEntry : restoreFormRecords) {
        FormRecord formRecord = formRecordEntry.second;
        formRecord.isNeedNotify = false;
        HILOG_INFO("formRecord no need notify, formId:%{public}" PRId64 ".", formRecord.formId);
        if (!formDataMgr_->UpdateFormRecord(formRecord.formId, formRecord)) {
            HILOG_ERROR("update restoreFormRecords failed, formId:%{public}" PRId64 ".", formRecord.formId);
        }
    }
}

void FormVisibilityAdapter::FilterFormInstanceMapsByVisibleType(
    std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
    const int32_t formVisibleType, std::map<int64_t, FormRecord> &restoreFormRecords)
{
    for (auto iter = formInstanceMaps.begin(); iter != formInstanceMaps.end();) {
        std::vector<FormInstance> formInstances = iter->second;
        HILOG_DEBUG("bundName:%{public}s, formInstances:%{public}d", iter->first.c_str(), (int)formInstances.size());
        auto instanceIter = formInstances.begin();
        while (instanceIter != formInstances.end()) {
            FormRecord record;
            if (!formDataMgr_->GetFormRecord(instanceIter->formId, record)) {
                HILOG_WARN("get formRecord failed! formId:%{public}" PRId64 ".", instanceIter->formId);
                ++instanceIter;
                continue;
            }
            if (record.formVisibleNotifyState != formVisibleType) {
                HILOG_INFO("erase formId:%{public}" PRId64 ", formVisibleNotifyState:%{public}d",
                    instanceIter->formId, record.formVisibleNotifyState);
                restoreFormRecords[record.formId] = record;
                instanceIter = formInstances.erase(instanceIter);
                continue;
            }
            if (!record.isNeedNotify) {
                HILOG_INFO("erase formId:%{public}" PRId64
                    ", isNeedNotify:%{public}d, formVisibleNotifyState:%{public}d",
                    instanceIter->formId, record.isNeedNotify, record.formVisibleNotifyState);
                instanceIter = formInstances.erase(instanceIter);
                continue;
            }
            ++instanceIter;
        }
        if (formInstances.empty()) {
            iter = formInstanceMaps.erase(iter);
        } else {
            iter->second = formInstances;
            ++iter;
        }
    }
}

void FormVisibilityAdapter::FilterEventMapsByVisibleType(std::map<std::string, std::vector<int64_t>> &eventMaps,
    const int32_t formVisibleType, std::map<int64_t, FormRecord> &restoreFormRecords)
{
    for (auto iter = eventMaps.begin(); iter != eventMaps.end();) {
        std::vector<int64_t> formIds = iter->second;
        HILOG_DEBUG("bundName:%{public}s, eventMaps:%{public}d", iter->first.c_str(), (int)formIds.size());
        auto formItr = formIds.begin();
        while (formItr != formIds.end()) {
            FormRecord record;
            if (!formDataMgr_->GetFormRecord(*formItr, record)) {
                HILOG_WARN("get formRecord failed! formId:%{public}" PRId64 ".", *formItr);
                ++formItr;
                continue;
            }
            if (record.formVisibleNotifyState != formVisibleType) {
                HILOG_INFO("erase formId:%{public}" PRId64 ", formVisibleNotifyState:%{public}d",
                    *formItr, record.formVisibleNotifyState);
                restoreFormRecords[record.formId] = record;
                formItr = formIds.erase(formItr);
                continue;
            }
            if (!record.isNeedNotify) {
                HILOG_INFO("erase formId:%{public}" PRId64
                    ", isNeedNotify:%{public}d, formVisibleNotifyState %{public}d",
                    *formItr, record.isNeedNotify, record.formVisibleNotifyState);
                formItr = formIds.erase(formItr);
                continue;
            }
            ++formItr;
        }
        if (formIds.empty()) {
            iter = eventMaps.erase(iter);
        } else {
            iter->second = formIds;
            ++iter;
        }
    }
}

bool FormVisibilityAdapter::isFormShouldUpdateProviderInfoToHost(const int64_t &matchedFormId, const int32_t &userId,
    const sptr<IRemoteObject> &callerToken, FormRecord &formRecord)
{
    if (!formDataMgr_->GetFormRecord(matchedFormId, formRecord)) {
        HILOG_WARN("not exist such form, formId:%{public}" PRId64 ".", matchedFormId);
        return false;
    }

    if (formRecord.providerUserId != userId) {
        HILOG_WARN("not self form, formId:%{public}" PRId64 ".", matchedFormId);
        return false;
    }
    FormHostRecord formHostRecord;
    bool hasFormHostRecord = formDataMgr_->GetMatchedHostClient(callerToken, formHostRecord);
    if (!(hasFormHostRecord && formHostRecord.Contains(matchedFormId))) {
        HILOG_WARN("form not belong to self,formId:%{public}" PRId64 ".", matchedFormId);
        return false;
    }
    return true;
}

bool FormVisibilityAdapter::UpdateProviderInfoToHost(const int64_t &matchedFormId, const int32_t &userId,
    const sptr<IRemoteObject> &callerToken, const int32_t &formVisibleType, FormRecord &formRecord)
{
    formRecord.formVisibleNotifyState = formVisibleType;
    formRecord.isNeedNotify = true;

    auto updateTask = [&formRecord](FormRecord &oldRecord) {
        oldRecord.formVisibleNotifyState = formRecord.formVisibleNotifyState;
        oldRecord.isNeedNotify = formRecord.isNeedNotify;
    };
    if (!formDataMgr_->UpdateFormRecord(matchedFormId, updateTask)) {
        HILOG_WARN("set formVisibleNotifyState error,formId:%{public}" PRId64 ".",
            matchedFormId);
        return false;
    }

    HILOG_INFO("formId:%{public}" PRId64 ",needRefresh:%{public}d,formVisibleType:%{public}d,"
        "isTimerRefresh:%{public}d,wantCacheMapSize:%{public}d,isHostRefresh:%{public}d", matchedFormId,
        formRecord.needRefresh, static_cast<int32_t>(formVisibleType), formRecord.isTimerRefresh,
        (int)formRecord.wantCacheMap.size(), formRecord.isHostRefresh);
    if (!formRecord.needRefresh || formVisibleType != Constants::FORM_VISIBLE) {
        return true;
    }
    // If the form need refresh flag is true and form visibleType is FORM_VISIBLE, refresh the form host.
    if (formRecord.isTimerRefresh || formRecord.isHostRefresh) {
        refreshCacheMgr_->ConsumeInvisibleFlag(formRecord.formId, userId);
        return true;
    }

    auto onUpdateTask = [matchedFormId, formRecord, callerToken, this]() mutable {
        std::string cacheData;
        std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
        FormHostRecord formHostRecord;
        (void)formDataMgr_->GetMatchedHostClient(callerToken, formHostRecord);
        // If the form has business cache, refresh the form host.
        if (formCacheMgr_->GetData(matchedFormId, cacheData, imageDataMap)) {
            formRecord.formProviderInfo.SetFormDataString(cacheData);
            formRecord.formProviderInfo.SetImageDataMap(imageDataMap);
            formHostRecord.OnUpdate(matchedFormId, formRecord);
        }
    };
    if (!formMgrQueue_->ScheduleTask(0, onUpdateTask)) {
        HILOG_WARN("post OnUpdate task failed, exec now");
        onUpdateTask();
    }
    return true;
}

bool FormVisibilityAdapter::CreateHandleEventMap(const int64_t matchedFormId, const FormRecord &formRecord,
    std::map<std::string, std::vector<int64_t>> &eventMaps)
{
    if (!formRecord.formVisibleNotify) {
        HILOG_WARN("the config 'formVisibleNotify' is false, formId:%{public}" PRId64 ".",
            matchedFormId);
        return false;
    }

    std::string providerKey = formRecord.bundleName + Constants::NAME_DELIMITER + formRecord.abilityName;
    auto iter = eventMaps.find(providerKey);
    if (iter == eventMaps.end()) {
        std::vector<int64_t> formEventsByProvider {matchedFormId};
        eventMaps.insert(std::make_pair(providerKey, formEventsByProvider));
    } else {
        iter->second.emplace_back(matchedFormId);
    }
    return true;
}

ErrCode FormVisibilityAdapter::HandleEventNotify(const std::string &providerKey, const std::vector<int64_t> &formIdsByProvider,
    const int32_t formVisibleType)
{
    HILOG_INFO("call");
    size_t position = providerKey.find(Constants::NAME_DELIMITER);
    std::string bundleName = providerKey.substr(0, position);
    std::string abilityName = providerKey.substr(position + strlen(Constants::NAME_DELIMITER));
    sptr<IAbilityConnection> formEventNotifyConnection = new (std::nothrow) FormEventNotifyConnection(formIdsByProvider,
        formVisibleType, bundleName, abilityName, commonAdapter_->GetCallingUserId());
    if (formEventNotifyConnection == nullptr) {
        HILOG_ERROR("create FormEventNotifyConnection failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    Want connectWant;
    connectWant.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    connectWant.SetElementName(bundleName, abilityName);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(connectWant, formEventNotifyConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    return ERR_OK;
}

void FormVisibilityAdapter::PostVisibleNotify(const std::vector<int64_t> &formIds,
    std::map<std::string, std::vector<FormInstance>> &formInstanceMaps,
    std::map<std::string, std::vector<int64_t>> &eventMaps,
    const int32_t formVisibleType, int32_t visibleNotifyDelay,
    const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("call, formIds size:%{public}zu", formIds.size());

    auto task = [formIds, formInstanceMaps, eventMaps, formVisibleType, callerToken, this]() {
        HandlerNotifyWhetherVisibleForms(formIds,
            formInstanceMaps, eventMaps, formVisibleType, callerToken);
    };

    bool ret = formMgrQueue_->ScheduleTask(visibleNotifyDelay, task);
    if (!ret) {
        HILOG_WARN("post visible notify task failed, exec now");
        HandlerNotifyWhetherVisibleForms(formIds,
            formInstanceMaps, eventMaps, formVisibleType, callerToken);
    }
    HILOG_DEBUG("end");
}

int FormVisibilityAdapter::NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds,
    bool isEnableUpdate, const sptr<IRemoteObject> &callerToken)
{
    HILOG_INFO("isEnableUpdate:%{public}d", isEnableUpdate);
    return HandleUpdateFormFlag(formIds, callerToken, isEnableUpdate, true);
}

ErrCode FormVisibilityAdapter::HandleUpdateFormFlag(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken, bool flag, bool isOnlyEnableUpdate)
{
    HILOG_DEBUG("call");
    if (formIds.empty() || callerToken == nullptr) {
        HILOG_ERROR("invalid param");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    std::vector<int64_t> refreshForms;
    int errCode = formDataMgr_->UpdateHostFormFlag(formIds, callerToken,
        flag, isOnlyEnableUpdate, refreshForms);
    if (errCode == ERR_OK && !refreshForms.empty()) {
        int32_t userId = commonAdapter_->GetCallingUserId();
        for (const int64_t id : refreshForms) {
            HILOG_DEBUG("formRecord need refresh:%{public}" PRId64 "", id);
            Want want;
            want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
            FormProviderMgr::GetInstance().RefreshForm(id, want, false);
        }
    }
    return errCode;
}

int32_t FormVisibilityAdapter::SetFormsRecyclable(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("call");
    FormRecord record;
    std::vector<int64_t> validFormIds;
    int callingUid = IPCSkeleton::GetCallingUid();
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_ERROR("form id is negative");
            continue;
        }

        int64_t matchedFormId = formDataMgr_->FindMatchedFormId(formId);
        if (!formDataMgr_->GetFormRecord(matchedFormId, record)) {
            HILOG_WARN("form %{public}" PRId64 " not exist", formId);
            continue;
        }
        if (record.formTempFlag) {
            HILOG_WARN("form %{public}" PRId64 " is temp form", formId);
            continue;
        }
        if (!record.isDynamic) {
            HILOG_WARN("form %{public}" PRId64 " is static form", formId);
            continue;
        }
        if (record.uiSyntax != FormType::ETS) {
            HILOG_WARN("form %{public}" PRId64 " not ETS form", formId);
            continue;
        }
        if (record.lowMemoryRecycleStatus != LowMemoryRecycleStatus::NON_RECYCLABLE) {
            HILOG_WARN("form %{public}" PRId64 " is already RECYCLABLE or RECYCLED", formId);
            continue;
        }
        if (std::find(record.formUserUids.begin(), record.formUserUids.end(), callingUid) ==
            record.formUserUids.end()) {
            HILOG_WARN("form %{public}" PRId64 " not owned by %{public}d", formId, callingUid);
            continue;
        }

        record.lowMemoryRecycleStatus = LowMemoryRecycleStatus::RECYCLABLE;
        formDataMgr_->UpdateFormRecord(matchedFormId, record);
        validFormIds.emplace_back(matchedFormId);
        HILOG_INFO("formId:%{public}" PRId64 " recyclable", formId);
    }

    if (validFormIds.empty()) {
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return ERR_OK;
}

int32_t FormVisibilityAdapter::RecycleForms(const std::vector<int64_t> &formIds, const Want &want, bool isCheckCallingUid)
{
    FormRecord record;
    std::vector<int64_t> validFormIds;
    int callingUid = IPCSkeleton::GetCallingUid();
    for (int64_t formId : formIds) {
        if (formId <= 0) {
            HILOG_ERROR("form id is negative");
            continue;
        }

        int64_t matchedFormId = formDataMgr_->FindMatchedFormId(formId);
        if (!formDataMgr_->GetFormRecord(matchedFormId, record)) {
            HILOG_WARN("form %{public}" PRId64 " not exist", formId);
            continue;
        }
        if (record.formTempFlag) {
            HILOG_WARN("form %{public}" PRId64 " is temp form", formId);
            continue;
        }
        if (!record.isDynamic) {
            HILOG_WARN("form %{public}" PRId64 " is static form", formId);
            continue;
        }
        if (record.uiSyntax != FormType::ETS) {
            HILOG_WARN("form %{public}" PRId64 " not ETS form", formId);
            continue;
        }
        if (record.lowMemoryRecycleStatus != LowMemoryRecycleStatus::RECYCLABLE) {
            HILOG_WARN("form %{public}" PRId64 " is not RECYCLABLE", formId);
            continue;
        }
        if (FormStatus::GetInstance().IsFormProcessRecycle(formId)) {
            HILOG_WARN("form %{public}" PRId64 " is already RECYCLED", formId);
            continue;
        }
        if (isCheckCallingUid && std::find(record.formUserUids.begin(), record.formUserUids.end(), callingUid) ==
            record.formUserUids.end()) {
            HILOG_WARN("form %{public}" PRId64 " not owned by %{public}d", formId, callingUid);
            continue;
        }
        if (!isCheckCallingUid && callingUid < Constants::CALLING_UID_TRANSFORM_DIVISOR) {
            callingUid = *(record.formUserUids.begin());
        }
        validFormIds.emplace_back(matchedFormId);
        HILOG_INFO("formId:%{public}" PRId64 " recyclable", formId);
    }

    if (validFormIds.empty()) {
        HILOG_WARN("empty validFormIds");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    formDataMgr_->SetExpectRecycledStatus(validFormIds, true);
    formDataMgr_->RecycleForms(validFormIds, callingUid, want);
    return ERR_OK;
}

int32_t FormVisibilityAdapter::NotifyFormLocked(const int64_t &formId, bool isLocked)
{
    FormRecord formRecord;
    auto matchedFormId = formDataMgr_->FindMatchedFormId(formId);
    if (!formDataMgr_->GetFormRecord(matchedFormId, formRecord)) {
        HILOG_ERROR("No matching formRecord was found for the formId:%{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    int32_t userId = commonAdapter_->GetCallingUserId();
    bool isBundleProtected = FormBundleLockMgr::GetInstance().IsBundleProtect(formRecord.bundleName, userId);
    if (!isBundleProtected && isLocked) {
        HILOG_ERROR("can't lock form when bundle unprotected, formId %{public}" PRId64, formId);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (formRecord.protectForm == isLocked) {
        HILOG_WARN("protectForm state is same as before, formId:%{public}" PRId64, formId);
        return ERR_OK;
    }

    formRecord.protectForm = isLocked;

    HILOG_INFO("formId:%{public}" PRId64 ", isLocked:%{public}d", formId, isLocked);
    FormExemptLockMgr::GetInstance().SetExemptLockStatus(formId, !isLocked);
    formDataMgr_->SetFormProtect(formId, isLocked);
    std::vector<FormRecord> formRecords;
    formRecords.push_back(formRecord);
    formDataMgr_->LockForms(std::move(formRecords), isLocked);

    return ERR_OK;
}

} // namespace AppExecFwk
} // namespace OHOS
