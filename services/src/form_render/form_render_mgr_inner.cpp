/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "form_render/form_render_mgr_inner.h"

#include <mutex>

#include "form_render/form_render_mgr.h"
#include "fms_log_wrapper.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_cache_mgr.h"
#include "form_constants.h"
#include "data_center/form_data_mgr.h"
#include "form_event_report.h"
#include "form_host_interface.h"
#include "form_mgr_errors.h"
#include "form_render/form_render_task_mgr.h"
#include "form_provider/form_supply_callback.h"
#include "status_mgr_center/form_status_task_mgr.h"
#include "common/util/form_trust_mgr.h"
#include "common/util/form_util.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "want.h"
#include "data_center/form_info/form_info_rdb_storage_mgr.h"
#include "data_center/form_record/form_record_report.h"
#include "status_mgr_center/form_status_mgr.h"
#include "form_host/form_host_task_mgr.h"
#include "status_mgr_center/form_status.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"
#include "feature/memory_mgr/form_render_report.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t LAST_CONNECTION = 1;
const std::string DLP_INDEX = "ohos.dlp.params.index";
const int FORM_DISCONNECT_FRS_DELAY_TIME = 5000; // ms
}
using Want = OHOS::AAFwk::Want;
FormRenderMgrInner::FormRenderMgrInner()
{
}
FormRenderMgrInner::~FormRenderMgrInner()
{
}

ErrCode FormRenderMgrInner::RenderForm(
    const FormRecord &formRecord, Want &want, const sptr<IRemoteObject> &hostToken)
{
    RecoverFRSOnFormActivity();
    if (atomicRerenderCount_ > 0) {
        --atomicRerenderCount_;
    } else {
        atomicRerenderCount_ = 0;
    }
    if (hostToken) {
        HILOG_DEBUG("Add host token");
        AddHostToken(hostToken, formRecord.formId);
        want.SetParam(Constants::PARAM_FORM_HOST_TOKEN, hostToken);
    }
    if (!isActiveUser_) {
        HILOG_WARN("isActiveUser is false, return");
        return ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED;
    }
    FillBundleInfo(want, formRecord.bundleName);

    sptr<FormRenderConnection> connection = nullptr;
    bool connectionExisted = GetRenderFormConnection(connection, formRecord.formId);
    if (connectionExisted) {
        if (connection == nullptr) {
            HILOG_ERROR("null connection");
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return RenderConnectedForm(formRecord, want, connection);
    }

    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, want.GetParams());
    if (formRenderConnection == nullptr) {
        HILOG_ERROR("null formRenderConnection");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    ErrCode errorCode = ConnectRenderService(formRenderConnection, formRecord.privacyLevel);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("ConnectServiceAbility failed");
        FormRenderMgr::GetInstance().HandleConnectFailed(formRecord.formId, errorCode);
        FormEventReport::SendFormFailedEvent(FormEventName::ADD_FORM_FAILED,
            formRecord.formId,
            formRecord.bundleName,
            formRecord.formName,
            static_cast<int32_t>(AddFormFailedErrorType::CONNECT_FORM_RENDER_FAILED),
            errorCode);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

void FormRenderMgrInner::CheckIfFormRecycled(FormRecord &formRecord, Want& want) const
{
    if (FormStatus::GetInstance().GetFormStatus(formRecord.formId) == FormFsmStatus::RECYCLED) {
        formRecord.lowMemoryRecycleStatus = LowMemoryRecycleStatus::NON_RECYCLABLE;
        FormDataMgr::GetInstance().UpdateFormRecord(formRecord.formId, formRecord);
        if (!formRecord.isDynamic) {
            HILOG_DEBUG("form %{public}" PRId64 " is static form", formRecord.formId);
            return;
        }
        std::string statusData;
        if (FormInfoRdbStorageMgr::GetInstance().LoadStatusData(
            std::to_string(formRecord.formId), statusData) != ERR_OK) {
            HILOG_ERROR("read status data of %{public}" PRId64 " failed.", formRecord.formId);
        } else {
            want.SetParam(Constants::FORM_STATUS_DATA, statusData);
        }
    }
}

ErrCode FormRenderMgrInner::GetConnectionAndRenderForm(FormRecord &formRecord, Want &want)
{
    int32_t connectId = 0;
    if (!GetRenderFormConnectId(formRecord.formId, connectId)) {
        HILOG_ERROR("Not find renderFormConnection");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    sptr<IRemoteObject> remoteObject;
    auto ret = GetRenderObject(remoteObject);
    if (ret != ERR_OK) {
        HILOG_ERROR("null remoteObjectGotten");
        return ret;
    }
    CheckIfFormRecycled(formRecord, want);
    want.SetParam(Constants::FORM_CONNECT_ID, connectId);

    auto renderType = want.GetIntParam(Constants::FORM_UPDATE_TYPE_KEY, Constants::ADD_FORM_UPDATE_FORM);
    if (renderType != Constants::ADAPTER_UPDATE_FORM ||
        FormDataMgr::GetInstance().GetFormCanUpdate(formRecord.formId) ||
        FormDataMgr::GetInstance().IsDataProxyIgnoreFormVisibility(formRecord.formId)) {
        FormDataMgr::GetInstance().ResetDataProxyUpdate(formRecord.formId);
        FormStatusTaskMgr::GetInstance().PostRenderForm(formRecord, std::move(want), remoteObject);
        return ERR_OK;
    }

    auto task = [formRecord, newWant = want, remoteObject]() {
        FormRecord newRecord(formRecord);
        std::string cacheData;
        std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
        bool hasCacheData = FormCacheMgr::GetInstance().GetData(formRecord.formId, cacheData, imageDataMap);
        if (hasCacheData) {
            newRecord.formProviderInfo.SetFormDataString(cacheData);
            newRecord.formProviderInfo.SetImageDataMap(imageDataMap);
        }
        FormStatusTaskMgr::GetInstance().PostRenderForm(newRecord, newWant, remoteObject);
    };
    RefreshCacheMgr::GetInstance().AddRenderTask(formRecord.formId, task);
    return ERR_OK;
}

ErrCode FormRenderMgrInner::UpdateRenderingForm(FormRecord &formRecord, const FormProviderData &formProviderData,
    const WantParams &wantParams, bool mergeData)
{
    RecoverFRSOnFormActivity();
    if (mergeData) {
        nlohmann::json jsonData = formProviderData.GetData();
        formRecord.formProviderInfo.MergeData(jsonData);
        auto providerData = formRecord.formProviderInfo.GetFormData();
        providerData.SetImageDataState(formProviderData.GetImageDataState());
        providerData.SetImageDataMap(formProviderData.GetImageDataMap());
        formRecord.formProviderInfo.SetFormData(providerData);
    } else {
        formRecord.formProviderInfo.SetFormData(formProviderData);
    }

    if (formRecord.formProviderInfo.NeedCache()) {
        FormCacheMgr::GetInstance().AddData(formRecord.formId, formRecord.formProviderInfo.GetFormData());
        if (FormStatus::GetInstance().GetFormStatus(formRecord.formId) == FormFsmStatus::RECYCLED) {
            std::string cacheData;
            std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
            if (FormCacheMgr::GetInstance().GetData(formRecord.formId, cacheData, imageDataMap)) {
                formRecord.formProviderInfo.SetImageDataMap(imageDataMap);
            }
        }
    } else {
        HILOG_DEBUG("need to delete data");
        FormCacheMgr::GetInstance().DeleteData(formRecord.formId);
    }
    if (formRecord.isTimerRefresh) {
        formRecord.isInited = true;
    } else {
        FormDataMgr::GetInstance().SetFormCacheInited(formRecord.formId, true);
    }

    HILOG_DEBUG("enableForm:%{public}d, protectForm:%{public}d", formRecord.enableForm, formRecord.protectForm);
    if (!formRecord.enableForm) {
        FormDataMgr::GetInstance().UpdateFormRecord(formRecord.formId, formRecord);
        FormDataMgr::GetInstance().SetUpdateDuringDisableForm(formRecord.formId, true);
        FormRecordReport::GetInstance().IncreaseUpdateTimes(formRecord.formId,
            HiSysEventPointType::TYPE_DISABLE_FORM_INTERCEPT);
        return ERR_APPEXECFWK_FORM_DISABLE_REFRESH;
    }
    Want want;
    want.SetParams(wantParams);
    FillBundleInfo(want, formRecord.bundleName);
    if (wantParams.IsEmpty()) {
        want.SetParam(Constants::FORM_UPDATE_TYPE_KEY, Constants::ADAPTER_UPDATE_FORM);
    }
    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::UPDATE_RENDERING_FORM);
    std::string recordUid = std::to_string(formRecord.providerUserId) + formRecord.bundleName;
    want.SetParam(Constants::FORM_SUPPLY_UID, recordUid);
    want.SetParam(Constants::FORM_LOCATION_KEY, static_cast<int32_t>(formRecord.formLocation));
    return GetConnectionAndRenderForm(formRecord, want);
}

ErrCode FormRenderMgrInner::ReloadForm(
    const std::vector<FormRecord> &&formRecords, const std::string &bundleName, int32_t userId)
{
    RecoverFRSOnFormActivity();
    sptr<IRemoteObject> remoteObject;
    auto ret = GetRenderObject(remoteObject);
    if (ret != ERR_OK) {
        HILOG_ERROR("null remoteObjectGotten");
        return ret;
    }
    Want want;
    FillBundleInfo(want, bundleName);
    want.SetParam(Constants::FORM_SUPPLY_UID, std::to_string(userId) + bundleName);
    want.SetParam(Constants::PARAM_BUNDLE_NAME_KEY, bundleName);
    FormRenderTaskMgr::GetInstance().PostReloadForm(std::forward<decltype(formRecords)>(formRecords),
        want, remoteObject);
    return ERR_OK;
}

void FormRenderMgrInner::FillBundleInfo(Want &want, const std::string &bundleName) const
{
    BundleInfo bundleInfo;
    if (!FormBmsHelper::GetInstance().GetBundleInfoDefault(
        bundleName, FormUtil::GetCurrentAccountId(), bundleInfo)) {
        HILOG_ERROR("get bundle info failed. %{public}s", bundleName.c_str());
        return;
    }

    want.SetParam(Constants::FORM_COMPATIBLE_VERSION_KEY, static_cast<int32_t>(bundleInfo.compatibleVersion));
    want.SetParam(Constants::FORM_TARGET_VERSION_KEY, static_cast<int32_t>(bundleInfo.targetVersion));
}

void FormRenderMgrInner::PostOnUnlockTask()
{
    HILOG_DEBUG("call");
    RecoverFRSOnFormActivity();
    sptr<IRemoteObject> remoteObject;
    auto ret = GetRenderObject(remoteObject);
    if (ret != ERR_OK) {
        HILOG_ERROR("null remoteObjectGotten");
        return;
    }
    FormRenderTaskMgr::GetInstance().PostOnUnlock(remoteObject);
}

void FormRenderMgrInner::NotifyScreenOn()
{
    HILOG_DEBUG("call");
    RecoverFRSOnFormActivity();
    sptr<IRemoteObject> remoteObject;
    auto ret = GetRenderObject(remoteObject);
    if (ret != ERR_OK) {
        HILOG_ERROR("null remoteObjectGotten");
        return;
    }
    sptr<IFormRender> remoteFormRenderer = iface_cast<IFormRender>(remoteObject);
    if (remoteFormRenderer == nullptr) {
        return;
    }
    remoteFormRenderer->RunCachedConfigurationUpdated();
}

void FormRenderMgrInner::PostSetVisibleChangeTask(int64_t formId, bool isVisible)
{
    HILOG_INFO("call");
    if (isVisible) {
        RecoverFRSOnFormActivity();
    }
    sptr<IRemoteObject> remoteObject;
    auto ret = GetRenderObject(remoteObject);
    if (ret != ERR_OK) {
        HILOG_ERROR("null remoteObjectGotten");
        return;
    }
    FormRenderTaskMgr::GetInstance().PostSetVisibleChange(formId, isVisible, remoteObject);
}

ErrCode FormRenderMgrInner::StopRenderingForm(int64_t formId, const FormRecord &formRecord,
    const std::string &compId, const sptr<IRemoteObject> &hostToken)
{
    if (formRecord.uiSyntax != FormType::ETS) {
        return ERR_OK;
    }
    if (formRecord.abilityName.empty()) {
        HILOG_ERROR("empty formRecord.abilityName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (formRecord.bundleName.empty()) {
        HILOG_ERROR("empty formRecord.bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    RecoverFRSOnFormActivity();
    Want want;
    std::string recordUid = std::to_string(formRecord.providerUserId) + formRecord.bundleName;
    want.SetParam(Constants::FORM_SUPPLY_UID, recordUid);
    if (!compId.empty()) {
        want.SetParam(Constants::FORM_RENDER_COMP_ID, compId);
    }
    if (hostToken) {
        HILOG_DEBUG("StopRenderingForm Add host token");
        want.SetParam(Constants::PARAM_FORM_HOST_TOKEN, hostToken);
    }

    return PostStopRenderingFormTask(formRecord, want);
}

ErrCode FormRenderMgrInner::StopRenderingFormCallback(int64_t formId, const Want &want)
{
    size_t renderFormConnectionSize = 0;
    sptr<FormRenderConnection> stopConnection = nullptr;
    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        HILOG_DEBUG("renderFormConnections_ size:%{public}zu", renderFormConnections_.size());
        auto conIterator = renderFormConnections_.find(formId);
        if (conIterator == renderFormConnections_.end()) {
            HILOG_ERROR("Can't find formId in map");
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        stopConnection = conIterator->second;
        renderFormConnectionSize = renderFormConnections_.size();
        for (auto iter = etsHosts_.begin(); iter != etsHosts_.end();) {
            iter->second.erase(formId);
            if (iter->second.empty()) {
                HILOG_INFO("All forms of the host have been removed, remove the host");
                iter = etsHosts_.erase(iter);
            } else {
                ++iter;
            }
        }
        renderFormConnections_.erase(formId);
    }
    if (stopConnection == nullptr) {
        HILOG_ERROR("Can't find stopConnection in map");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    DisconnectRenderService(stopConnection, renderFormConnectionSize);
    return ERR_OK;
}

ErrCode FormRenderMgrInner::ReleaseRenderer(int64_t formId, const FormRecord &formRecord, const std::string &compId)
{
    if (formRecord.uiSyntax != FormType::ETS) {
        return ERR_OK;
    }
    if (formRecord.abilityName.empty()) {
        HILOG_ERROR("empty formRecord.abilityName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (formRecord.bundleName.empty()) {
        HILOG_ERROR("empty formRecord.bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (CheckRenderConnectionExistById(formRecord.formId) != ERR_OK) {
        HILOG_ERROR("null connection");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    RecoverFRSOnFormActivity();
    sptr<IRemoteObject> remoteObject;
    auto ret = GetRenderObject(remoteObject);
    if (ret != ERR_OK) {
        HILOG_ERROR("null remoteObjectGotten");
        return ret;
    }
    std::string uid = std::to_string(formRecord.providerUserId) + formRecord.bundleName;
    FormStatusTaskMgr::GetInstance().PostReleaseRenderer(formId, compId, uid, remoteObject, formRecord.isDynamic);
    return ERR_OK;
}

ErrCode FormRenderMgrInner::AddConnection(int64_t formId, sptr<FormRenderConnection> connection)
{
    if (connection == nullptr) {
        HILOG_ERROR("null FormRenderConnection");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    size_t renderFormConnectionSize = 0;
    sptr<FormRenderConnection> oldConnection = nullptr;
    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        int32_t connectKey = static_cast<int32_t>(FormUtil::GetCurrentMillisecond());
        auto conIterator = renderFormConnections_.find(formId);
        if (conIterator == renderFormConnections_.end()) {
            connection->SetConnectId(connectKey);
            renderFormConnections_.emplace(formId, connection);
        } else if (renderFormConnections_[formId]->GetConnectId() != connection->GetConnectId()) {
            HILOG_WARN("Duplicate connection of formId:%{public}" PRId64 ", delete old connection", formId);
            renderFormConnectionSize = renderFormConnections_.size();
            oldConnection = renderFormConnections_[formId];
            renderFormConnections_[formId] = connection;
            connection->SetConnectId(connectKey);
        }
        HILOG_DEBUG("renderFormConnections size:%{public}zu", renderFormConnections_.size());
    }
    if (oldConnection) {
        DisconnectRenderService(oldConnection, renderFormConnectionSize);
    }
    return ERR_OK;
}

void FormRenderMgrInner::RemoveConnection(int64_t formId)
{
    std::lock_guard<std::mutex> lock(resourceMutex_);
    if (renderFormConnections_.find(formId) != renderFormConnections_.end()) {
        HILOG_DEBUG("Remove connection of formId:%{public}" PRId64 "", formId);
        renderFormConnections_.erase(formId);
    }
}

ErrCode FormRenderMgrInner::checkConnectionsFormIds(std::vector<int64_t> formIds, std::vector<int64_t> &needConFormIds)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(resourceMutex_);
    for (const int64_t &formId : formIds) {
        if (renderFormConnections_.find(formId) == renderFormConnections_.end()) {
            HILOG_ERROR("need add connection of formId:%{public}" PRId64 "", formId);
            needConFormIds.push_back(formId);
        }
    }
    HILOG_INFO("end");
    return ERR_OK;
}

void FormRenderMgrInner::RerenderAllForms()
{
    HILOG_WARN("FRS is died,notify host");
    std::unique_lock<std::shared_mutex> guard(renderRemoteObjMutex_);
    renderRemoteObj_ = nullptr;
    guard.unlock();
    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        atomicRerenderCount_ = renderFormConnections_.size();
        if (etsHosts_.empty() || renderFormConnections_.empty()) {
            HILOG_INFO("All hosts died or all connections erased, no need to rerender");
            return;
        }
        HILOG_INFO("The forms need to rerender count:%{public}zu", renderFormConnections_.size());
        for (auto &item : renderFormConnections_) {
            if (item.second == nullptr) {
                HILOG_ERROR("null Connection");
                continue;
            }
            item.second->SetStateDisconnected();
        }
    }
    if (!FormDataMgr::GetInstance().IsLowMemory()) {
        NotifyHostRenderServiceIsDead();
    } else {
        FormRenderReport::GetInstance().RecordFRSDead();
        isFrsDiedInLowMemory_ = true;
        HILOG_ERROR("Low memory killed FRS");
    }
}

void FormRenderMgrInner::CleanFormHost(const sptr<IRemoteObject> &host)
{
    HILOG_INFO("Host is died or been removed, notify FormRenderService and remove host");
    RemoveHostToken(host);
    std::unique_lock<std::shared_mutex> guard(renderRemoteObjMutex_);
    if (renderRemoteObj_ == nullptr) {
        HILOG_WARN("renderRemoteObj is null,render service may exit already");
        return;
    }
    renderRemoteObj_->CleanFormHost(host);
}

void FormRenderMgrInner::AddRenderDeathRecipient(const sptr<IRemoteObject> &remoteObject)
{
    std::shared_lock<std::shared_mutex> guard(renderRemoteObjMutex_);
    if (renderRemoteObj_) {
        HILOG_INFO("renderDeathRecipient is exist, no need to add again");
        return;
    }
    guard.unlock();

    HILOG_INFO("Get renderRemoteObj,add death recipient");
    auto renderRemoteObj = iface_cast<IFormRender>(remoteObject);
    if (renderRemoteObj == nullptr) {
        HILOG_ERROR("null renderRemoteObj");
        return;
    }

    if (renderDeathRecipient_ == nullptr) {
        renderDeathRecipient_ = new (std::nothrow) FormRenderRecipient([this]() {
            HILOG_WARN("FRS is Death, userId:%{public}d, isActiveUser:%{public}d", userId_, isActiveUser_);
            if (isActiveUser_) {
                RerenderAllForms();
            } else {
                std::unique_lock<std::shared_mutex> guard(renderRemoteObjMutex_);
                renderRemoteObj_ = nullptr;
                guard.unlock();
            }
        });
    }
    if (!remoteObject->AddDeathRecipient(renderDeathRecipient_)) {
        HILOG_ERROR("AddDeathRecipient failed");
        return;
    }
    SetRenderRemoteObj(renderRemoteObj);
}

inline ErrCode FormRenderMgrInner::ConnectRenderService(
    const sptr<FormRenderConnection> &connection, int32_t level) const
{
    if (connection == nullptr) {
        HILOG_INFO("null connection");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    Want want;
    want.SetElementName(Constants::FRS_BUNDLE_NAME, "ServiceExtension");
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    if (level > 0) {
        want.SetParam(DLP_INDEX, Constants::DEFAULT_SANDBOX_FRS_APP_INDEX);
        want.SetParam(Constants::FRS_APP_INDEX, Constants::DEFAULT_SANDBOX_FRS_APP_INDEX);
    }
    connection->SetStateConnecting();
    return FormAmsHelper::GetInstance().ConnectServiceAbilityWithUserId(want, connection, GetUserId());
}

void FormRenderMgrInner::SetUserId(int32_t userId)
{
    userId_ = userId;
}

int32_t FormRenderMgrInner::GetUserId() const
{
    return userId_;
}

void FormRenderMgrInner::RerenderAllFormsImmediate()
{
    HILOG_INFO("Called");
    isActiveUser_ = true;
    if (etsHosts_.empty()) {
        HILOG_WARN("All hosts died, no need to rerender.");
        return;
    }
    NotifyHostRenderServiceIsDead();
}

void FormRenderMgrInner::DisconnectAllRenderConnections()
{
    HILOG_INFO("renderFormConnections size: %{public}zu.", renderFormConnections_.size());
    std::lock_guard<std::mutex> lock(resourceMutex_);
    size_t size = renderFormConnections_.size();
    for (auto iter = renderFormConnections_.begin(); iter != renderFormConnections_.end();) {
        DisconnectRenderService(iter->second, size);
        iter = renderFormConnections_.erase(iter);
        size--;
    }
    isActiveUser_ = false;
}

void FormRenderMgrInner::DisconnectRenderService(const sptr<FormRenderConnection> connection, size_t size) const
{
    if (size == LAST_CONNECTION) {
        HILOG_INFO("This is the last connection, disconnect render service delay");
        FormAmsHelper::GetInstance().DisconnectServiceAbilityDelay(connection, FORM_DISCONNECT_FRS_DELAY_TIME);
    } else {
        HILOG_DEBUG("Disconnect render service ability");
        FormAmsHelper::GetInstance().DisconnectServiceAbility(connection);
    }
}

void FormRenderMgrInner::OnRenderingBlock(const std::string &bundleName)
{
    HILOG_INFO("bundleName:%{public}s", bundleName.c_str());
    FormEventInfo eventInfo;
    eventInfo.bundleName = bundleName;
    FormEventReport::SendSecondFormEvent(
        FormEventName::FORM_RENDER_BLOCK, HiSysEventType::FAULT, eventInfo);

    FormTrustMgr::GetInstance().MarkTrustFlag(bundleName, false);

    Want want;
    want.SetElementName(Constants::FRS_BUNDLE_NAME, "ServiceExtension");
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    FormAmsHelper::GetInstance().StopExtensionAbility(want);
}

inline void FormRenderMgrInner::AddHostToken(const sptr<IRemoteObject> &host, int64_t formId)
{
    std::lock_guard<std::mutex> lock(resourceMutex_);
    auto iter = etsHosts_.find(host);
    if (iter == etsHosts_.end()) {
        HILOG_DEBUG("Add host, current etsHosts.size:%{public}zu", etsHosts_.size());
        std::unordered_set<int64_t> formIdSet;
        formIdSet.emplace(formId);
        etsHosts_.emplace(host, formIdSet);
    } else {
        HILOG_DEBUG("Add formId to host, current etsHosts.size:%{public}zu", etsHosts_.size());
        iter->second.emplace(formId);
    }
}

void FormRenderMgrInner::RemoveHostToken(const sptr<IRemoteObject> &host)
{
    size_t left = 0;
    std::unordered_map<int64_t, sptr<FormRenderConnection>> connections;
    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        auto iter = etsHosts_.find(host);
        if (iter == etsHosts_.end()) {
            HILOG_ERROR("Can't find host in etsHosts");
            return;
        }
        auto formIdSet = iter->second;
        etsHosts_.erase(host);
        if (etsHosts_.empty()) {
            HILOG_DEBUG("etsHosts is empty, disconnect all connections size:%{public}zu",
                renderFormConnections_.size());
            connections.swap(renderFormConnections_);
        } else {
            for (const int64_t formId : formIdSet) {
                FormRecord formRecord;
                if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
                    connections.emplace(formId, renderFormConnections_[formId]);
                    renderFormConnections_.erase(formId);
                }
            }
        }
        left = renderFormConnections_.size();
    }
    for (auto iter = connections.begin(); iter != connections.end();) {
        DisconnectRenderService(iter->second, connections.size() > left ? connections.size() : left);
        iter = connections.erase(iter);
    }
}

void FormRenderMgrInner::NotifyHostRenderServiceIsDead() const
{
    {
        std::shared_lock<std::shared_mutex> guard(renderRemoteObjMutex_);
        if (renderRemoteObj_) {
            HILOG_WARN("FRS is not died");
            return;
        }
    }

    std::unordered_map<sptr<IRemoteObject>, std::unordered_set<int64_t>, RemoteObjHash> hostsForNotify;
    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        HILOG_INFO("Notify hosts the render is dead, hosts.size:%{public}zu", etsHosts_.size());
        auto tmpMap(etsHosts_);
        hostsForNotify.swap(tmpMap);
    }
    for (const auto &item : hostsForNotify) {
        sptr<IRemoteObject> hostClient = item.first;
        if (hostClient == nullptr) {
            HILOG_ERROR("null hostClient");
            continue;
        }
        FormHostTaskMgr::GetInstance().PostFrsDiedTaskToHost(hostClient);
    }
}

sptr<IFormRender> FormRenderMgrInner::GetRenderRemoteObj() const
{
    return renderRemoteObj_;
}

void FormRenderMgrInner::SetRenderRemoteObj(sptr<IFormRender> remoteObject)
{
    std::unique_lock<std::shared_mutex> guard(renderRemoteObjMutex_);
    renderRemoteObj_ = remoteObject;
}

int32_t FormRenderMgrInner::GetReRenderCount() const
{
    return atomicRerenderCount_;
}

ErrCode FormRenderMgrInner::RecycleForms(
    const std::vector<int64_t> &formIds, const Want &want, const sptr<IRemoteObject> &remoteObjectOfHost)
{
    HILOG_DEBUG("call");
    RecoverFRSOnFormActivity();
    sptr<IRemoteObject> remoteObject;
    auto ret = GetRenderObject(remoteObject);
    if (ret != ERR_OK) {
        HILOG_ERROR("null remoteObjectGotten");
        return ret;
    }

    std::vector<int64_t> connectedForms;
    GetConnectedForms(formIds, connectedForms);
    FormStatusTaskMgr::GetInstance().PostRecycleForms(connectedForms, want, remoteObjectOfHost, remoteObject);
    return ERR_OK;
}

ErrCode FormRenderMgrInner::RecoverForms(const std::vector<int64_t> &formIds, const WantParams &wantParams)
{
    HILOG_INFO("call");
    RecoverFRSOnFormActivity();
    sptr<IRemoteObject> remoteObject;
    auto ret = GetRenderObject(remoteObject);
    if (ret != ERR_OK) {
        HILOG_ERROR("null remoteObjectGotten");
        return ret;
    }

    for (const int64_t &formId : formIds) {
        Want want;
        want.SetParams(wantParams);

        FormRecord formRecord;
        if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
            HILOG_ERROR("form record %{public}" PRId64 " not exist", formId);
            continue;
        }

        std::string cacheData;
        std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
        if (FormCacheMgr::GetInstance().GetData(formRecord.formId, cacheData, imageDataMap)) {
            formRecord.formProviderInfo.SetImageDataMap(imageDataMap);
        }

        std::string uid = std::to_string(formRecord.providerUserId) + formRecord.bundleName;
        want.SetParam(Constants::FORM_SUPPLY_UID, uid);

        int32_t connectId = 0;
        if (GetRenderFormConnectId(formId, connectId)) {
            want.SetParam(Constants::FORM_CONNECT_ID, connectId);
            std::string statusData;
            if (FormInfoRdbStorageMgr::GetInstance().LoadStatusData(std::to_string(formId), statusData) != ERR_OK) {
                HILOG_ERROR("read status data of %{public}" PRId64 " failed.", formId);
            }
            want.SetParam(Constants::FORM_STATUS_DATA, statusData);

            FormStatusTaskMgr::GetInstance().PostRecoverForm(formRecord, want, remoteObject);
        } else {
            HILOG_ERROR("can't find connection of %{public}" PRId64, formId);
        }
    }
    return ERR_OK;
}

ErrCode FormRenderMgrInner::UpdateFormSize(const int64_t &formId, float width, float height, float borderWidth)
{
    HILOG_DEBUG("call");
    RecoverFRSOnFormActivity();
    sptr<IRemoteObject> remoteObject;
    auto ret = GetRenderObject(remoteObject);
    if (ret != ERR_OK) {
        HILOG_ERROR("null remoteObjectGotten");
        return ret;
    }

    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("form record %{public}" PRId64 " not exist", formId);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    std::string uid = std::to_string(formRecord.providerUserId) + formRecord.bundleName;
    FormRenderTaskMgr::GetInstance().PostUpdateFormSize(formId, width, height, borderWidth, uid, remoteObject);
    return ERR_OK;
}

ErrCode FormRenderMgrInner::GetRenderObject(sptr<IRemoteObject> &renderObj)
{
    std::shared_lock<std::shared_mutex> guard(renderRemoteObjMutex_);
    if (renderRemoteObj_ == nullptr) {
        HILOG_ERROR("null renderRemoteObj");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    renderObj = renderRemoteObj_->AsObject();
    if (renderObj == nullptr) {
        HILOG_ERROR("null remoteObj");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    return ERR_OK;
}

bool FormRenderMgrInner::GetRenderFormConnectId(const int64_t formId, int32_t &connectId)
{
    std::lock_guard<std::mutex> lock(resourceMutex_);
    auto conIterator = renderFormConnections_.find(formId);
    if (conIterator != renderFormConnections_.end()) {
        auto connection = conIterator->second;
        if (connection == nullptr) {
            HILOG_ERROR("connection of %{public}" PRId64 " is null.", formId);
            return false;
        }
        connectId = connection->GetConnectId();
        return true;
    }
    HILOG_ERROR("Not find renderFormConnection. formId: %{public}" PRId64, formId);
    return false;
}

bool FormRenderMgrInner::GetRenderFormConnection(sptr<FormRenderConnection> &connection, const int64_t formId)
{
    std::lock_guard<std::mutex> lock(resourceMutex_);
    HILOG_DEBUG("renderFormConnections_ size:%{public}zu", renderFormConnections_.size());
    auto conIterator = renderFormConnections_.find(formId);
    if (conIterator != renderFormConnections_.end()) {
        connection = conIterator->second;
        return true;
    }
    return false;
}

void FormRenderMgrInner::GetConnectedForms(const std::vector<int64_t> &formIds, std::vector<int64_t> &connectedForms)
{
    std::lock_guard<std::mutex> lock(resourceMutex_);
    for (const int64_t &formId : formIds) {
        auto conIterator = renderFormConnections_.find(formId);
        if (conIterator != renderFormConnections_.end()) {
            auto connection = conIterator->second;
            if (connection == nullptr) {
                HILOG_ERROR("connection of %{public}" PRId64 " is null.", formId);
                continue;
            }
            connectedForms.emplace_back(formId);
        } else {
            HILOG_ERROR("can't find connection of %{public}" PRId64, formId);
        }
    }
}

ErrCode FormRenderMgrInner::RenderConnectedForm(
    const FormRecord &formRecord, Want &want, const sptr<FormRenderConnection> &connection)
{
    if (connection == nullptr) {
        HILOG_ERROR("null connection");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    RecoverFRSOnFormActivity();
    std::shared_lock<std::shared_mutex> guard(renderRemoteObjMutex_);
    if (renderRemoteObj_ == nullptr) {
        connection->UpdateFormRecord(formRecord);
        connection->UpdateWantParams(want.GetParams());
        ErrCode ret = ConnectRenderService(connection, formRecord.privacyLevel);
        HILOG_INFO("ret:%{public}d", ret);
        if (ret) {
            FormRenderMgr::GetInstance().HandleConnectFailed(formRecord.formId, ret);
        }
        return ret;
    }
    auto remoteObject = renderRemoteObj_->AsObject();
    if (remoteObject == nullptr) {
        HILOG_ERROR("null remoteObject");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    guard.unlock();
    want.SetParam(Constants::FORM_CONNECT_ID, connection->GetConnectId());
    FormStatusTaskMgr::GetInstance().PostRenderForm(formRecord, want, remoteObject);
    return ERR_OK;
}

ErrCode FormRenderMgrInner::PostStopRenderingFormTask(const FormRecord &formRecord, Want &want)
{
    std::lock_guard<std::mutex> lock(resourceMutex_);
    auto conIterator = renderFormConnections_.find(formRecord.formId);
    if (conIterator != renderFormConnections_.end()) {
        auto connection = conIterator->second;
        if (connection == nullptr) {
            HILOG_ERROR("null connection");
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        sptr<IRemoteObject> remoteObject;
        auto ret = GetRenderObject(remoteObject);
        if (ret != ERR_OK) {
            HILOG_ERROR("null remoteObjectGotten");
            return ret;
        }
        want.SetParam(Constants::FORM_CONNECT_ID, connection->GetConnectId());
        FormStatusTaskMgr::GetInstance().PostStopRenderingForm(formRecord, std::move(want), remoteObject);
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormRenderMgrInner::CheckRenderConnectionExistById(int64_t formId)
{
    std::lock_guard<std::mutex> lock(resourceMutex_);
    auto conIterator = renderFormConnections_.find(formId);
    if (conIterator != renderFormConnections_.end()) {
        auto connection = conIterator->second;
        if (connection == nullptr) {
            HILOG_ERROR("null connection");
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

void FormRenderMgrInner::RecoverFRSOnFormActivity()
{
    if (isFrsDiedInLowMemory_.exchange(false)) {
        NotifyHostRenderServiceIsDead();
    }
}

bool FormRenderMgrInner::GetIsFRSDiedInLowMemory()
{
    HILOG_INFO("call isFrsDiedInLowMemory_ %{public}d", isFrsDiedInLowMemory_.load());
    return isFrsDiedInLowMemory_;
}

void FormRenderRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_INFO("Recv FormRenderService death notice");
    if (handler_) {
        handler_();
    }
}

FormRenderRecipient::FormRenderRecipient(RemoteDiedHandler handler) : handler_(handler) {}

FormRenderRecipient::~FormRenderRecipient() {}
} // namespace AppExecFwk
} // namespace OHOS
