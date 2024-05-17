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

#include "form_render_mgr_inner.h"

#include <mutex>

#include "form_render_mgr.h"
#include "fms_log_wrapper.h"
#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_cache_mgr.h"
#include "form_constants.h"
#include "form_data_mgr.h"
#include "form_event_report.h"
#include "form_host_interface.h"
#include "form_mgr_errors.h"
#include "form_render_mgr.h"
#include "form_supply_callback.h"
#include "form_task_mgr.h"
#include "form_trust_mgr.h"
#include "form_util.h"
#include "ipc_skeleton.h"
#include "os_account_manager.h"
#include "want.h"
#include "form_info_rdb_storage_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t LAST_CONNECTION = 1;
const std::string DLP_INDEX = "ohos.dlp.params.index";
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
    FillBundleInfo(want, formRecord.bundleName);

    bool connectionExisted = false;
    sptr<FormRenderConnection> connection = nullptr;
    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        HILOG_DEBUG("renderFormConnections_ size: %{public}zu.", renderFormConnections_.size());
        auto conIterator = renderFormConnections_.find(formRecord.formId);
        if (conIterator != renderFormConnections_.end()) {
            connectionExisted = true;
            connection = conIterator->second;
        }
    }
    if (connectionExisted) {
        if (connection == nullptr) {
            HILOG_ERROR("connection is null.");
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        if (renderRemoteObj_ == nullptr) {
            connection->UpdateWantParams(want.GetParams());
            ErrCode ret = ConnectRenderService(connection, formRecord.privacyLevel);
            HILOG_INFO("renderRemoteObj is nullptr, render may exit, need reconnect, ret: %{public}d.", ret);
            if (ret) {
                FormRenderMgr::GetInstance().HandleConnectFailed(formRecord.formId, ret);
            }
            return ret;
        }
        auto remoteObject = renderRemoteObj_->AsObject();
        if (remoteObject == nullptr) {
            HILOG_ERROR("remoteObject is nullptr, can not get obj from renderRemoteObj.");
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        want.SetParam(Constants::FORM_CONNECT_ID, connection->GetConnectId());
        FormTaskMgr::GetInstance().PostRenderForm(formRecord, want, remoteObject);
        return ERR_OK;
    }

    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, want.GetParams());
    if (formRenderConnection == nullptr) {
        HILOG_ERROR("formRenderConnection is null.");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    ErrCode errorCode = ConnectRenderService(formRenderConnection, formRecord.privacyLevel);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("%{public}s fail, ConnectServiceAbility failed.", __func__);
        FormRenderMgr::GetInstance().HandleConnectFailed(formRecord.formId, errorCode);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

void FormRenderMgrInner::CheckIfFormRecycled(FormRecord &formRecord, Want& want) const
{
    if (formRecord.recycleStatus == RecycleStatus::RECYCLED) {
        formRecord.recycleStatus = RecycleStatus::NON_RECYCLABLE;
        FormDataMgr::GetInstance().UpdateFormRecord(formRecord.formId, formRecord);
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
    std::lock_guard<std::mutex> lock(resourceMutex_);
    auto conIterator = renderFormConnections_.find(formRecord.formId);
    if (conIterator == renderFormConnections_.end()) {
        HILOG_ERROR("Not find renderFormConnection.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    auto connection = conIterator->second;
    if (connection == nullptr) {
        HILOG_ERROR("connection is null.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (renderRemoteObj_ == nullptr) {
        HILOG_ERROR("%{public}s, renderRemoteObj_ is nullptr", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    auto remoteObject = renderRemoteObj_->AsObject();
    if (remoteObject == nullptr) {
        HILOG_ERROR("remoteObject is nullptr, can not get obj from renderRemoteObj.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    CheckIfFormRecycled(formRecord, want);
    want.SetParam(Constants::FORM_CONNECT_ID, connection->GetConnectId());
    FormTaskMgr::GetInstance().PostRenderForm(formRecord, std::move(want), remoteObject);
    return ERR_OK;
}

ErrCode FormRenderMgrInner::UpdateRenderingForm(FormRecord &formRecord, const FormProviderData &formProviderData,
    const WantParams &wantParams, bool mergeData)
{
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
    } else {
        HILOG_DEBUG("need to delete data.");
        FormCacheMgr::GetInstance().DeleteData(formRecord.formId);
    }
    FormDataMgr::GetInstance().SetFormCacheInited(formRecord.formId, true);

    Want want;
    want.SetParams(wantParams);
    FillBundleInfo(want, formRecord.bundleName);
    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::UPDATE_RENDERING_FORM);
    int32_t userId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::FORM_SUPPLY_UID, std::to_string(userId) + formRecord.bundleName);
    return GetConnectionAndRenderForm(formRecord, want);
}

ErrCode FormRenderMgrInner::ReloadForm(
    const std::vector<FormRecord> &&formRecords, const std::string &bundleName, int32_t userId)
{
    if (renderRemoteObj_ == nullptr) {
        HILOG_ERROR("renderRemoteObj_ is nullptr");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    auto remoteObject = renderRemoteObj_->AsObject();
    if (remoteObject == nullptr) {
        HILOG_ERROR("remoteObject is nullptr, can not get obj from renderRemoteObj.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    Want want;
    FillBundleInfo(want, bundleName);
    want.SetParam(Constants::FORM_SUPPLY_UID, std::to_string(userId) + bundleName);
    FormTaskMgr::GetInstance().PostReloadForm(std::forward<decltype(formRecords)>(formRecords), want, remoteObject);
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
    HILOG_DEBUG("called");
    if (renderRemoteObj_ == nullptr) {
        HILOG_ERROR("renderRemoteObj_ is nullptr");
        return;
    }
    auto remoteObject = renderRemoteObj_->AsObject();
    if (remoteObject == nullptr) {
        HILOG_ERROR("remoteObject is nullptr, can not get obj from renderRemoteObj.");
        return;
    }
    FormTaskMgr::GetInstance().PostOnUnlock(remoteObject);
}

ErrCode FormRenderMgrInner::StopRenderingForm(int64_t formId, const FormRecord &formRecord,
    const std::string &compId, const sptr<IRemoteObject> &hostToken)
{
    if (formRecord.uiSyntax != FormType::ETS) {
        return ERR_OK;
    }
    if (formRecord.abilityName.empty()) {
        HILOG_ERROR("formRecord.abilityName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (formRecord.bundleName.empty()) {
        HILOG_ERROR("formRecord.bundleName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    Want want;
    int32_t userId = FormUtil::GetCurrentAccountId();
    want.SetParam(Constants::FORM_SUPPLY_UID, std::to_string(userId) + formRecord.bundleName);
    if (!compId.empty()) {
        want.SetParam(Constants::FORM_RENDER_COMP_ID, compId);
    }
    if (hostToken) {
        HILOG_DEBUG("StopRenderingForm Add host token");
        want.SetParam(Constants::PARAM_FORM_HOST_TOKEN, hostToken);
    }

    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        auto conIterator = renderFormConnections_.find(formRecord.formId);
        if (conIterator != renderFormConnections_.end()) {
            auto connection = conIterator->second;
            if (connection == nullptr) {
                HILOG_ERROR("connection is null.");
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
            if (renderRemoteObj_ == nullptr) {
                HILOG_ERROR(" renderRemoteObj_ is nullptr");
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
            auto remoteObject = renderRemoteObj_->AsObject();
            if (remoteObject == nullptr) {
                HILOG_ERROR("remoteObject is nullptr, can not get obj from renderRemoteObj.");
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
            want.SetParam(Constants::FORM_CONNECT_ID, connection->GetConnectId());
            FormTaskMgr::GetInstance().PostStopRenderingForm(formRecord, std::move(want), remoteObject);
            return ERR_OK;
        }
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormRenderMgrInner::StopRenderingFormCallback(int64_t formId, const Want &want)
{
    size_t renderFormConnectionSize = 0;
    sptr<FormRenderConnection> stopConnection = nullptr;
    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        HILOG_DEBUG("renderFormConnections_ size: %{public}zu.", renderFormConnections_.size());
        auto conIterator = renderFormConnections_.find(formId);
        if (conIterator == renderFormConnections_.end()) {
            HILOG_ERROR("Can not find formId in map.");
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        stopConnection = conIterator->second;
        renderFormConnectionSize = renderFormConnections_.size();
        for (auto iter = etsHosts_.begin(); iter != etsHosts_.end();) {
            iter->second.erase(formId);
            if (iter->second.empty()) {
                HILOG_INFO("All forms of the host have been removed, remove the host.");
                iter = etsHosts_.erase(iter);
            } else {
                ++iter;
            }
        }
        renderFormConnections_.erase(formId);
    }
    if (stopConnection == nullptr) {
        HILOG_ERROR("Can not find stopConnection in map.");
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
        HILOG_ERROR("formRecord.abilityName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    if (formRecord.bundleName.empty()) {
        HILOG_ERROR("formRecord.bundleName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int32_t userId = FormUtil::GetCurrentAccountId();
    std::string uid = std::to_string(userId) + formRecord.bundleName;
    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        auto conIterator = renderFormConnections_.find(formRecord.formId);
        if (conIterator != renderFormConnections_.end()) {
            auto connection = conIterator->second;
            if (connection == nullptr) {
                HILOG_ERROR("connection is null.");
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
            if (renderRemoteObj_ == nullptr) {
                HILOG_ERROR("renderRemoteObj_ is nullptr");
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
            auto remoteObject = renderRemoteObj_->AsObject();
            if (remoteObject == nullptr) {
                HILOG_ERROR("remoteObject is nullptr, can not get obj from renderRemoteObj.");
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
            FormTaskMgr::GetInstance().PostReleaseRenderer(formId, compId, uid, remoteObject);
            return ERR_OK;
        }
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormRenderMgrInner::AddConnection(int64_t formId, sptr<FormRenderConnection> connection)
{
    if (connection == nullptr) {
        HILOG_ERROR("Input FormRenderConnection is nullptr.");
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
            HILOG_WARN("Duplicate connection of formId: %{public}" PRId64 ", delete old connection", formId);
            renderFormConnectionSize = renderFormConnections_.size();
            oldConnection = renderFormConnections_[formId];
            renderFormConnections_[formId] = connection;
            connection->SetConnectId(connectKey);
        }
        HILOG_DEBUG("renderFormConnections size: %{public}zu.", renderFormConnections_.size());
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
        HILOG_DEBUG("Remove connection of formId: %{public}" PRId64 "", formId);
        renderFormConnections_.erase(formId);
    }
}

void FormRenderMgrInner::RerenderAllForms()
{
    HILOG_INFO("FRS is died, notify host.");
    renderRemoteObj_ = nullptr;

    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        atomicRerenderCount_ = renderFormConnections_.size();
        if (etsHosts_.empty() || renderFormConnections_.empty()) {
            HILOG_INFO("All hosts died or all connections erased, no need to rerender.");
            return;
        }
        HILOG_INFO("The forms need to rerender count: %{public}zu.", renderFormConnections_.size());
        for (auto &item : renderFormConnections_) {
            if (item.second == nullptr) {
                HILOG_ERROR("Connection is nullptr.");
                continue;
            }
            item.second->SetStateDisconnected();
        }
    }

    NotifyHostRenderServiceIsDead();
}

void FormRenderMgrInner::CleanFormHost(const sptr<IRemoteObject> &host)
{
    HILOG_INFO("Host is died or been removed, notify FormRenderService and remove host.");
    RemoveHostToken(host);
    if (renderRemoteObj_ == nullptr) {
        HILOG_WARN("renderRemoteObj is nullptr, render service may exit already.");
        return;
    }
    renderRemoteObj_->CleanFormHost(host);
}

void FormRenderMgrInner::AddRenderDeathRecipient(const sptr<IRemoteObject> &remoteObject)
{
    if (renderRemoteObj_) {
        HILOG_INFO("renderDeathRecipient is exist, no need to add again.");
        return;
    }

    HILOG_INFO("Get renderRemoteObj, add death recipient.");
    auto renderRemoteObj = iface_cast<IFormRender>(remoteObject);
    if (renderRemoteObj == nullptr) {
        HILOG_ERROR("renderRemoteObj is nullptr.");
        return;
    }

    if (renderDeathRecipient_ == nullptr) {
        renderDeathRecipient_ = new (std::nothrow)FormRenderRecipient([this]() {
            RerenderAllForms();
        });
    }
    if (!remoteObject->AddDeathRecipient(renderDeathRecipient_)) {
        HILOG_ERROR("AddDeathRecipient failed.");
        return;
    }
    SetRenderRemoteObj(renderRemoteObj);
}

inline ErrCode FormRenderMgrInner::ConnectRenderService(
    const sptr<FormRenderConnection> &connection, int32_t level) const
{
    if (connection == nullptr) {
        HILOG_INFO("connection is nullptr.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    Want want;
    want.SetElementName(Constants::FRS_BUNDLE_NAME, "ServiceExtension");
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    if (level > 0) {
        want.SetParam(DLP_INDEX, 1);
        want.SetParam(Constants::FRS_APP_INDEX, 1);
    }
    connection->SetStateConnecting();
    return FormAmsHelper::GetInstance().ConnectServiceAbility(want, connection);
}

void FormRenderMgrInner::DisconnectRenderService(const sptr<FormRenderConnection> connection, size_t size) const
{
    if (size == LAST_CONNECTION) {
        HILOG_INFO("This is the last connection, disconnect render service delay");
        FormAmsHelper::GetInstance().DisconnectServiceAbilityDelay(connection);
    } else {
        HILOG_DEBUG("Disconnect render service ability");
        FormAmsHelper::GetInstance().DisconnectServiceAbility(connection);
    }
}

void FormRenderMgrInner::OnRenderingBlock(const std::string &bundleName)
{
    HILOG_INFO("OnRenderingBlock called, bundleName: %{public}s.", bundleName.c_str());
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
        HILOG_DEBUG("Add host, current etsHosts.size: %{public}zu.", etsHosts_.size());
        std::unordered_set<int64_t> formIdSet;
        formIdSet.emplace(formId);
        etsHosts_.emplace(host, formIdSet);
    } else {
        HILOG_DEBUG("Add formId to host, current etsHosts.size: %{public}zu.", etsHosts_.size());
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
            HILOG_ERROR("Can not find host in etsHosts.");
            return;
        }
        auto formIdSet = iter->second;
        etsHosts_.erase(host);
        if (etsHosts_.empty()) {
            HILOG_DEBUG("etsHosts is empty, disconnect all connections size: %{public}zu.",
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
    std::unordered_map<sptr<IRemoteObject>, std::unordered_set<int64_t>, RemoteObjHash> hostsForNotify;
    {
        std::lock_guard<std::mutex> lock(resourceMutex_);
        HILOG_INFO("Notify hosts the render is dead, hosts.size: %{public}zu.", etsHosts_.size());
        auto tmpMap(etsHosts_);
        hostsForNotify.swap(tmpMap);
    }
    for (const auto &item : hostsForNotify) {
        auto hostClient = iface_cast<IFormHost>(item.first);
        if (hostClient == nullptr) {
            HILOG_ERROR("hostClient is nullptr");
            continue;
        }
        hostClient->OnError(ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED, "FormRenderService is dead.");
    }
}

sptr<IFormRender> FormRenderMgrInner::GetRenderRemoteObj() const
{
    return renderRemoteObj_;
}

void FormRenderMgrInner::SetRenderRemoteObj(sptr<IFormRender> remoteObject)
{
    renderRemoteObj_ = remoteObject;
}

int32_t FormRenderMgrInner::GetReRenderCount() const
{
    return atomicRerenderCount_;
}

ErrCode FormRenderMgrInner::RecycleForms(
    const std::vector<int64_t> &formIds, const Want &want, const sptr<IRemoteObject> &remoteObjectOfHost)
{
    HILOG_DEBUG("called.");
    if (renderRemoteObj_ == nullptr) {
        HILOG_ERROR("renderRemoteObj_ is nullptr");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    auto remoteObject = renderRemoteObj_->AsObject();
    if (remoteObject == nullptr) {
        HILOG_ERROR("remoteObject is nullptr, can not get obj from renderRemoteObj.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> lock(resourceMutex_);
    std::vector<int64_t> connectedForms;
    for (const int64_t &formId : formIds) {
        auto conIterator = renderFormConnections_.find(formId);
        if (conIterator != renderFormConnections_.end()) {
            auto connection = conIterator->second;
            if (connection == nullptr) {
                HILOG_ERROR("connection of %{public}" PRId64 " is null.", formId);
                continue;
            }
            connectedForms.emplace_back(formId);
        }
    }
    FormTaskMgr::GetInstance().PostRecycleForms(connectedForms, want, remoteObjectOfHost, remoteObject);
    return ERR_OK;
}

ErrCode FormRenderMgrInner::RecoverForms(const std::vector<int64_t> &formIds, const WantParams &wantParams)
{
    HILOG_DEBUG("called.");
    if (renderRemoteObj_ == nullptr) {
        HILOG_ERROR("renderRemoteObj_ is nullptr");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    auto remoteObject = renderRemoteObj_->AsObject();
    if (remoteObject == nullptr) {
        HILOG_ERROR("remoteObject is nullptr, can not get obj from renderRemoteObj.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    for (const int64_t &formId : formIds) {
        Want want;
        want.SetParams(wantParams);

        FormRecord formRecord;
        if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
            HILOG_ERROR("form record %{public}" PRId64 " not exist", formId);
            continue;
        }
        std::string uid = std::to_string(FormUtil::GetCurrentAccountId()) + formRecord.bundleName;
        want.SetParam(Constants::FORM_SUPPLY_UID, uid);

        std::lock_guard<std::mutex> lock(resourceMutex_);
        auto conIterator = renderFormConnections_.find(formId);
        if (conIterator != renderFormConnections_.end()) {
            auto connection = conIterator->second;
            if (connection == nullptr) {
                HILOG_ERROR("connection of %{public}" PRId64 " is null.", formId);
                continue;
            }
            want.SetParam(Constants::FORM_CONNECT_ID, connection->GetConnectId());

            std::string statusData;
            if (FormInfoRdbStorageMgr::GetInstance().LoadStatusData(std::to_string(formId), statusData) != ERR_OK) {
                HILOG_ERROR("read status data of %{public}" PRId64 " failed.", formId);
            }
            want.SetParam(Constants::FORM_STATUS_DATA, statusData);

            FormTaskMgr::GetInstance().PostRecoverForm(formId, want, remoteObject);
        } else {
            HILOG_ERROR("can't find connection of %{public}" PRId64, formId);
        }
    }
    return ERR_OK;
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
