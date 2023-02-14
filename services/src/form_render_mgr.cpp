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

#include "form_render_mgr.h"

#include "form_ams_helper.h"
#include "form_bms_helper.h"
#include "form_constants.h"
#include "form_data_mgr.h"
#include "form_host_interface.h"
#include "form_mgr_errors.h"
#include "form_supply_callback.h"
#include "form_task_mgr.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr int32_t CALLING_UID_TRANSFORM_DIVISOR = 200000;
}
using Want = OHOS::AAFwk::Want;
FormRenderMgr::FormRenderMgr()
{
}
FormRenderMgr::~FormRenderMgr()
{
}
ErrCode FormRenderMgr::RenderForm(
    const FormRecord &formRecord, const WantParams &wantParams, const sptr<IRemoteObject> &hostToken)
{
    HILOG_INFO("RenderForm formId: %{public}" PRId64 "", formRecord.formId);
    if (formRecord.uiSyntax != FormType::ETS) {
        return ERR_OK;
    }

    if (formRecord.formId <= 0) {
        HILOG_ERROR("%{public}s fail, formId should be greater than 0.", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = callingUid / CALLING_UID_TRANSFORM_DIVISOR;
    int32_t bundleUid = FormBmsHelper::GetInstance().GetUidByBundleName(formRecord.bundleName, userId);
    Want want;
    want.SetParams(wantParams);
    want.SetParam(Constants::FORM_SUPPLY_UID, bundleUid);
    if (atomicRerenderCount_ > 0) {
        --atomicRerenderCount_;
    } else {
        atomicRerenderCount_ = 0;
    }
    if (hostToken) {
        HILOG_DEBUG("Add host token");
        AddHostToken(hostToken);
        want.SetParam(Constants::PARAM_FORM_HOST_TOKEN, hostToken);
    }

    {
        std::lock_guard<std::mutex> lock(conMutex_);
        HILOG_DEBUG("renderFormConnections_ size: %{public}zu.", renderFormConnections_.size());
        auto conIterator = renderFormConnections_.find(formRecord.formId);
        if (conIterator != renderFormConnections_.end()) {
            auto connection = conIterator->second;
            if (connection == nullptr) {
                HILOG_ERROR("connection is null.");
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
            if (renderRemoteObj_ == nullptr) {
                connection->UpdateWantParams(want.GetParams());
                ErrCode ret = ConnectRenderService(connection);
                HILOG_INFO("renderRemoteObj is nullptr, render may exit, need reconnect, ret: %{public}d.", ret);
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
    }
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, want.GetParams());

    if (formRenderConnection == nullptr) {
        HILOG_ERROR("formRenderConnection is null.");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    ErrCode errorCode = ConnectRenderService(formRenderConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("%{public}s fail, ConnectServiceAbility failed.", __func__);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

ErrCode FormRenderMgr::UpdateRenderingForm(int64_t formId, const FormProviderData &formProviderData,
    const WantParams &wantParams, bool mergeData)
{
    HILOG_DEBUG("RenderForm with formId.");
    FormRecord formRecord;
    bool isGetFormRecord = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isGetFormRecord) {
        HILOG_ERROR("%{public}s fail, not exist such form, formId:%{public}" PRId64 "", __func__, formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
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

    Want want;
    want.SetParams(wantParams);
    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::UPDATE_RENDERING_FORM);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = callingUid / CALLING_UID_TRANSFORM_DIVISOR;
    int32_t bundleUid = FormBmsHelper::GetInstance().GetUidByBundleName(formRecord.bundleName, userId);
    want.SetParam(Constants::FORM_SUPPLY_UID, bundleUid);
    {
        std::lock_guard<std::mutex> lock(conMutex_);
        auto conIterator = renderFormConnections_.find(formRecord.formId);
        if (conIterator != renderFormConnections_.end()) {
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
            want.SetParam(Constants::FORM_CONNECT_ID, connection->GetConnectId());
            FormTaskMgr::GetInstance().PostRenderForm(formRecord, want, remoteObject);
            return ERR_OK;
        }
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormRenderMgr::StopRenderingForm(int64_t formId, const FormRecord &formRecord)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    if (formRecord.uiSyntax != FormType::ETS) {
        return ERR_OK;
    }

    if (formRecord.abilityName.empty()) {
        HILOG_ERROR("%{public}s, formRecord.abilityName is empty.", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (formRecord.bundleName.empty()) {
        HILOG_ERROR("%{public}s, formRecord.bundleName is empty.", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    Want want;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = callingUid / CALLING_UID_TRANSFORM_DIVISOR;
    int32_t bundleUid = FormBmsHelper::GetInstance().GetUidByBundleName(formRecord.bundleName, userId);
    want.SetParam(Constants::FORM_SUPPLY_UID, bundleUid);
    {
        std::lock_guard<std::mutex> lock(conMutex_);
        auto conIterator = renderFormConnections_.find(formRecord.formId);
        if (conIterator != renderFormConnections_.end()) {
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
            want.SetParam(Constants::FORM_CONNECT_ID, connection->GetConnectId());
            FormTaskMgr::GetInstance().PostStopRenderingForm(formRecord, want, remoteObject);
            return ERR_OK;
        }
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode FormRenderMgr::RenderFormCallback(int64_t formId, const Want &want)
{
    HILOG_INFO("%{public}s called.", __func__);
    return ERR_OK;
}

ErrCode FormRenderMgr::StopRenderingFormCallback(int64_t formId, const Want &want)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::lock_guard<std::mutex> lock(conMutex_);
    HILOG_DEBUG("renderFormConnections_ size: %{public}zu.", renderFormConnections_.size());
    auto conIterator = renderFormConnections_.find(formId);
    if (conIterator == renderFormConnections_.end()) {
        HILOG_ERROR("Can not find formId in map.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    sptr<FormAbilityConnection> stopConnection = conIterator->second;
    if (stopConnection == nullptr) {
        HILOG_ERROR("Can not find stopConnection in map.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    FormAmsHelper::GetInstance().DisconnectServiceAbility(stopConnection);
    renderFormConnections_.erase(formId);
    return ERR_OK;
}

ErrCode FormRenderMgr::AddConnection(int64_t formId, sptr<FormRenderConnection> connection)
{
    HILOG_INFO("%{public}s called.", __func__);
    if (connection == nullptr) {
        HILOG_ERROR("Input FormRenderConnection is nullptr.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    {
        int32_t connectKey = static_cast<int32_t>(FormUtil::GetCurrentMillisecond());
        std::lock_guard<std::mutex> lock(conMutex_);
        if (connectKey <= maxConnectKey) {
            connectKey = maxConnectKey + 1;
            maxConnectKey = connectKey;
        }
        connection->SetConnectId(connectKey);
        auto conIterator = renderFormConnections_.find(formId);
        if (conIterator == renderFormConnections_.end()) {
            renderFormConnections_.emplace(formId, connection);
            conIterator = renderFormConnections_.begin();
        }

        renderFormConnections_[formId] = connection;
        HILOG_DEBUG("renderFormConnections size: %{public}zu.", renderFormConnections_.size());
    }
    return ERR_OK;
}

ErrCode FormRenderMgr::RemoveConnection(int64_t formId)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::lock_guard<std::mutex> lock(conMutex_);
    auto conIterator = renderFormConnections_.find(formId);
    if (conIterator != renderFormConnections_.end()) {
        FormAmsHelper::GetInstance().DisconnectServiceAbility(conIterator->second);
    }
    renderFormConnections_.erase(formId);

    HILOG_DEBUG("renderFormConnections size: %{public}zu.", renderFormConnections_.size());
    return ERR_OK;
}

void FormRenderMgr::RerenderAllForms()
{
    HILOG_INFO("Render is dead.");
    renderDeathRecipient_ = nullptr;
    renderRemoteObj_ = nullptr;
    
    {
        std::lock_guard<std::mutex> lock(conMutex_);
        atomicRerenderCount_ = renderFormConnections_.size();
        if (etsHosts_.empty() || renderFormConnections_.empty()) {
            HILOG_INFO("All hosts died or all connections erased, no need to rerender.");
            return;
        }
        HILOG_INFO("The forms need to rerender count: %{public}zu.", renderFormConnections_.size());
    }

    NotifyHostRenderIsDead();
}

void FormRenderMgr::HandleHostDied(const sptr<IRemoteObject> &host)
{
    HILOG_INFO("Host is died, notify FormRenderService and remove host.");
    RemoveHostToken(host);
    if (renderRemoteObj_ == nullptr) {
        HILOG_WARN("renderRemoteObj is nullptr, render service may exit already.");
        return;
    }
    renderRemoteObj_->CleanFormHost(host);
}

void FormRenderMgr::AddRenderDeathRecipient(const sptr<IRemoteObject> &remoteObject)
{
    if (renderDeathRecipient_) {
        HILOG_INFO("renderDeathRecipient is exist, no need to add again.");
        return;
    }

    HILOG_INFO("Get renderRemoteObj, add death recipient.");
    auto renderRemoteObj = iface_cast<IFormRender>(remoteObject);
    if (renderRemoteObj == nullptr) {
        HILOG_ERROR("renderRemoteObj is nullptr.");
        return;
    }
    renderRemoteObj_ = renderRemoteObj;

    renderDeathRecipient_ = new FormRenderRecipient([]() {
        FormRenderMgr::GetInstance().RerenderAllForms();
    });
    remoteObject->AddDeathRecipient(renderDeathRecipient_);
}

inline ErrCode FormRenderMgr::ConnectRenderService(const sptr<AAFwk::IAbilityConnection> &connection) const
{
    Want want;
    want.SetElementName("com.ohos.formrenderservice", "ServiceExtension");
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    return FormAmsHelper::GetInstance().ConnectServiceAbility(want, connection);
}

bool FormRenderMgr::IsNeedRender(int64_t formId)
{
    FormRecord formRecord;
    bool isGetFormRecord = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isGetFormRecord) {
        HILOG_ERROR("%{public}s fail, not exist such form, formId:%{public}" PRId64 "", __func__, formId);
        return false;
    }
    if (formRecord.uiSyntax != FormType::ETS) {
        HILOG_DEBUG("%{public}s fail, no need render, formId:%{public}" PRId64 "", __func__, formId);
        return false;
    }
    return true;
}

inline void FormRenderMgr::AddHostToken(const sptr<IRemoteObject> &host)
{
    HILOG_DEBUG("Add host, current etsHosts.size: %{public}zu.", etsHosts_.size());
    {
        std::lock_guard<std::mutex> lock(hostsMutex_);
        etsHosts_.emplace(host);
    }
}

inline void FormRenderMgr::RemoveHostToken(const sptr<IRemoteObject> &host)
{
    HILOG_DEBUG("Remove host, current etsHosts.size: %{public}zu.", etsHosts_.size());
    {
        std::lock_guard<std::mutex> lock(hostsMutex_);
        etsHosts_.erase(host);
        if (etsHosts_.empty()) {
            HILOG_DEBUG("etsHosts is empty, disconnect all connections.");
            std::lock_guard<std::mutex> lock(conMutex_);
            for (const auto &item : renderFormConnections_) {
                FormAmsHelper::GetInstance().DisconnectServiceAbility(item.second);
            }
        }
    }
}

void FormRenderMgr::NotifyHostRenderIsDead() const
{
    HILOG_INFO("Notify hosts the render is dead, hosts.size: %{public}zu.", etsHosts_.size());
    for (const auto &host : etsHosts_) {
        auto hostClient = iface_cast<IFormHost>(host);
        if (hostClient == nullptr) {
            HILOG_ERROR("hostClient is nullptr");
            continue;
        }
        hostClient->OnError(ERR_APPEXECFWK_FORM_CONNECT_FORM_RENDER_FAILED, "Connect FormRenderService failed");
    }
}

bool FormRenderMgr::IsRerenderForRenderDied(int64_t formId)
{
    bool ret = IsNeedRender(formId) && (atomicRerenderCount_ > 0);
    HILOG_DEBUG("Is need to rerender: %{public}d.", ret);
    return ret;
}

void FormRenderRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_ERROR("Recv FormRenderService death notice");
    
    if (handler_) {
        handler_();
    }
}

FormRenderRecipient::FormRenderRecipient(RemoteDiedHandler handler) : handler_(handler) {}

FormRenderRecipient::~FormRenderRecipient() {}
} // namespace AppExecFwk
} // namespace OHOS
