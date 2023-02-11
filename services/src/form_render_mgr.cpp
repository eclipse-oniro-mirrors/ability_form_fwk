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
#include "form_stop_rendering_connection.h"
#include "form_supply_callback.h"
#include "form_task_mgr.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr int32_t MAX_RECONNECT_COUNT = 3;
    constexpr int32_t ERROR_CODE_CONNECT_RENDER = -1;
    const char *ERROR_MSG_CONNECT_RENDER = "Connect RenderService failed";
    constexpr int32_t CALLING_UID_TRANSFORM_DIVISOR = 200000;
}
using Want = OHOS::AAFwk::Want;
FormRenderMgr::FormRenderMgr()
{
}
FormRenderMgr::~FormRenderMgr()
{
}
ErrCode FormRenderMgr::RenderForm(const FormRecord &formRecord, const WantParams &wantParams)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    if (formRecord.uiSyntax != FormType::ETS) {
        return ERR_OK;
    }

    if (formRecord.formId <= 0) {
        HILOG_ERROR("%{public}s fail, formId should be greater than 0", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    {
        std::lock_guard<std::mutex> lock(conMutex_);
        auto conIterator = renderFormConnections_.find(formRecord.formId);
        if (conIterator != renderFormConnections_.end()) {
            auto connection = conIterator->second.first;
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
            SecondFormRenderConnect(formRecord, wantParams, remoteObject, connection->GetConnectId());
            return ERR_OK;
        }
    }
    auto formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    
    AddHostToken(formRecord.formId);

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

void FormRenderMgr::SecondFormRenderConnect(const FormRecord &formRecord, const WantParams &wantParams,
    const sptr<IRemoteObject> &remoteObject, int32_t connectId)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    int32_t userId = callingUid / CALLING_UID_TRANSFORM_DIVISOR;
    int32_t bundleUid = FormBmsHelper::GetInstance().GetUidByBundleName(formRecord.bundleName, userId);
    Want want;
    want.SetParams(wantParams);
    want.SetParam(Constants::FORM_SUPPLY_UID, bundleUid);
    want.SetParam(Constants::FORM_CONNECT_ID, connectId);
    FormTaskMgr::GetInstance().PostRenderForm(formRecord, want, remoteObject);
}

ErrCode FormRenderMgr::RenderForm(int64_t formId, const FormProviderInfo &formProviderInfo,
    const WantParams &wantParams)
{
    FormRecord formRecord;
    bool isGetFormRecord = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!isGetFormRecord) {
        HILOG_ERROR("%{public}s fail, not exist such form, formId:%{public}" PRId64 "", __func__, formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    formRecord.formProviderInfo = formProviderInfo;

    return RenderForm(formRecord, wantParams);
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

    sptr<IAbilityConnection> formStopRenderingConnection =
        new (std::nothrow) FormStopRenderingConnection(formRecord, formRecord.bundleName, formRecord.abilityName);
    if (formStopRenderingConnection == nullptr) {
        HILOG_ERROR("formStopRenderingConnection is null.");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    ErrCode errorCode = ConnectRenderService(formStopRenderingConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("%{public}s fail, ConnectServiceAbility failed.", __func__);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
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
    auto conIterator = renderFormConnections_.find(formId);
    if (conIterator == renderFormConnections_.end()) {
        HILOG_ERROR("Can not find formId in map.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    sptr<FormAbilityConnection> stopConnection = conIterator->second.second;
    if (stopConnection == nullptr) {
        HILOG_ERROR("Can not find stopConnection in map.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    FormAmsHelper::GetInstance().DisconnectServiceAbility(stopConnection);
    conIterator->second.second = nullptr;

    return ERR_OK;
}

ErrCode FormRenderMgr::AddConnection(int64_t formId, sptr<FormAbilityConnection> connection)
{
    HILOG_INFO("%{public}s called.", __func__);
    if (connection == nullptr) {
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
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
            renderFormConnections_.emplace(formId, RenderConnectionPair());
            conIterator = renderFormConnections_.begin();
        }
        renderFormConnections_[formId].first = connection;
    }
    HILOG_DEBUG("%{public}s end.", __func__);
    return ERR_OK;
}

ErrCode FormRenderMgr::RemoveConnection(int64_t formId)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::lock_guard<std::mutex> lock(conMutex_);
    auto conIterator = renderFormConnections_.find(formId);
    if (conIterator != renderFormConnections_.end()) {
        FormAmsHelper::GetInstance().DisconnectServiceAbility(conIterator->second.first);
        FormAmsHelper::GetInstance().DisconnectServiceAbility(conIterator->second.second);
    }
    renderFormConnections_.erase(formId);

    HILOG_DEBUG("%{public}s end.", __func__);
    return ERR_OK;
}

void FormRenderMgr::ReconnectRenderService()
{
    HILOG_INFO("Render is died, reconnect.");
    renderDeathRecipient_ = nullptr;
    renderRemoteObj_ = nullptr;
    if (++reconnectCount_ > MAX_RECONNECT_COUNT) {
        HILOG_ERROR("Reconnect count is reach MAX, NotifyHostConnectRenderFailed");
        NotifyHostConnectRenderFailed();
        return;
    }
    if (reconnectRenderConnection_ == nullptr) {
        FormRecord formRecord;
        WantParams wantParams;
        reconnectRenderConnection_ = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
        if (reconnectRenderConnection_ == nullptr) {
            HILOG_ERROR("Create reconnectRenderConnection failed.");
            return;
        }
        reconnectRenderConnection_->SetReconnectFlag();
    }
    auto ret = ConnectRenderService(reconnectRenderConnection_);
    // If ret != 0, no need to wait callback, just reconnect again.
    if (ret) {
        ReconnectRenderService();
        return;
    }
}

void FormRenderMgr::RerenderAll()
{
    HILOG_INFO("Reconnect render success, rerender all forms.");
    reconnectCount_ = 0;
    std::lock_guard<std::mutex> lock(conMutex_);
    for (const auto &item : renderFormConnections_) {
        auto renderConnection = item.second.first;
        ConnectRenderService(renderConnection);
    }
    FormAmsHelper::GetInstance().DisconnectServiceAbility(reconnectRenderConnection_);
}

void FormRenderMgr::AddRenderDeathRecipient(const sptr<IRemoteObject> &remoteObject)
{
    if (renderDeathRecipient_) {
        return;
    }
    HILOG_INFO("Get renderRemoteObj, add death recipient.");
    auto renderRemoteObj = iface_cast<IFormRender>(remoteObject);
    if (renderRemoteObj == nullptr) {
        HILOG_ERROR("renderRemoteObj is nullptr.");
        return;
    }
    if (renderRemoteObj_ == nullptr) {
        renderRemoteObj_ = renderRemoteObj;
    }

    renderDeathRecipient_ = new FormRenderRecipient([]() {
        FormRenderMgr::GetInstance().ReconnectRenderService();
    });
    auto renderService = renderRemoteObj_->AsObject();
    if (renderService == nullptr) {
        HILOG_ERROR("renderService is nullptr, can not get obj from renderRemoteObj.");
        return;
    }
    renderService->AddDeathRecipient(renderDeathRecipient_);
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

inline void FormRenderMgr::AddHostToken(int64_t formId)
{
    std::vector<sptr<IRemoteObject>> formHostObjs;
    FormDataMgr::GetInstance().GetFormHostRemoteObj(formId, formHostObjs);

    {
        std::lock_guard<std::mutex> lock(hostsMutex_);
        for (const auto &host : formHostObjs) {
            etsHosts_.emplace(host);
        }
    }
}

inline void FormRenderMgr::RemoveHostToken(const sptr<IRemoteObject> &host)
{
    {
        std::lock_guard<std::mutex> lock(hostsMutex_);
        etsHosts_.erase(host);
    }
}

void FormRenderMgr::NotifyHostConnectRenderFailed() const
{
    for (const auto &host : etsHosts_) {
        auto hostClient = iface_cast<IFormHost>(host);
        if (hostClient == nullptr) {
            HILOG_ERROR("hostClient is nullptr");
            continue;
        }
        hostClient->OnError(ERROR_CODE_CONNECT_RENDER, ERROR_MSG_CONNECT_RENDER);
    }
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
