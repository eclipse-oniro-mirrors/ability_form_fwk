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
#include "form_constants.h"
#include "form_data_mgr.h"
#include "form_mgr_errors.h"
#include "form_render_connection.h"
#include "form_stop_rendering_connection.h"
#include "form_supply_callback.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
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

    sptr<IAbilityConnection> formRenderConnection;
    auto conIterator = renderFormConnections_.find(formRecord.formId);
    if (conIterator != renderFormConnections_.end()) {
        auto connection = conIterator->second.begin();
        formRenderConnection = *connection;
    } else {
        formRenderConnection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    }
    
    if (formRenderConnection == nullptr) {
        HILOG_ERROR("formRenderConnection is null.");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    Want want;
    want.SetElementName("com.ohos.formrenderservice", "ServiceExtension");
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, formRenderConnection);
    if (errorCode != ERR_OK) {
        HILOG_ERROR("%{public}s fail, ConnectServiceAbility failed.", __func__);
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
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

    sptr<IAbilityConnection> formStopRenderingConnection = new (std::nothrow) FormStopRenderingConnection(formRecord,
            formRecord.bundleName, formRecord.abilityName);
    if (formStopRenderingConnection == nullptr) {
        HILOG_ERROR("formStopRenderingConnection is null.");
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }

    Want want;
    want.SetElementName("com.ohos.formrenderservice", "ServiceExtension");
    want.AddFlags(Want::FLAG_ABILITY_FORM_ENABLED);
    ErrCode errorCode = FormAmsHelper::GetInstance().ConnectServiceAbility(want, formStopRenderingConnection);
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
    auto connectId = want.GetIntParam(Constants::FORM_CONNECT_ID, 0);
    {
        std::lock_guard<std::mutex> lock(conMutex_);
        auto conIterator = renderFormConnections_.find(formId);
        for (auto &conn : conIterator->second) {
            if (conn->GetConnectId() == connectId) {
                FormAmsHelper::GetInstance().DisconnectServiceAbility(conn);
                std::unordered_set<sptr<FormAbilityConnection>, FormAbilityConHash> &connection = conIterator->second;
                connection.erase(conn);
                break;
            }
        }
    }
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
        }
        connection->SetConnectId(connectKey);
        auto conIterator = renderFormConnections_.find(formId);
        if (conIterator == renderFormConnections_.end()) {
            renderFormConnections_.emplace(formId, std::unordered_set<sptr<FormAbilityConnection>, FormAbilityConHash>());
            conIterator = renderFormConnections_.begin();
        }
        conIterator->second.emplace(connection);
    }
    HILOG_INFO("%{public}s end.", __func__);
    return ERR_OK;
}

ErrCode FormRenderMgr::RemoveConnection(int64_t formId)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    {
        std::lock_guard<std::mutex> lock(conMutex_);
        auto conIterator = renderFormConnections_.find(formId);
        for (auto &conn : conIterator->second) {
            FormAmsHelper::GetInstance().DisconnectServiceAbility(conn);
        }
        renderFormConnections_.erase(formId);
    }
    HILOG_INFO("%{public}s end.", __func__);
    return ERR_OK;
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
} // namespace AppExecFwk
} // namespace OHOS