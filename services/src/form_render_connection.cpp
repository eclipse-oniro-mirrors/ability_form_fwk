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

#include "form_render_connection.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_bms_helper.h"
#include "form_cache_mgr.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_supply_callback.h"
#include "form_render_mgr.h"
#include "form_task_mgr.h"
#include "form_util.h"
#include "ipc_skeleton.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
FormRenderConnection::FormRenderConnection(
    const FormRecord &formRecord, const WantParams &wantParams) : formRecord_(formRecord), wantParams_(wantParams)
{
    SetFormId(formRecord.formId);
    SetProviderKey(formRecord.bundleName, formRecord.abilityName);
}

void FormRenderConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_INFO("ConnectDone, formId:%{public}" PRId64, GetFormId());
    if (resultCode != ERR_OK) {
        HILOG_ERROR("%{public}s, abilityName:%{public}s, formId:%{public}" PRId64 ", resultCode:%{public}d",
           __func__, element.GetAbilityName().c_str(), GetFormId(), resultCode);
        return;
    }

    connectState_ = ConnectState::CONNECTED;
    int32_t compileMode = 0;
    if (!FormBmsHelper::GetInstance().GetCompileMode(formRecord_.bundleName, formRecord_.moduleName,
        FormUtil::GetCurrentAccountId(), compileMode)) {
        HILOG_ERROR("get compile mode failed.");
        return;
    }

    FormRecord newRecord(formRecord_);
    std::string cacheData;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    if (FormCacheMgr::GetInstance().GetData(formRecord_.formId, cacheData, imageDataMap)) {
        newRecord.formProviderInfo.SetFormDataString(cacheData);
        newRecord.formProviderInfo.SetImageDataMap(imageDataMap);
    }

    sptr<FormRenderConnection> connection(this);
    FormRenderMgr::GetInstance().AddConnection(GetFormId(), connection, newRecord.privacyLevel);
    FormRenderMgr::GetInstance().AddRenderDeathRecipient(remoteObject, newRecord.privacyLevel);
    Want want;
    want.SetParams(wantParams_);
    want.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
    want.SetParam(Constants::FORM_COMPILE_MODE_KEY, compileMode);
    FormTaskMgr::GetInstance().PostRenderForm(newRecord, std::move(want), remoteObject);
}

void FormRenderConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    HILOG_DEBUG("element:%{public}s, resultCode:%{public}d, connectState: %{public}d",
        element.GetURI().c_str(), resultCode, connectState_);
    // If connectState_ is CONNECTING, it means connect failed and host will try again, don't need to notify host
    if (resultCode && connectState_ == ConnectState::CONNECTING) {
        FormRenderMgr::GetInstance().RemoveConnection(GetFormId(), formRecord_.privacyLevel);
    }
    connectState_ = ConnectState::DISCONNECTED;
}

void FormRenderConnection::SetStateConnecting()
{
    connectState_ = ConnectState::CONNECTING;
}

void FormRenderConnection::SetStateDisconnected()
{
    connectState_ = ConnectState::DISCONNECTED;
}

void FormRenderConnection::UpdateWantParams(const WantParams &wantParams)
{
    wantParams_ = wantParams;
}
}  // namespace AppExecFwk
}  // namespace OHOS
