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

#include "form_render/form_render_connection.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_cache_mgr.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_provider/form_supply_callback.h"
#include "form_render/form_render_mgr.h"
#include "status_mgr_center/form_status_task_mgr.h"
#include "form_host/form_host_task_mgr.h"
#include "common/util/form_util.h"
#include "ipc_skeleton.h"
#include "want.h"
#include "feature/memory_mgr/form_render_report.h"

const int32_t MAX_FAILED_TIMES = 5;

namespace OHOS {
namespace AppExecFwk {
FormRenderConnection::FormRenderConnection(
    const FormRecord &formRecord, const WantParams &wantParams) : formRecord_(formRecord), wantParams_(wantParams)
{
    SetFormId(formRecord.formId);
    SetProviderKey(formRecord.bundleName, formRecord.abilityName, formRecord.providerUserId);
}

void FormRenderConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_INFO("ConnectDone, formId:%{public}" PRId64, GetFormId());
    if (resultCode != ERR_OK) {
        HILOG_ERROR("abilityName:%{public}s, formId:%{public}" PRId64 ", resultCode:%{public}d",
            element.GetAbilityName().c_str(), GetFormId(), resultCode);
        return;
    }
    if (remoteObject == nullptr || remoteObject->IsObjectDead()) {
        failedTimes++;
        HILOG_WARN("remoteObject is null or dead, formId:%{public}" PRId64 ", failedTimes:%{public}d",
            GetFormId(), failedTimes);
        if (failedTimes <= MAX_FAILED_TIMES) {
            FormHostTaskMgr::GetInstance().PostConnectFRSFailedTaskToHost(
                GetFormId(), ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED);
        }
        return;
    }
    FormRenderReport::GetInstance().RecordFRSStart();
    connectState_ = ConnectState::CONNECTED;
    failedTimes = 0;
    int32_t compileMode = 0;
    if (!FormBmsHelper::GetInstance().GetCompileMode(formRecord_.bundleName, formRecord_.moduleName,
        formRecord_.providerUserId, compileMode)) {
        HILOG_ERROR("get compile mode failed");
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
    FormRenderMgr::GetInstance().AddConnection(GetFormId(), connection, newRecord);
    FormRenderMgr::GetInstance().AddRenderDeathRecipient(remoteObject, newRecord);
    Want want;
    want.SetParams(wantParams_);
    want.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
    want.SetParam(Constants::FORM_COMPILE_MODE_KEY, compileMode);
    FormStatusTaskMgr::GetInstance().PostRenderForm(newRecord, std::move(want), remoteObject);
}

void FormRenderConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    HILOG_INFO("formId:%{public}" PRId64 ", resultCode:%{public}d, connectState:%{public}d",
        GetFormId(), resultCode, connectState_);
    // If connectState_ is CONNECTING, it means connect failed and host will try again, don't need to notify host
    if (resultCode && connectState_ == ConnectState::CONNECTING) {
        FormRenderMgr::GetInstance().RemoveConnection(GetFormId(), formRecord_);
    }
    connectState_ = ConnectState::DISCONNECTED;
    failedTimes = 0;
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

void FormRenderConnection::UpdateFormRecord(const FormRecord &formRecord)
{
    formRecord_ = formRecord;
}
}  // namespace AppExecFwk
}  // namespace OHOS
