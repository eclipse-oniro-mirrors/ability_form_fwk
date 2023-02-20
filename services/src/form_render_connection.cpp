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

#include "form_bms_helper.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_supply_callback.h"
#include "form_render_mgr.h"
#include "form_task_mgr.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "ipc_skeleton.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
FormRenderConnection::FormRenderConnection(const FormRecord &formRecord,
    const WantParams &wantParams) : formRecord_(formRecord), wantParams_(wantParams)
{
    SetFormId(formRecord.formId);
    SetProviderKey(formRecord.bundleName, formRecord.abilityName);
}

void FormRenderConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_INFO("ConnectDone");
    if (resultCode != ERR_OK) {
        HILOG_ERROR("%{public}s, abilityName:%{public}s, formId:%{public}" PRId64 ", resultCode:%{public}d",
           __func__, element.GetAbilityName().c_str(), GetFormId(), resultCode);
        return;
    }

    int32_t compileMode = 0;
    if (!FormBmsHelper::GetInstance().GetCompileMode(formRecord_.bundleName, formRecord_.moduleName,
        FormUtil::GetCurrentAccountId(), compileMode)) {
        HILOG_INFO("get compile mode failed.");
        return;
    }

    FormRenderMgr::GetInstance().AddConnection(GetFormId(), this);
    FormRenderMgr::GetInstance().AddRenderDeathRecipient(remoteObject);
    Want want;
    want.SetParams(wantParams_);
    want.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
    want.SetParam(Constants::FORM_COMPILE_MODE_KEY, compileMode);
    FormTaskMgr::GetInstance().PostRenderForm(formRecord_, want, remoteObject);
}

void FormRenderConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    HILOG_DEBUG("%{public}s, element:%{public}s, resultCode:%{public}d",
        __func__, element.GetURI().c_str(), resultCode);
    if (resultCode) {
        FormRenderMgr::GetInstance().HandleConnectFailed(
            formRecord_.formId, ERR_APPEXECFWK_FORM_CONNECT_FORM_RENDER_FAILED);
    }
}

void FormRenderConnection::UpdateWantParams(const WantParams &wantParams)
{
    wantParams_ = wantParams;
}
}  // namespace AppExecFwk
}  // namespace OHOS
