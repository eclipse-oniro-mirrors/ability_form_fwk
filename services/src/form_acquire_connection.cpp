
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

#include "form_acquire_connection.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_supply_callback.h"
#include "form_task_mgr.h"
#include "form_util.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
FormAcquireConnection::FormAcquireConnection(const int64_t formId, const FormItemInfo &info,
    const WantParams &wantParams, const sptr<IRemoteObject> hostToken) : info_(info), wantParams_(wantParams)
{
    SetFormId(formId);
    SetProviderKey(info.GetProviderBundleName(), info.GetAbilityName());
    SetHostToken(hostToken);
}
/**
 * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
 * @param element service ability's ElementName.
 * @param remoteObject the session proxy of service ability.
 * @param resultCode ERR_OK on success, others on failure.
 */
void FormAcquireConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    HILOG_INFO("%{public}s called.", __func__);
    if (resultCode != ERR_OK) {
        HILOG_ERROR("%{public}s, abilityName:%{public}s, formId:%{public}" PRId64 ", resultCode:%{public}d",
           __func__, element.GetAbilityName().c_str(), GetFormId(), resultCode);
        return;
    }
    onFormAppConnect();
#ifdef RES_SCHEDULE_ENABLE
    OnFormAbilityConnectDoneCallback();
#endif
    sptr<FormAcquireConnection> connection(this);
    FormSupplyCallback::GetInstance()->AddConnection(connection);
    Want want;
    want.SetParams(wantParams_);
    FormUtil::CreateFormWant(info_.GetFormName(), info_.GetSpecificationId(), info_.IsTemporaryForm(), want);
    if (want.GetBoolParam(Constants::RECREATE_FORM_KEY, false)) {
        want.SetParam(Constants::ACQUIRE_TYPE, Constants::ACQUIRE_TYPE_RECREATE_FORM);
    } else {
        want.SetParam(Constants::ACQUIRE_TYPE, Constants::ACQUIRE_TYPE_CREATE_FORM);
    }
    want.SetParam(Constants::FORM_CONNECT_ID, this->GetConnectId());
    want.SetElementName(info_.GetDeviceId(), info_.GetProviderBundleName(),
        info_.GetAbilityName(), info_.GetModuleName());
    HILOG_DEBUG("%{public}s , deviceId: %{public}s, bundleName: %{public}s, abilityName: %{public}s.",
        __func__, info_.GetDeviceId().c_str(), info_.GetProviderBundleName().c_str(), info_.GetAbilityName().c_str());

    FormTaskMgr::GetInstance().PostAcquireTask(GetFormId(), want, remoteObject);
    if (GetHostToken() != nullptr) {
        SetProviderToken(remoteObject);
    }
}

/**
 * @brief OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
 * @param element service ability's ElementName.
 * @param resultCode ERR_OK on success, others on failure.
 */
void FormAcquireConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    FormAbilityConnection::OnAbilityDisconnectDone(element, resultCode);
#ifdef RES_SCHEDULE_ENABLE
    OnFormAbilityDisconnectDoneCallback();
#endif
}

void FormAcquireConnection::SetFormAbilityConnectCb(
    std::function<void(const std::string &bundleName)> &&callback)
{
    onFormAblityConnectCb_ = std::move(callback);
}

void FormAcquireConnection::SetFormAbilityDisconnectCb(
    std::function<void(const std::string &bundleName)> &&callback)
{
    onFormAblityDisconnectCb_ = std::move(callback);
}

void FormAcquireConnection::OnFormAbilityConnectDoneCallback()
{
    if (!onFormAblityConnectCb_) {
        HILOG_ERROR("Empty form ability connect callback!");
        return;
    }
    onFormAblityConnectCb_(GetBundleName());
}

void FormAcquireConnection::OnFormAbilityDisconnectDoneCallback()
{
    if (!onFormAblityDisconnectCb_) {
        HILOG_ERROR("Empty form ability disconnect callback!");
        return;
    }
    onFormAblityDisconnectCb_(GetBundleName());
}
} // namespace AppExecFwk
} // namespace OHOS