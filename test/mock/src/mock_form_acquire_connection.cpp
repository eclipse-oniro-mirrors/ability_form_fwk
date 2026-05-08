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

#include "form_provider/connection/form_acquire_connection.h"
#include "common/connection/form_ability_connection.h"

namespace OHOS {
namespace AppExecFwk {

FormAcquireConnection::FormAcquireConnection(const int64_t formId, const FormItemInfo &info,
    const WantParams &wantParams, const sptr<IRemoteObject> hostToken)
    : FormAbilityConnection(), info_(info), wantParams_(wantParams)
{
    SetFormId(formId);
}

void FormAcquireConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) {}

void FormAcquireConnection::SetFormAbilityConnectCb(std::function<void(const std::string &bundleName)> &&callback) {}

void FormAcquireConnection::SetFormAbilityDisconnectCb(std::function<void(const std::string &bundleName)> &&callback) {}

void FormAcquireConnection::OnFormAbilityConnectDoneCallback() {}

void FormAcquireConnection::OnFormAbilityDisconnectDoneCallback() {}

void FormAcquireConnection::OnPreConnectTask() {}

Want FormAcquireConnection::OnBuildTaskWant()
{
    Want want;
    return want;
}

void FormAcquireConnection::OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject) {}
} // namespace AppExecFwk
} // namespace OHOS
