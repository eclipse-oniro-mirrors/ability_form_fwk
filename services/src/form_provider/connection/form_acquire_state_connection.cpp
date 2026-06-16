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

#include "form_provider/connection/form_acquire_state_connection.h"

#include "fms_log_wrapper.h"
#include "form_provider/form_provider_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {

FormAcquireStateConnection::FormAcquireStateConnection(const std::string &bundleName,
    const std::string &abilityName, const Want &want, std::string &provider, const int32_t userId)
    : want_(want), provider_(provider)
{
    SetProviderKey(bundleName, abilityName, userId);
}

void FormAcquireStateConnection::OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    FormProviderTaskMgr::GetInstance().PostAcquireStateTask(want_, provider_, want, remoteObject);
}

}  // namespace AppExecFwk
}  // namespace OHOS