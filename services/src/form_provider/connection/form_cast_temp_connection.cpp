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

#include "form_provider/connection/form_cast_temp_connection.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_provider/form_provider_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {

FormCastTempConnection::FormCastTempConnection(const int64_t formId, const std::string &bundleName,
    const std::string &abilityName, const int32_t userId)
{
    SetFormId(formId);
    SetProviderKey(bundleName, abilityName, userId);
}

void FormCastTempConnection::OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject)
{
    FormProviderTaskMgr::GetInstance().PostCastTempTask(GetFormId(), want, remoteObject);
}

}  // namespace AppExecFwk
}  // namespace OHOS