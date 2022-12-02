/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "form_ams_helper.h"
#include "form_mgr_errors.h"

namespace {
    bool g_mockConnectServiceAbilityRet = true;
}

void MockConnectServiceAbility(bool mockRet)
{
    g_mockConnectServiceAbilityRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormAmsHelper::FormAmsHelper()
{}

FormAmsHelper::~FormAmsHelper()
{}

ErrCode FormAmsHelper::ConnectServiceAbility(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect)
{
    if (g_mockConnectServiceAbilityRet == false) {
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    } else {
        return ERR_OK;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
