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

#include "ams_mgr/form_ams_helper.h"

#include "form_mgr_errors.h"

namespace {
    bool g_mockConnectServiceAbilityRet = true;
    bool g_mockDisconnectServiceAbilityRet = true;
    bool g_mockStartAbilityOnlyUIAbilityRet = true;
}

void MockConnectServiceAbility(bool mockRet)
{
    g_mockConnectServiceAbilityRet = mockRet;
}

void MockDisconnectServiceAbility(bool mockRet)
{
    g_mockDisconnectServiceAbilityRet = mockRet;
}

void MockStartAbilityOnlyUIAbility(bool mockRet)
{
    g_mockStartAbilityOnlyUIAbilityRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormAmsHelper::FormAmsHelper()
{}

FormAmsHelper::~FormAmsHelper()
{}

ErrCode FormAmsHelper::DisconnectServiceAbility(const sptr<AAFwk::IAbilityConnection> &connect)
{
    if (!g_mockDisconnectServiceAbilityRet) {
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

ErrCode FormAmsHelper::ConnectServiceAbility(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect)
{
    if (true == g_mockConnectServiceAbilityRet) {
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

ErrCode FormAmsHelper::ConnectServiceAbilityWithUserId(
    const Want &want, const sptr<AAFwk::IAbilityConnection> &connect, int32_t userId)
{
    if (true == g_mockConnectServiceAbilityRet) {
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}

ErrCode FormAmsHelper::StartAbilityOnlyUIAbility(Want &want, const int32_t userId)
{
    if (!g_mockStartAbilityOnlyUIAbilityRet) {
        return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
