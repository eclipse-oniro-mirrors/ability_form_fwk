/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "bms_mgr/form_bms_helper.h"
#include "form_mgr_errors.h"
#include "form_mgr/form_mgr_adapter.h"

namespace {
    bool g_mockGetAbilityInfoRet = true;
    bool g_mockGetAbilityInfoByActionRet = true;
}

void MockGetAbilityInfo(bool mockRet)
{
    g_mockGetAbilityInfoRet = mockRet;
}

void MockGetAbilityInfoByAction(bool mockRet)
{
    g_mockGetAbilityInfoByActionRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

bool FormBmsHelper::GetAbilityInfo(const AAFwk::Want &want, int32_t userId, AbilityInfo &abilityInfo)
{
    if (g_mockGetAbilityInfoRet) {
        abilityInfo.name = "name";
    }
    return g_mockGetAbilityInfoRet;
}

bool FormBmsHelper::GetAbilityInfoByAction(const std::string &action, int32_t userId,
    AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionAbilityInfo)
{
    if (g_mockGetAbilityInfoByActionRet) {
        abilityInfo.name = "name";
    }
    return g_mockGetAbilityInfoByActionRet;
}

ErrCode FormMgrAdapter::RequestPublishForm(Want &want, bool withFormBindingData,
    std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId,
    const std::vector<FormDataProxy> &formDataProxies, bool needCheckFormPermission)
{
    if (formId == 1) {
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    } else if (formId == 2) {
        return ERR_OK;
    }

    return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
}
} // namespace AppExecFwk
} // namespace OHOS
