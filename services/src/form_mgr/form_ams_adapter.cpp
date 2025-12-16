/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "form_mgr/form_ams_adapter.h"

#include "form_mgr_errors.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {
FormAmsAdapter::FormAmsAdapter()
{
    HILOG_DEBUG("call");
}
FormAmsAdapter::~FormAmsAdapter()
{
    HILOG_DEBUG("call");
}

ErrCode FormAmsAdapter::StartUIAbilityByFms(const int32_t uid, const Want &want)
{
    Want securedWant(want);
    std::string dstAbilityName = securedWant.GetElement().GetAbilityName();
    if (dstAbilityName.empty()) {
        HILOG_ERROR("bundleName or abilityName is empty");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    std::string bundleName;
    auto ret = FormBmsHelper::GetInstance().GetBundleNameByUid(uid, bundleName);
    if (ret != ERR_OK) {
        HILOG_ERROR("get BundleName failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    securedWant.SetBundle(bundleName);
    AbilityInfo abilityInfo;
    int32_t userId = FormUtil::GetCallerUserId(uid);
    bool success = FormBmsHelper::GetInstance().GetAbilityInfo(securedWant, userId, abilityInfo);
    if (!success) {
        HILOG_ERROR("get ability info failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    if (abilityInfo.type != AbilityType::PAGE) {
        HILOG_ERROR("target ability is not UIAbility");
        return ERR_APPEXECFWK_FORM_NOT_UI_ABILITY;
    }
    ErrCode retCode = FormAmsHelper::GetInstance().StartAbility(securedWant, userId);
    if (retCode != ERR_OK) {
        HILOG_ERROR("StartAbility failed, code:%{public}d", retCode);
    }
    return retCode;
}
}  // namespace AppExecFwk
}  // namespace OHOS
