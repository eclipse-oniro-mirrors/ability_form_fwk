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

#include "form_refresh/strategy/refresh_check_mgr.h"

#include "fms_log_wrapper.h"
#include "form_refresh/check_mgr/system_app_checker.h"
#include "form_refresh/check_mgr/self_form_checker.h"
#include "form_refresh/check_mgr/calling_user_checker.h"
#include "form_refresh/check_mgr/calling_bundle_checker.h"
#include "form_refresh/check_mgr/active_user_checker.h"
#include "form_refresh/check_mgr/add_finish_checker.h"
#include "form_refresh/check_mgr/untrust_app_checker.h"
#include "form_refresh/check_mgr/multi_active_users_checker.h"

namespace OHOS {
namespace AppExecFwk {

RefreshCheckMgr::RefreshCheckMgr() {}
RefreshCheckMgr::~RefreshCheckMgr() {}

const static std::map<int32_t, IBaseChecker *> checkerMap = {
    { TYPE_SYSTEM_APP, &SystemAppChecker::GetInstance() },
    { TYPE_SELF_FORM, &SelfFormChecker::GetInstance() },
    { TYPE_CALLING_USER, &CallingUserChecker::GetInstance() },
    { TYPE_CALLING_BUNDLE, &CallingBundleChecker::GetInstance() },
    { TYPE_ACTIVE_USER, &ActiveUserChecker::GetInstance() },
    { TYPE_ADD_FINISH, &AddFinishChecker::GetInstance() },
    { TYPE_UNTRUST_APP, &UntrustAppChecker::GetInstance() },
    { TYPE_MULTI_ACTIVE_USERS, &MultiActiveUsersChecker::GetInstance() },
};

int RefreshCheckMgr::IsBaseValidPass(const std::vector<int32_t> &types, const CheckValidFactor &factor)
{
    if (types.empty()) {
        HILOG_INFO("the refresh task need't check valid, formId:%{public}" PRId64, factor.formId);
        return ERR_OK;
    }

    int ret = ERR_OK;
    for (const auto type : types) {
        ret = HandleCheckValid(factor, type);
        if (ret != ERR_OK) {
            // If a check fails, return directly.
            return ret;
        }
    }
    return ret;
}

int RefreshCheckMgr::HandleCheckValid(const CheckValidFactor &factor, const int32_t checkType)
{
    HILOG_DEBUG("checkType:%{public}d, formId:%{public}" PRId64, checkType, factor.formId);
    auto it = checkerMap.find(checkType);
    if (it != checkerMap.end()) {
        return it->second->CheckValid(factor);
    } else {
        HILOG_ERROR("invalid checkType");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
}

} // namespace AppExecFwk
} // namespace OHOS