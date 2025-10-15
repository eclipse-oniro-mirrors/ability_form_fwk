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

#include "form_refresh/check_mgr/untrust_app_checker.h"
#include "common/util/form_trust_mgr.h"
#include "feature/param_update/param_control.h"

namespace OHOS {
namespace AppExecFwk {

UntrustAppChecker::UntrustAppChecker() {}
UntrustAppChecker::~UntrustAppChecker() {}

int UntrustAppChecker::CheckValid(const CheckValidFactor &factor)
{
    if (!FormTrustMgr::GetInstance().IsTrust(factor.record.bundleName)) {
        HILOG_ERROR("is untrust app, formId:%{public}" PRId64, factor.record.formId);
        return ERR_APPEXECFWK_FORM_NOT_TRUST;
    }

    if (ParamControl::GetInstance().IsFormDisable(factor.record)) {
        HILOG_ERROR("form is disable refresh by due, %{public}" PRId64, factor.record.formId);
        return ERR_APPEXECFWK_FORM_DUE_DISABLE;
    }

    if (ParamControl::GetInstance().IsFormRemove(factor.record)) {
        HILOG_ERROR("form is remove state by due, %{public}" PRId64, factor.record.formId);
        return ERR_APPEXECFWK_FORM_DUE_REMOVE;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS