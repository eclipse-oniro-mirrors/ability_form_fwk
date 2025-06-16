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

#include "form_refresh/check_mgr/system_app_checker.h"

namespace OHOS {
namespace AppExecFwk {

SystemAppChecker::SystemAppChecker() {}
SystemAppChecker::~SystemAppChecker() {}

int SystemAppChecker::CheckValid(const CheckValidFactor &factor)
{
    if (!factor.record.isSystemApp) {
        HILOG_ERROR("is not system app, formId:%{public}" PRId64, factor.record.formId);
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS