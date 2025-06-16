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

#include "form_refresh/check_mgr/add_finish_checker.h"

#include "common/util/form_report.h"

namespace OHOS {
namespace AppExecFwk {

AddFinishChecker::AddFinishChecker() {}
AddFinishChecker::~AddFinishChecker() {}

int AddFinishChecker::CheckValid(const CheckValidFactor &factor)
{
    bool addFormFinish = false;
    FormReport::GetInstance().GetAddFormFinish(factor.formId, addFormFinish);
    if (!addFormFinish) {
        HILOG_WARN("form is adding:%{public}" PRId64, factor.formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS