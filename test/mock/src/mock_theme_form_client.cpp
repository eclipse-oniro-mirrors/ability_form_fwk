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

#include "mock_theme_form_client.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "services/include/feature/theme_form/theme_form_client.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockThemeFormClient> MockThemeFormClient::obj = nullptr;

int32_t ThemeFormClient::AddForm(const FormNotifyInfo& info)
{
    GTEST_LOG_(INFO) << "AddForm called";
    if (AppExecFwk::MockThemeFormClient::obj) {
        return AppExecFwk::MockThemeFormClient::obj->AddForm(info);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

int32_t ThemeFormClient::DeleteForms(const std::vector<int64_t> &formIds)
{
    GTEST_LOG_(INFO) << "DeleteForms called";
    if (AppExecFwk::MockThemeFormClient::obj) {
        return AppExecFwk::MockThemeFormClient::obj->DeleteForms(formIds);
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}
}  // namespace AppExecFwk
}  // namespace OHOS
