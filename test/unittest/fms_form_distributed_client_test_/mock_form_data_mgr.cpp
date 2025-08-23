/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "mock_form_data_proxy_record_test.h"

namespace {
    bool g_mockGetFormRecordRet = false;
    constexpr int32_t UPDATE_DURATION  = 2;
}

namespace OHOS {
void MockGetFormRecord(bool mockRet)
{
    g_mockGetFormRecordRet = mockRet;
}
} // namespace OHOS

namespace OHOS {
namespace AppExecFwk {
FormDataMgr::FormDataMgr()
{
    HILOG_INFO("create form data manager instance");
}
FormDataMgr::~FormDataMgr()
{
    HILOG_INFO("destroy form data manager instance");
}

bool FormDataMgr::GetFormRecord(const int64_t formId, FormRecord &formRecord) const
{
    if (g_mockGetFormRecordRet) {
        formRecord.bundleName = "com.form.provider.service";
        formRecord.formId = formId;
        formRecord.isEnableUpdate = true;
        formRecord.updateDuration = UPDATE_DURATION * Constants::TIME_CONVERSION;
    }
    return g_mockGetFormRecordRet;
}
} // namespace AppExecFwk
} // namespace OHOS
