/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "fms_log_wrapper.h"

namespace {
    OHOS::ErrCode g_mockGetBundleNameByUidRet = OHOS::ERR_OK;
    std::string g_mockBundleName = "A";
}

void MockGetBundleNameByUid(OHOS::ErrCode mockRet)
{
    g_mockGetBundleNameByUidRet = mockRet;
}

void MockGetBundleNameByUid(OHOS::ErrCode mockRet, const std::string &bundleName)
{
    g_mockGetBundleNameByUidRet = mockRet;
    g_mockBundleName = bundleName;
}

namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

ErrCode FormBmsHelper::GetBundleNameByUid(const int32_t uid, std::string &bundleName)
{
    bundleName = g_mockBundleName;
    return g_mockGetBundleNameByUidRet;
}
} // namespace AppExecFwk
} // namespace OHOS
