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

#include "form_bms_helper.h"

#include "form_mgr_errors.h"
#include "hilog_wrapper.h"

namespace {
    bool g_mockGetBundlePackInfoRet = true;
    bool g_mockGetUidByBundleNameRet = true;
}

void MockGetBundlePackInfo(bool mockRet)
{
    g_mockGetBundlePackInfoRet = mockRet;
}

void MockGetUidByBundleName(bool mockRet)
{
    g_mockGetUidByBundleNameRet = mockRet;
}

namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

bool FormBmsHelper::GetBundlePackInfo(const std::string &bundleName, const int32_t userId,
    BundlePackInfo &bundlePackInfo)
{
    return g_mockGetBundlePackInfoRet;
}

int32_t FormBmsHelper::GetUidByBundleName(const std::string &bundleName, const int32_t userId)
{
    if (true == g_mockGetUidByBundleNameRet) {
        return INVALID_UID;
    }
    return 10;
}
} // namespace AppExecFwk
} // namespace OHOS
