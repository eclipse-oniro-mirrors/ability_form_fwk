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

#include <gtest/gtest.h>

#include "bms_mgr/form_bms_helper.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"

namespace {
    int32_t getCallerBundleName = OHOS::ERR_OK;
    std::string g_mockBundleName;
    bool g_mockGetBundleInfoByFlagsRet = true;
    std::string g_mockAppProvisionType;
    int32_t g_mockGetBundleNameByUidRet = OHOS::ERR_OK;
    std::string g_mockGetBundleNameByUidBundleName;
}

namespace OHOS {
namespace AppExecFwk {

void MockGetCallerBundleName(int32_t mockRet, const std::string &bundleName)
{
    getCallerBundleName = mockRet;
    g_mockBundleName = bundleName;
}

void MockFormBmsHelperGetBundleInfoByFlags(bool mockRet, const std::string &appProvisionType)
{
    g_mockGetBundleInfoByFlagsRet = mockRet;
    g_mockAppProvisionType = appProvisionType;
}

void MockFormBmsHelperGetBundleNameByUid(int32_t mockRet, const std::string &bundleName)
{
    g_mockGetBundleNameByUidRet = mockRet;
    g_mockGetBundleNameByUidBundleName = bundleName;
}
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

int32_t FormBmsHelper::GetCallerBundleName(std::string &callerBundleName)
{
    GTEST_LOG_(INFO) << "GetCallerBundleName called " << getCallerBundleName;
    callerBundleName = g_mockBundleName;
    return getCallerBundleName;
}

bool FormBmsHelper::GetBundleInfoByFlags(const std::string &bundleName, const int32_t flags, int32_t userId,
    BundleInfo &bundleInfo)
{
    if (!g_mockGetBundleInfoByFlagsRet) {
        return false;
    }
    bundleInfo.applicationInfo.appProvisionType = g_mockAppProvisionType;
    return true;
}

int32_t FormBmsHelper::GetBundleNameByUid(const int32_t uid, std::string &bundleName)
{
    if (g_mockGetBundleNameByUidRet != OHOS::ERR_OK) {
        return g_mockGetBundleNameByUidRet;
    }
    bundleName = g_mockGetBundleNameByUidBundleName;
    return g_mockGetBundleNameByUidRet;
}
} // namespace AppExecFwk
} // namespace OHOS