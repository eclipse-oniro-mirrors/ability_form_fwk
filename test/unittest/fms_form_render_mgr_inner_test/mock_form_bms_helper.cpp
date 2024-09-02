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

#include <gtest/gtest.h>

#include "form_bms_helper.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"
namespace {
    const uint32_t COMPATIBLE_VERSION = 1;
    const uint32_t TARGET_VERSION = 1;
}
namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

bool FormBmsHelper::GetBundleInfoDefault(const std::string& bundleName, int32_t userId, BundleInfo &bundleInfo)
{
    GTEST_LOG_(INFO) << "GetBundleInfoDefault called";
    bundleInfo.compatibleVersion = COMPATIBLE_VERSION;
    bundleInfo.targetVersion = TARGET_VERSION;
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS