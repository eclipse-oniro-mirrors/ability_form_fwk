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

#include "mock_form_distributed_mgr.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormDistributedMgr> MockFormDistributedMgr::obj = nullptr;

FormDistributedMgr::FormDistributedMgr() {}
FormDistributedMgr::~FormDistributedMgr() {}

bool FormDistributedMgr::IsBundleDistributed(const std::string &bundleName, int32_t userId)
{
    GTEST_LOG_(INFO) << "IsBundleDistributed called";
    if (AppExecFwk::MockFormDistributedMgr::obj) {
        return AppExecFwk::MockFormDistributedMgr::obj->IsBundleDistributed(bundleName, userId);
    }
    return false;
}

std::string FormDistributedMgr::GetUiModuleName(const std::string &bundleName, int32_t userId)
{
    GTEST_LOG_(INFO) << "GetUiModuleName called";
    if (AppExecFwk::MockFormDistributedMgr::obj) {
        return AppExecFwk::MockFormDistributedMgr::obj->GetUiModuleName(bundleName, userId);
    }
    return "";
}
}  // namespace AppExecFwk
}  // namespace OHOS
