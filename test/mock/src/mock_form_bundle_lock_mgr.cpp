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

#include "mock_form_bundle_lock_mgr.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormBundleLockMgr> MockFormBundleLockMgr::obj = nullptr;

FormBundleLockMgr::FormBundleLockMgr() {}
FormBundleLockMgr::~FormBundleLockMgr() {}

bool FormBundleLockMgr::IsBundleProtect(const std::string &bundleName, const int32_t userId, int64_t formId)
{
    GTEST_LOG_(INFO) << "IsBundleProtect called";
    if (AppExecFwk::MockFormBundleLockMgr::obj) {
        return AppExecFwk::MockFormBundleLockMgr::obj->IsBundleProtect(bundleName, userId, formId);
    }
    return false;
}

bool FormBundleLockMgr::IsBundleLock(const std::string &bundleName, const int32_t userId, int64_t formId)
{
    GTEST_LOG_(INFO) << "IsBundleLock called";
    if (AppExecFwk::MockFormBundleLockMgr::obj) {
        return AppExecFwk::MockFormBundleLockMgr::obj->IsBundleLock(bundleName, userId, formId);
    }
    return false;
}

void FormBundleLockMgr::SetBundleLockStatus(const std::string &bundleName, bool isLock)
{
    GTEST_LOG_(INFO) << "SetBundleLockStatus called";
    if (AppExecFwk::MockFormBundleLockMgr::obj) {
        AppExecFwk::MockFormBundleLockMgr::obj->SetBundleLockStatus(bundleName, isLock);
    }
}

void FormBundleLockMgr::SetBundleProtectStatus(const std::string &bundleName, bool isProtect)
{
    GTEST_LOG_(INFO) << "SetBundleProtectStatus called";
    if (AppExecFwk::MockFormBundleLockMgr::obj) {
        AppExecFwk::MockFormBundleLockMgr::obj->SetBundleProtectStatus(bundleName, isProtect);
    }
}

}  // namespace AppExecFwk
}  // namespace OHOS
