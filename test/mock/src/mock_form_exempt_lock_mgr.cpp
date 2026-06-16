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

#include "mock_form_exempt_lock_mgr.h"
#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "feature/bundle_lock/form_exempt_lock_mgr.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<MockFormExemptLockMgr> MockFormExemptLockMgr::obj = nullptr;

FormExemptLockMgr::FormExemptLockMgr() {}
FormExemptLockMgr::~FormExemptLockMgr() {}

bool FormExemptLockMgr::IsExemptLock(int64_t formId)
{
    GTEST_LOG_(INFO) << "IsExemptLock called";
    if (AppExecFwk::MockFormExemptLockMgr::obj) {
        return AppExecFwk::MockFormExemptLockMgr::obj->IsExemptLock(formId);
    }
    return false;
}

void FormExemptLockMgr::SetExemptLockStatus(int64_t formId, bool isExempt)
{
    GTEST_LOG_(INFO) << "SetExemptLockStatus called";
    if (AppExecFwk::MockFormExemptLockMgr::obj) {
        AppExecFwk::MockFormExemptLockMgr::obj->SetExemptLockStatus(formId, isExempt);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
