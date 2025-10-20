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

#include "mock_ipc_skeleton.h"
#include <gtest/gtest.h>

#include "ipc_skeleton.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace {
constexpr int32_t DEFAULT_CALLING_UID = 20000000;
}  // namespace

namespace AppExecFwk {
MockIPCSkeleton *MockIPCSkeleton::obj = nullptr;
}  // namespace AppExecFwk

pid_t IPCSkeleton::GetCallingUid()
{
    GTEST_LOG_(INFO) << "GetCallingUid called ";
    if (AppExecFwk::MockIPCSkeleton::obj) {
        return AppExecFwk::MockIPCSkeleton::obj->GetCallingUid();
    }
    return DEFAULT_CALLING_UID;
}
}  // namespace OHOS