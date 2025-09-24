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

#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"

namespace {
    int32_t g_GetCallingUid = 20000000;
}

void MockGetCallingUid(int32_t mockRet)
{
    g_GetCallingUid = mockRet;
}

namespace OHOS {
pid_t IPCSkeleton::GetCallingUid()
{
    GTEST_LOG_(INFO) << "GetCallingUid called " << g_GetCallingUid;
    return g_GetCallingUid;
}
} // namespace OHOS