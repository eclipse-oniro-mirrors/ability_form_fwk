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

#include "formobservertaskmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#define protected public
#include "form_observer/form_observer_task_mgr.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
void DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormObserverTaskMgr formTaskMgr;
    std::string bundleName(data, size);
    sptr<IRemoteObject> remoteObject = nullptr;
    RunningFormInfo runningFormInfo;
    formTaskMgr.PostAddTaskToHost(bundleName, remoteObject, runningFormInfo);
    formTaskMgr.PostRemoveTaskToHost(bundleName, remoteObject, runningFormInfo);
    std::string formEventType(data, size);
    formTaskMgr.PostFormClickEventToHost(bundleName, formEventType, remoteObject, runningFormInfo);
    int32_t formRefreshType = 0;
    formTaskMgr.PostBatchRefreshForms(formRefreshType);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

