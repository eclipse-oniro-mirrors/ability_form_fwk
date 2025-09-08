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

#include "formerrors_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_errors.h"
#include "form_mgr/form_mgr_queue.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    FormErrors formErrors;
    int errorCode = fdp->ConsumeIntegral<int>();
    formErrors.InitErrorMessageMap();
    int32_t internalErrorCode = fdp->ConsumeIntegral<int32_t>();
    formErrors.QueryExternalErrorCode(internalErrorCode);
    int32_t externalErrorCode = fdp->ConsumeIntegral<int32_t>();
    formErrors.QueryExternalErrorMessage(internalErrorCode, externalErrorCode);
    formErrors.GetErrorMsgByExternalErrorCode(externalErrorCode);
    formErrors.GetErrorMessage(errorCode);
    uint64_t ms64 = fdp->ConsumeIntegral<uint64_t>();
    uint32_t ms32 = fdp->ConsumeIntegral<uint32_t>();
    std::function<void()> func = []() { return 1; };
    int64_t intKey = fdp->ConsumeIntegral<int64_t>();
    int64_t intValue = fdp->ConsumeIntegral<int64_t>();
    std::pair<int64_t, int64_t> eventMsg = std::make_pair(intKey, intValue);
    FormMgrQueue::GetInstance().ScheduleTask(ms64, func);
    FormMgrQueue::GetInstance().ScheduleDelayTask(eventMsg, ms32, func);
    FormMgrQueue::GetInstance().CancelDelayTask(eventMsg);
    return true;
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

    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    free(ch);
    ch = nullptr;
    return 0;
}