/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "formmgrqueue_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_mgr/form_mgr_queue.h"
#include "ffrt.h"
#undef private
#undef protected

// Interpose ffrt_queue_submit_h so no ffrt task is ever enqueued. Enqueuing
// tasks spawns ffrt CPU workers whose threads still run when ffrt's static
// CPUWorkerGroup is torn down at exit (heap-use-after-free).
extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

// Interpose WatchParameter so the memory-watermark watcher never arms. The
// param-service callback creates an ffrt queue during exit, racing with ffrt's
// static QueueMonitor teardown (heap-use-after-free).
extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr int32_t MAX_NUM = 10;
constexpr int32_t MIN_NUM = 0;
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto emptyFunc = []() {};
    int64_t formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
    int64_t userId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
    std::pair<int64_t, int64_t> eventMsg = std::make_pair(formId, userId);
    uint32_t delayMs = fdp->ConsumeIntegral<uint32_t>();
    FormMgrQueue::GetInstance().ScheduleDelayTask(eventMsg, delayMs, emptyFunc);

    FormMgrQueue::GetInstance().CancelDelayTask(eventMsg);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
