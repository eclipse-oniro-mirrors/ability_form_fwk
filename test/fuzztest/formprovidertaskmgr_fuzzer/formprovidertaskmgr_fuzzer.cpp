/*
 * Copyright (c) 2022-2026 Huawei Device Co., Ltd.
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

#include "formprovidertaskmgr_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "form_provider/form_provider_task_mgr.h"
#include "form_provider/form_provider_queue.h"
#define protected public

#undef private
#undef protected
#include "securec.h"
#include "ffrt.h"

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

constexpr size_t U32_AT_SIZE = 4;
void FormProviderQueueTest(FuzzedDataProvider *fdp)
{
    uint64_t ms64 = fdp->ConsumeIntegral<uint64_t>();
    std::function<void()> func = []() { return 1; };
    uint32_t ms32 = fdp->ConsumeIntegral<uint32_t>();
    const std::pair<int64_t, int64_t> eventMsg;
    FormProviderQueue::GetInstance().ScheduleTask(ms64, func);
    FormProviderQueue::GetInstance().ScheduleDelayTask(eventMsg, ms32, func);
    FormProviderQueue::GetInstance().CancelDelayTask(eventMsg);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    FormProviderTaskMgr formTaskMgr;
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.PostAcquireTask(formId, want, remoteObject);
    formTaskMgr.PostRefreshLocationTask(formId, want, remoteObject);
    formTaskMgr.PostRefreshTask(formId, want, remoteObject);
    formTaskMgr.PostDeleteTask(formId, want, remoteObject);
    std::set<int64_t> formIds;
    formIds.insert(formId);
    formTaskMgr.PostProviderBatchDeleteTask(formIds, want, remoteObject);
    formTaskMgr.PostCastTempTask(formId, want, remoteObject);
    Want wantArg;
    std::string provider = fdp->ConsumeRandomLengthString();
    formTaskMgr.PostAcquireStateTask(wantArg, provider, want, remoteObject);
    formTaskMgr.PostAcquireDataTask(formId, want, remoteObject);
    std::string message = fdp->ConsumeRandomLengthString();
    formTaskMgr.PostFormEventTask(formId, message, want, remoteObject);
    std::vector<int64_t> formEvent;
    formEvent.emplace_back(formId);
    int32_t formVisibleType = fdp->ConsumeIntegral<int32_t>();
    formTaskMgr.PostEventNotifyTask(formEvent, formVisibleType, want, remoteObject);
    int32_t newDimension = fdp->ConsumeIntegral<int32_t>();
    Rect newRect;
    formTaskMgr.PostSizeChangedTask(formId, newDimension, newRect, want, remoteObject);
    formTaskMgr.AcquireProviderFormInfo(formId, want, remoteObject);
    formTaskMgr.NotifyFormUpdate(formId, want, remoteObject);
    formTaskMgr.NotifyFormDelete(formId, want, remoteObject);
    formTaskMgr.ProviderBatchDelete(formIds, want, remoteObject);
    formTaskMgr.NotifyCastTemp(formId, want, remoteObject);
    formTaskMgr.AcquireState(wantArg, provider, want, remoteObject);
    formTaskMgr.AcquireFormData(formId, want, remoteObject);
    formTaskMgr.FireFormEvent(formId, message, want, remoteObject);
    formTaskMgr.EventNotify(formEvent, formVisibleType, want, remoteObject);
    AppExecFwk::Configuration configuration;
    formTaskMgr.NotifyConfigurationUpdate(configuration, want, remoteObject);
    formTaskMgr.NotifyFormLocationUpdate(formId, want, remoteObject);
    formTaskMgr.NotifySizeChanged(formId, newDimension, newRect, want, remoteObject);
    formTaskMgr.RemoveConnection(formId);
    int32_t connectId = fdp->ConsumeIntegral<int32_t>();
    formTaskMgr.DelayedFormExitDetect(connectId);
    OHOS::FormProviderQueueTest(fdp);
    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
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

    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}