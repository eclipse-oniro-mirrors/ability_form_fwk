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

#include "accountcommoneventmanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fuzzer/FuzzedDataProvider.h>

// ffrt.h must be included before the interpose functions below so the ffrt C
// types (ffrt_function_header_t, ffrt_function_kind_t, ffrt_task_handle_t,
// ffrt_queue_t, ffrt_task_attr_t, ffrt_auto_managed_function_storage_size)
// are visible in the function signatures. Including it after the `#define
// private public` block would still work, but the interpose definitions need
// these types resolved at parse time.
#include "ffrt.h"

// Interpose ffrt queue submit so tasks posted via FormMgrQueue::ScheduleTask are
// never actually executed. RegisterAccountCallback posts RegisterAccountCallbackInternal
// to the queue; without interpose the internal method would call the real
// EventFwk::CommonEventManager::SubscribeCommonEvent, spawning async common-event
// threads that outlive the fuzz process and race with static teardown at exit
// (heap-use-after-free). The stub drops the task safely.
extern "C" void* ffrt_alloc_auto_managed_function_storage_base(ffrt_function_kind_t kind)
{
    return malloc(ffrt_auto_managed_function_storage_size);
}

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    if (f != nullptr) {
        if (f->destroy != nullptr) {
            f->destroy(f);
        }
        free(f);
    }
    return nullptr;
}

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

#define private public
#define protected public
#include "form_observer/account_common_event_manager.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &manager = AccountCommonEventManager::GetInstance();

    // Exercise public API entry points. RegisterAccountCallback/UnregisterAccountCallback
    // post their internal work to FormMgrQueue; the ffrt interpose above drops those tasks
    // before they reach the real EventFwk::CommonEventManager::SubscribeCommonEvent, so no
    // real common-event subscription threads are spawned.
    if (fdp->ConsumeBool()) {
        manager.RegisterAccountCallback();
    } else {
        manager.UnregisterAccountCallback();
    }

    // UnregisterAccountInternal only unsubscribes when isRegistered_ is true and observer_
    // is non-null; calling it from the clean state below is a safe no-op that exercises the
    // "not registered" early-return branch. We avoid calling RegisterAccountCallbackInternal
    // directly because it would bypass the queue and perform a real subscription.
    if (fdp->ConsumeBool()) {
        manager.UnregisterAccountCallbackInternal();
    }

    // Reset state to avoid cross-invocation contamination.
    manager.isRegistered_.store(false);
    manager.retryCount_.store(0);
    manager.observer_ = nullptr;

    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}