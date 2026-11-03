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

#include "accountcommoneventobserver_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fuzzer/FuzzedDataProvider.h>

#include <common_event_data.h>
#include <common_event_subscriber.h>
#include <common_event_support.h>
#include "want.h"

// ffrt.h must be included before the interpose functions below so the ffrt C
// types (ffrt_function_header_t, ffrt_function_kind_t, ffrt_task_handle_t,
// ffrt_queue_t, ffrt_task_attr_t, ffrt_auto_managed_function_storage_size)
// are visible in the function signatures.
#include "ffrt.h"

// Interpose ffrt queue submit so the task posted by OnReceiveEvent
// (FormDataAdapter::UpdateFormByCondition) is never executed. Without interpose
// the dispatched refresh task would touch FormDataMgr/FormRefreshMgr and spawn
// async render/provider connections that outlive the fuzz process, racing with
// static teardown at exit (heap-use-after-free). The stub drops the task safely.
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
#include "form_observer/account_common_event_observer.h"
#undef private
#undef protected

using Want = OHOS::AAFwk::Want;
using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;
constexpr int32_t INVALID_USER_ID = -1;

Want GenerateFuzzedWant(FuzzedDataProvider *fdp)
{
    Want want;
    if (fdp == nullptr) {
        return want;
    }
    want.SetElementName(fdp->ConsumeRandomLengthString(MAX_LENGTH),
        fdp->ConsumeRandomLengthString(MAX_LENGTH));
    // Bias action toward the two real account events to exercise the
    // filtering logic, but still allow arbitrary strings to hit the
    // ignore-non-account-event branch.
    constexpr int32_t ACTION_SELECTOR_RANGE = 3;
    int32_t actionChoice = fdp->ConsumeIntegralInRange<int32_t>(MIN_NUM, ACTION_SELECTOR_RANGE);
    std::string action;
    if (actionChoice == 0) {
        action = "common.event.DISTRIBUTED_ACCOUNT_LOGIN";
    } else if (actionChoice == 1) {
        action = "common.event.DISTRIBUTED_ACCOUNT_LOGOUT";
    } else {
        action = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    }
    want.SetAction(action);
    // userId param: mix valid (>0) and invalid (<0) values to cover both
    // the skip-invalid branch and the dispatch branch.
    int32_t userId = fdp->ConsumeIntegral<int32_t>();
    want.SetParam("userId", userId);
    return want;
}

EventFwk::CommonEventData GenerateFuzzedCommonEventData(FuzzedDataProvider *fdp)
{
    EventFwk::CommonEventData data;
    if (fdp == nullptr) {
        return data;
    }
    data.SetWant(GenerateFuzzedWant(fdp));
    data.SetCode(fdp->ConsumeIntegral<int32_t>());
    data.SetData(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    return data;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    // Construct the observer with a minimal subscribe info (required by base class).
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("common.event.DISTRIBUTED_ACCOUNT_LOGIN");
    matchingSkills.AddEvent("common.event.DISTRIBUTED_ACCOUNT_LOGOUT");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    auto observer = std::make_shared<AccountCommonEventObserver>(subscribeInfo);
    if (observer == nullptr) {
        return true;
    }

    // Drive OnReceiveEvent with fuzzed event data: exercises action filtering,
    // userId extraction/validation, and the (interposed) dispatch path.
    EventFwk::CommonEventData data = GenerateFuzzedCommonEventData(fdp);
    observer->OnReceiveEvent(data);

    // Second invocation with independent fuzzed data to stress the
    // non-account-event ignore branch and invalid-userId branch.
    if (fdp->ConsumeBool()) {
        EventFwk::CommonEventData data2 = GenerateFuzzedCommonEventData(fdp);
        observer->OnReceiveEvent(data2);
    }

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