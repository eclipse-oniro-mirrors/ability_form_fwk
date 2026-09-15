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

#include "formcallbackadapterfive_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "ffrt.h"

#define private public
#define protected public
#include "form_mgr/form_callback_adapter.h"
#undef private
#undef protected

// The fuzz target links the real form service stack, whose FormDataMgr registers a
// memory-watermark parameter watcher. Its IPC-thread callback can submit ffrt tasks
// after the global scheduler is torn down at process exit (heap-use-after-free). The
// watcher path is not reachable from fuzz input, so stub the registration as no-op.
extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

// Interpose ffrt_queue_submit_h so no ffrt task is ever enqueued. Enqueuing
// tasks spawns ffrt CPU workers whose threads still run when ffrt's static
// CPUWorkerGroup is torn down at exit (heap-use-after-free).
extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int64_t MAX_FORM_ID = 10000;
constexpr int64_t MIN_FORM_ID = 1;
constexpr int64_t NEGATIVE_FORM_ID = -10000;
constexpr int64_t LARGE_FORM_ID = 1000000;
constexpr int32_t MAX_USER_UID_COUNT = 8;
constexpr int32_t MIN_UID = 0;
constexpr int32_t MAX_UID = 100000;
constexpr int32_t MAX_SPECIFICATION = 10;
constexpr int32_t MAX_USER_ID = 100;

// Build a minimally valid FormRecord. formUserUids is the only field CancelSceneEffects
// consumes (per-uid registry lookups), so fuzz both its length and values.
FormRecord MakeFormRecord(FuzzedDataProvider *fdp, int64_t formId)
{
    FormRecord record;
    record.formId = formId;
    record.isInited = true;
    record.bundleName = "com.form.fwk.callback.fuzz";
    record.moduleName = "entry";
    record.abilityName = "CallbackFuzzAbility";
    record.formName = "FuzzWidget";
    record.specification = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_SPECIFICATION);
    record.userId = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_USER_ID);
    record.isSystemApp = fdp->ConsumeBool();
    record.formTempFlag = fdp->ConsumeBool();
    int32_t uidCount = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_USER_UID_COUNT);
    for (int32_t i = 0; i < uidCount; ++i) {
        record.formUserUids.emplace_back(fdp->ConsumeIntegralInRange<int32_t>(MIN_UID, MAX_UID));
    }
    return record;
}

// Seed a record into the FormDataMgr singleton so GetFormRecord(formId) succeeds.
void SeedFormRecord(int64_t formId, const FormRecord &record)
{
    auto &dataMgr = FormDataMgr::GetInstance();
    dataMgr.formRecords_[formId] = record;
}

// Remove the seeded record to keep the singleton state deterministic across iterations.
void ClearFormRecord(int64_t formId)
{
    auto &dataMgr = FormDataMgr::GetInstance();
    dataMgr.formRecords_.erase(formId);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormCallbackAdapter::GetInstance();

    // Call 1: likely-invalid formId - triggers GetFormRecord failure branch (early return).
    int64_t invalidFormId = fdp->ConsumeIntegralInRange<int64_t>(NEGATIVE_FORM_ID, MIN_FORM_ID - 1);
    adapter.CancelSceneEffects(invalidFormId);

    // Call 2: seed a matching FormRecord so the fuzz-driven formId gets past the
    // GetFormRecord guard and reaches the core formUserUids loop (per-uid overflow
    // and scene-animation registry lookups).
    int64_t seededFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    FormRecord record = MakeFormRecord(fdp, seededFormId);
    SeedFormRecord(seededFormId, record);
    adapter.CancelSceneEffects(seededFormId);
    ClearFormRecord(seededFormId);

    // Call 3: large out-of-range formId - broadens the GetFormRecord lookup miss branch.
    int64_t extremeFormId = fdp->ConsumeIntegralInRange<int64_t>(MAX_FORM_ID + 1, LARGE_FORM_ID);
    adapter.CancelSceneEffects(extremeFormId);

    // Call 4: fully random formId from fuzzer for maximum variety.
    int64_t randomFormId = fdp->ConsumeIntegral<int64_t>();
    adapter.CancelSceneEffects(randomFormId);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
