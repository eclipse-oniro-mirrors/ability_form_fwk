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

#include "formextensionprocesspool_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#define private public
#define protected public
#include "form_provider/form_extension_process_pool.h"
#include "common/connection/form_ability_connection.h"
#include "form_provider/connection/form_refresh_connection.h"
#undef private
#undef protected
#include "ffrt.h"

// FFRT stubs: prevent real async tasks from accumulating threads during long fuzz runs.
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

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
constexpr int32_t MAX_USER_ID = 100;
constexpr size_t MIN_FUZZ_INPUT_SIZE = 4;
constexpr int32_t FUZZ_OP_COUNT = 7;
// Keep the threshold small so the fuzzer frequently hits the pool-full PENDING path.
constexpr int32_t FUZZ_MAX_THRESHOLD = 3;

enum class FuzzOp : uint8_t {
    ADMIT_CONNECTION = 0,
    TERMINATE_CONNECTION = 1,
    POP_NEXT = 2,
    DUMP = 3,
    SET_THRESHOLD = 4,
    GET_COUNTS = 5,
    FORCE_ADMIT = 6,
};

AAFwk::Want FuzzMakeWant(FuzzedDataProvider &fdp)
{
    AAFwk::Want want;
    std::string bundle = "fuzz.bundle." + std::to_string(fdp.ConsumeIntegral<uint8_t>());
    want.SetElementName(bundle, "FuzzAbility");
    return want;
}

sptr<FormAbilityConnection> FuzzMakeConnectionWith(const int64_t formId, const std::string &bundle,
    const int32_t userId, const AAFwk::Want &want)
{
    FormRecord record;
    record.bundleName = bundle;
    record.abilityName = "FuzzAbility";
    record.providerUserId = userId;
    return new FormRefreshConnection(formId, want, record);
}

sptr<FormAbilityConnection> FuzzMakeConnection(FuzzedDataProvider &fdp)
{
    int64_t formId = static_cast<int64_t>(fdp.ConsumeIntegral<uint32_t>());
    std::string bundle = "fuzz.conn." + std::to_string(fdp.ConsumeIntegral<uint8_t>());
    int32_t userId = static_cast<int32_t>(fdp.ConsumeIntegral<uint8_t>()) % MAX_USER_ID;
    return FuzzMakeConnectionWith(formId, bundle, userId, FuzzMakeWant(fdp));
}

void FuzzAdmitConnection(FuzzedDataProvider &fdp)
{
    auto pool = &FormExtensionProcessPool::GetInstance();
    pool->threshold_ = fdp.ConsumeIntegralInRange<size_t>(1, FUZZ_MAX_THRESHOLD);
    auto want = FuzzMakeWant(fdp);
    auto conn = FuzzMakeConnection(fdp);
    pool->AdmitConnection(want, conn);
}

void FuzzOnConnectionTerminated(FuzzedDataProvider &fdp)
{
    auto pool = &FormExtensionProcessPool::GetInstance();
    auto conn = FuzzMakeConnection(fdp);
    int32_t userId = static_cast<int32_t>(fdp.ConsumeIntegral<uint8_t>()) % MAX_USER_ID;
    std::string bundle = "fuzz.term." + std::to_string(fdp.ConsumeIntegral<uint8_t>());
    pool->OnConnectionTerminated(userId, bundle, conn);
}

void FuzzPopNext(FuzzedDataProvider &fdp)
{
    auto pool = &FormExtensionProcessPool::GetInstance();
    int32_t userId = static_cast<int32_t>(fdp.ConsumeIntegral<uint8_t>()) % MAX_USER_ID;
    PendingRequest out;
    pool->PopNext(userId, out);
}

void FuzzDump(FuzzedDataProvider &fdp)
{
    auto pool = &FormExtensionProcessPool::GetInstance();
    std::unordered_map<int32_t, FormExtensionProcessPool::BundleLedger> providers;
    FormExtensionProcessPool::PendingQueueMap pendingQueue;
    pool->DumpProcessPoolStatus(providers, pendingQueue);
}

void FuzzSetThreshold(FuzzedDataProvider &fdp)
{
    auto pool = &FormExtensionProcessPool::GetInstance();
    pool->threshold_ = static_cast<size_t>(fdp.ConsumeIntegral<uint16_t>());
}

void FuzzGetCounts(FuzzedDataProvider &fdp)
{
    auto pool = &FormExtensionProcessPool::GetInstance();
    int32_t userId = static_cast<int32_t>(fdp.ConsumeIntegral<uint8_t>()) % MAX_USER_ID;
    pool->GetActiveProviderCount(userId);
    pool->GetPendingCount(userId);
}

void FuzzForceAdmit(FuzzedDataProvider &fdp)
{
    auto pool = &FormExtensionProcessPool::GetInstance();
    int32_t userId = static_cast<int32_t>(fdp.ConsumeIntegral<uint8_t>()) % MAX_USER_ID;
    // Occupy the single slot so the next connection of this user is queued as pending.
    pool->threshold_ = 1;
    AAFwk::Want blockerWant = FuzzMakeWant(fdp);
    auto blocker = FuzzMakeConnectionWith(static_cast<int64_t>(fdp.ConsumeIntegral<uint32_t>()),
        "fuzz.block." + std::to_string(fdp.ConsumeIntegral<uint8_t>()), userId, blockerWant);
    pool->AdmitConnection(blockerWant, blocker);

    // A different bundle cannot acquire a slot and is queued as pending; then simulate
    // the 3-second visibility timeout force-admitting it (cancel pending + register).
    AAFwk::Want pendingWant = FuzzMakeWant(fdp);
    auto pending = FuzzMakeConnectionWith(static_cast<int64_t>(fdp.ConsumeIntegral<uint32_t>()),
        "fuzz.pend." + std::to_string(fdp.ConsumeIntegral<uint8_t>()), userId, pendingWant);
    if (!pool->AdmitConnection(pendingWant, pending)) {
        pool->ForceAdmitConnection(pendingWant, pending);
    }
}

void FuzzSequence(FuzzedDataProvider &fdp)
{
    // Randomly exercise multiple pool APIs in sequence.
    for (int32_t i = 0; i < FUZZ_OP_COUNT; ++i) {
        auto op = static_cast<FuzzOp>(fdp.ConsumeIntegral<uint8_t>() % FUZZ_OP_COUNT);
        switch (op) {
            case FuzzOp::ADMIT_CONNECTION: FuzzAdmitConnection(fdp); break;
            case FuzzOp::TERMINATE_CONNECTION: FuzzOnConnectionTerminated(fdp); break;
            case FuzzOp::POP_NEXT: FuzzPopNext(fdp); break;
            case FuzzOp::DUMP: FuzzDump(fdp); break;
            case FuzzOp::SET_THRESHOLD: FuzzSetThreshold(fdp); break;
            case FuzzOp::GET_COUNTS: FuzzGetCounts(fdp); break;
            case FuzzOp::FORCE_ADMIT: FuzzForceAdmit(fdp); break;
            default: break;
        }
    }
}
} // namespace AppExecFwk
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < MIN_FUZZ_INPUT_SIZE) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::AppExecFwk::FuzzSequence(fdp);
    return 0;
}
