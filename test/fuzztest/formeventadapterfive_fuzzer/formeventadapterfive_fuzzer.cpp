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

#include "formeventadapterfive_fuzzer.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#define private public
#define protected public
#include "form_mgr/form_event_adapter.h"
#undef private
#undef protected

#include "form_constants.h"
#include "insight_intent/insight_intent_execute_param.h"
#include "want.h"

// The fuzz target links the real form service stack, whose FormDataMgr registers a
// memory-watermark parameter watcher. Its IPC-thread callback can submit ffrt tasks
// after the global scheduler is torn down at process exit (heap-use-after-free). The
// watcher path is not reachable from fuzz input, so stub the registration as no-op.
extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int64_t MAX_FORM_ID = 10000;
constexpr int64_t MIN_FORM_ID = 0;
constexpr int64_t MIN_NEG_FORM_ID = -10000;

std::string GenerateSafeString(FuzzedDataProvider *fdp, int32_t maxLength)
{
    std::string result = fdp->ConsumeRandomLengthString(maxLength);
    std::string safeResult;
    for (char c : result) {
        if (std::isalnum(c) || c == '_' || c == '-' || c == '.' || c == '/' || c == ':') {
            safeResult += c;
        } else {
            safeResult += '_';
        }
    }
    return safeResult.empty() ? "default" : safeResult;
}

// Build a want whose element triple fields are fuzzily blanked to cover the
// record-backfill branches in PrepareInsightIntentParam.
Want GenerateInsightIntentWant(FuzzedDataProvider *fdp)
{
    Want want;
    std::string bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    std::string moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    std::string abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    if (fdp->ConsumeBool()) {
        bundleName = "";
    }
    if (fdp->ConsumeBool()) {
        moduleName = "";
    }
    if (fdp->ConsumeBool()) {
        abilityName = "";
    }
    want.SetElementName(bundleName, moduleName, abilityName);
    want.SetAction(GenerateSafeString(fdp, MAX_LENGTH));
    return want;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormEventAdapter::GetInstance();

    // Fuzz InsightIntentEvent with the intent name param set
    // (covers intent name parsing and element backfill in PrepareInsightIntentParam)
    int64_t formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want want = GenerateInsightIntentWant(fdp);
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, GenerateSafeString(fdp, MAX_LENGTH));
    sptr<IRemoteObject> callerToken = nullptr;
    adapter.InsightIntentEvent(formId, want, callerToken);

    // Fuzz InsightIntentEvent without the intent name param (covers HasParam false branch)
    int64_t absentFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want absentWant = GenerateInsightIntentWant(fdp);
    adapter.InsightIntentEvent(absentFormId, absentWant, callerToken);

    // Fuzz InsightIntentEvent with a negative or zero formId (covers invalid formId branch)
    int64_t invalidFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NEG_FORM_ID, 0);
    Want invalidWant = GenerateInsightIntentWant(fdp);
    invalidWant.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, GenerateSafeString(fdp, MAX_LENGTH));
    adapter.InsightIntentEvent(invalidFormId, invalidWant, callerToken);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
