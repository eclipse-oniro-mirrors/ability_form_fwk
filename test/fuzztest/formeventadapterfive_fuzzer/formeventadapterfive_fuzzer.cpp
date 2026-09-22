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
#include "data_center/form_data_mgr.h"
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
constexpr int32_t PROVIDER_USER_ID = 100;

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

void AddFormRecordForFuzz(int64_t formId)
{
    if (formId <= 0) {
        return;
    }
    FormDataMgr::GetInstance().ClearFormRecords();
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.example.fuzzer";
    record.moduleName = "entry";
    record.abilityName = "FormAbility";
    record.providerUserId = PROVIDER_USER_ID;
    record.isSystemApp = true;
    FormDataMgr::GetInstance().formRecords_[formId] = record;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormEventAdapter::GetInstance();

    int64_t formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want want = GenerateInsightIntentWant(fdp);
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, GenerateSafeString(fdp, MAX_LENGTH));
    AddFormRecordForFuzz(formId);
    sptr<IRemoteObject> callerToken = nullptr;
    adapter.InsightIntentEvent(formId, want, callerToken);

    int64_t absentFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want absentWant = GenerateInsightIntentWant(fdp);
    AddFormRecordForFuzz(absentFormId);
    adapter.InsightIntentEvent(absentFormId, absentWant, callerToken);

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
    constexpr int32_t sleepSeconds = 2;
    std::this_thread::sleep_for(std::chrono::seconds(sleepSeconds));
    return 0;
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
