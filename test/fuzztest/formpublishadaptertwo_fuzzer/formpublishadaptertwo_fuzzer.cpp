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

#include "formpublishadaptertwo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <mutex>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_mgr/form_publish_adapter.h"
#undef private
#undef protected
#include "form_constants.h"

using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 0;
constexpr int32_t MAX_USER_ID = 100;
constexpr int32_t MIN_USER_ID = 0;
constexpr int32_t MAX_RESULT = 10;
constexpr int32_t MIN_RESULT = -10;

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    want.SetElementName(fdp->ConsumeRandomLengthString(MAX_LENGTH),
        fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetAction(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    return want;
}

// Helper function to set up formIdMap with specific state for coverage
void SetupFormIdMapWithState(FormPublishAdapter &adapter,
    FuzzedDataProvider *fdp, int64_t &formId, OHOS::AppExecFwk::AddFormResultErrorCodes state)
{
    Want want = GenerateWant(fdp);
    int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);

    // Set required parameters for RequestPublishFormCommon
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetParam(AppExecFwk::Constants::PARAM_FORM_NAME_KEY, fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, fdp->ConsumeIntegralInRange<int32_t>(0, 10));

    // Call RequestPublishFormCommon to insert data into formIdMap
    adapter.RequestPublishFormCommon(want, userId, formId);

    // Manually set the desired state
    std::lock_guard<std::mutex> lock(adapter.formResultMutex_);
    adapter.formIdMap_[formId] = state;
    adapter.condition_.notify_all();
}

// Helper function to create a valid Want for form operations
Want CreateValidFormWant(FuzzedDataProvider *fdp)
{
    Want want = GenerateWant(fdp);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetParam(AppExecFwk::Constants::PARAM_FORM_NAME_KEY, fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, fdp->ConsumeIntegralInRange<int32_t>(0, 10));
    want.SetParam(Constants::PARAM_FORM_USER_ID, fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID));
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID)));
    return want;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormPublishAdapter::GetInstance();

    // Fuzz GetCallerType
    std::string callerBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.GetCallerType(callerBundleName);

    // Fuzz CheckSnapshotWant
    Want snapshotWant = GenerateWant(fdp);
    adapter.CheckSnapshotWant(snapshotWant);

    // Fuzz QueryPublishFormToHost
    Want wantToHost = GenerateWant(fdp);
    adapter.QueryPublishFormToHost(wantToHost);

    // Fuzz QueryPublishFormToHost with userId
    Want wantToHostUser = GenerateWant(fdp);
    int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    adapter.QueryPublishFormToHost(wantToHostUser, userId);

    // Fuzz RequestPublishFormCommon with proper setup
    Want commonWant = CreateValidFormWant(fdp);
    int32_t commonUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    int64_t commonFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.RequestPublishFormCommon(commonWant, commonUserId, commonFormId);

    // Fuzz RemoveFormIdMapElement
    int64_t removeFormId;
    SetupFormIdMapWithState(adapter, fdp, removeFormId, OHOS::AppExecFwk::AddFormResultErrorCodes::UNKNOWN);
    adapter.RemoveFormIdMapElement(removeFormId);

    // Fuzz CheckAddFormTaskTimeoutOrFailed with FAILED state
    int64_t checkFormId;
    SetupFormIdMapWithState(adapter, fdp, checkFormId, OHOS::AppExecFwk::AddFormResultErrorCodes::FAILED);
    AddFormResultErrorCodes formStates;
    adapter.CheckAddFormTaskTimeoutOrFailed(checkFormId, formStates);

    // Fuzz CheckAddFormTaskTimeoutOrFailed with TIMEOUT state
    int64_t checkFormId2;
    SetupFormIdMapWithState(adapter, fdp, checkFormId2, OHOS::AppExecFwk::AddFormResultErrorCodes::TIMEOUT);
    AddFormResultErrorCodes formStates2;
    adapter.CheckAddFormTaskTimeoutOrFailed(checkFormId2, formStates2);

    // Fuzz CheckAddFormTaskTimeoutOrFailed with UNKNOWN state
    int64_t checkFormId3;
    SetupFormIdMapWithState(adapter, fdp, checkFormId3, OHOS::AppExecFwk::AddFormResultErrorCodes::UNKNOWN);
    AddFormResultErrorCodes formStates3;
    adapter.CheckAddFormTaskTimeoutOrFailed(checkFormId3, formStates3);

    // Fuzz AcquireAddFormResult with SUCCESS state
    int64_t acquireFormId;
    SetupFormIdMapWithState(adapter, fdp, acquireFormId, OHOS::AppExecFwk::AddFormResultErrorCodes::SUCCESS);
    adapter.AcquireAddFormResult(acquireFormId);

    // Fuzz AcquireAddFormResult with FAILED state
    int64_t acquireFormId2;
    SetupFormIdMapWithState(adapter, fdp, acquireFormId2, OHOS::AppExecFwk::AddFormResultErrorCodes::FAILED);
    adapter.AcquireAddFormResult(acquireFormId2);

    // Fuzz AcquireAddFormResult with TIMEOUT state
    int64_t acquireFormId3;
    SetupFormIdMapWithState(adapter, fdp, acquireFormId3, OHOS::AppExecFwk::AddFormResultErrorCodes::TIMEOUT);
    adapter.AcquireAddFormResult(acquireFormId3);

    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
