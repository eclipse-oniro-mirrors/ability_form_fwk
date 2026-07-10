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

#include "formpublishadapterthree_fuzzer.h"

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

    // Fuzz IncreaseAddFormRequestTimeOutTask
    int64_t increaseFormId;
    SetupFormIdMapWithState(adapter, fdp, increaseFormId, OHOS::AppExecFwk::AddFormResultErrorCodes::UNKNOWN);
    adapter.IncreaseAddFormRequestTimeOutTask(increaseFormId);

    // Fuzz CancelAddFormRequestTimeOutTask
    int64_t cancelFormId;
    SetupFormIdMapWithState(adapter, fdp, cancelFormId, OHOS::AppExecFwk::AddFormResultErrorCodes::UNKNOWN);
    int32_t cancelResult = fdp->ConsumeIntegralInRange<int32_t>(MIN_RESULT, MAX_RESULT);
    adapter.CancelAddFormRequestTimeOutTask(cancelFormId, cancelResult);

    // Fuzz SetPublishFormResult with existing formId (covers state update branches)
    int64_t resultFormId;
    SetupFormIdMapWithState(adapter, fdp, resultFormId, OHOS::AppExecFwk::AddFormResultErrorCodes::UNKNOWN);
    Constants::PublishFormResult errorCodeInfo;
    errorCodeInfo.code = static_cast<Constants::PublishFormErrorCode>(fdp->ConsumeIntegralInRange<int32_t>(0, 10));
    errorCodeInfo.message = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.SetPublishFormResult(resultFormId, errorCodeInfo);

    // Fuzz RequestPublishForm (5-arg variant with binding data + formId out-param) with proper setup
    Want publishWant = CreateValidFormWant(fdp);
    bool withFormBindingData = fdp->ConsumeBool();
    std::unique_ptr<FormProviderData> formBindingData = nullptr;
    int64_t publishFormId = 0;
    std::vector<FormDataProxy> formDataProxies;
    bool needCheckFormPermissionPublish = fdp->ConsumeBool();
    adapter.RequestPublishForm(publishWant, withFormBindingData, formBindingData, publishFormId,
        formDataProxies, needCheckFormPermissionPublish);

    // Fuzz RequestPublishFormToHost (private, single-arg) with proper setup
    Want toHostWant = CreateValidFormWant(fdp);
    int64_t toHostFormId;
    SetupFormIdMapWithState(adapter, fdp, toHostFormId, OHOS::AppExecFwk::AddFormResultErrorCodes::UNKNOWN);
    adapter.RequestPublishFormToHost(toHostWant);

    // Fuzz RequestPublishFormToHost (private, two-arg with userId) with proper setup
    Want toHostUserWant = CreateValidFormWant(fdp);
    int64_t toHostUserFormId;
    SetupFormIdMapWithState(adapter, fdp, toHostUserFormId, OHOS::AppExecFwk::AddFormResultErrorCodes::SUCCESS);
    int32_t toHostUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    adapter.RequestPublishFormToHost(toHostUserWant, toHostUserId);

    // Fuzz RequestPublishFormCrossUser with proper setup
    Want crossUserWant = CreateValidFormWant(fdp);
    int32_t crossUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    int64_t crossUserFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.RequestPublishFormCrossUser(crossUserWant, crossUserId, crossUserFormId);

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
