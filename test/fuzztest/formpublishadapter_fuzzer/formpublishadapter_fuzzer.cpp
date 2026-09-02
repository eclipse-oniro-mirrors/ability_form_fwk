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

#include "formpublishadapter_fuzzer.h"

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

// The fuzz target links the real form service stack, whose FormDataMgr registers a
// memory-watermark parameter watcher. Its IPC-thread callback can submit ffrt tasks
// after the global scheduler is torn down at process exit (heap-use-after-free). The
// watcher path is not reachable from fuzz input, so stub the registration as no-op.
extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

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

    // Fuzz IsRequestPublishFormSupported
    adapter.IsRequestPublishFormSupported();

    // Fuzz IsActionAllowToPublish
    std::string action = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.IsActionAllowToPublish(action);

    // Fuzz CheckPublishForm
    Want checkWant = GenerateWant(fdp);
    bool needCheckFormPermission = fdp->ConsumeBool();
    adapter.CheckPublishForm(checkWant, needCheckFormPermission);

    // Fuzz CheckFormBundleName (private; bundleName is out-param)
    Want bundleNameWant = GenerateWant(fdp);
    std::string bundleNameOut;
    bool bundleNameCheckPermission = fdp->ConsumeBool();
    adapter.CheckFormBundleName(bundleNameWant, bundleNameOut, bundleNameCheckPermission);

    // Fuzz IsValidPublishEvent (private)
    Want publishEventWant = GenerateWant(fdp);
    std::string publishEventBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    bool publishEventCheckPermission = fdp->ConsumeBool();
    adapter.IsValidPublishEvent(publishEventBundleName, publishEventWant, publishEventCheckPermission);

    // Fuzz IsErmsSupportPublishForm
    std::string ermsBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<Want> ermsWants;
    adapter.IsErmsSupportPublishForm(ermsBundleName, ermsWants);

    // Fuzz CheckIsSystemAppByBundleName (private)
    int32_t systemAppUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    std::string systemAppBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.CheckIsSystemAppByBundleName(systemAppUserId, systemAppBundleName);

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
