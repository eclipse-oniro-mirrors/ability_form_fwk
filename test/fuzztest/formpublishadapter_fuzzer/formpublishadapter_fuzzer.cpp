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
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_mgr/form_publish_adapter.h"
#undef private
#undef protected

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

    // Fuzz SetPublishFormResult
    int64_t resultFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Constants::PublishFormResult errorCodeInfo;
    errorCodeInfo.code = static_cast<Constants::PublishFormErrorCode>(fdp->ConsumeIntegralInRange<int32_t>(0, 10));
    errorCodeInfo.message = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.SetPublishFormResult(resultFormId, errorCodeInfo);

    // Fuzz RemoveFormIdMapElement
    int64_t removeFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.RemoveFormIdMapElement(removeFormId);

    // Fuzz CancelAddFormRequestTimeOutTask
    int64_t cancelFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t cancelResult = fdp->ConsumeIntegralInRange<int32_t>(MIN_RESULT, MAX_RESULT);
    adapter.CancelAddFormRequestTimeOutTask(cancelFormId, cancelResult);

    // Fuzz CheckAddFormTaskTimeoutOrFailed
    int64_t checkFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    AddFormResultErrorCodes formStates;
    adapter.CheckAddFormTaskTimeoutOrFailed(checkFormId, formStates);

    // Fuzz QueryPublishFormToHost
    Want wantToHost = GenerateWant(fdp);
    adapter.QueryPublishFormToHost(wantToHost);

    // Fuzz QueryPublishFormToHost with userId
    Want wantToHostUser = GenerateWant(fdp);
    int32_t userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    adapter.QueryPublishFormToHost(wantToHostUser, userId);

    // Fuzz CheckPublishForm
    Want checkWant = GenerateWant(fdp);
    bool needCheckFormPermission = fdp->ConsumeBool();
    adapter.CheckPublishForm(checkWant, needCheckFormPermission);

    // Fuzz RequestPublishFormCommon
    Want commonWant = GenerateWant(fdp);
    int32_t commonUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    int64_t commonFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.RequestPublishFormCommon(commonWant, commonUserId, commonFormId);

    // Fuzz GetCallerType
    std::string callerBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.GetCallerType(callerBundleName);

    // Fuzz CheckSnapshotWant
    Want snapshotWant = GenerateWant(fdp);
    adapter.CheckSnapshotWant(snapshotWant);

    // Fuzz RequestPublishForm (5-arg variant with binding data + formId out-param)
    Want publishWant = GenerateWant(fdp);
    bool withFormBindingData = fdp->ConsumeBool();
    std::unique_ptr<FormProviderData> formBindingData = nullptr;
    int64_t publishFormId = 0;
    std::vector<FormDataProxy> formDataProxies;
    bool needCheckFormPermissionPublish = fdp->ConsumeBool();
    adapter.RequestPublishForm(publishWant, withFormBindingData, formBindingData, publishFormId,
        formDataProxies, needCheckFormPermissionPublish);

    // Fuzz CheckFormBundleName (private; bundleName is out-param)
    Want bundleNameWant = GenerateWant(fdp);
    std::string bundleNameOut;
    bool bundleNameCheckPermission = fdp->ConsumeBool();
    adapter.CheckFormBundleName(bundleNameWant, bundleNameOut, bundleNameCheckPermission);

    // Fuzz IsValidPublishEvent (private; pass nullptr IBundleMgr to hit error path)
    Want publishEventWant = GenerateWant(fdp);
    std::string publishEventBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    sptr<IBundleMgr> nullBundleMgr = nullptr;
    bool publishEventCheckPermission = fdp->ConsumeBool();
    adapter.IsValidPublishEvent(nullBundleMgr, publishEventBundleName, publishEventWant,
        publishEventCheckPermission);

    // Fuzz AcquireAddFormResult
    int64_t acquireFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.AcquireAddFormResult(acquireFormId);

    // Fuzz IsErmsSupportPublishForm
    std::string ermsBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::vector<Want> ermsWants;
    adapter.IsErmsSupportPublishForm(ermsBundleName, ermsWants);

    // Fuzz RequestPublishFormToHost (private, single-arg)
    Want toHostWant = GenerateWant(fdp);
    adapter.RequestPublishFormToHost(toHostWant);

    // Fuzz RequestPublishFormToHost (private, two-arg with userId)
    Want toHostUserWant = GenerateWant(fdp);
    int32_t toHostUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    adapter.RequestPublishFormToHost(toHostUserWant, toHostUserId);

    // Fuzz RequestPublishFormCrossUser
    Want crossUserWant = GenerateWant(fdp);
    int32_t crossUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    int64_t crossUserFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.RequestPublishFormCrossUser(crossUserWant, crossUserId, crossUserFormId);

    // Fuzz CheckIsSystemAppByBundleName (private; pass nullptr IBundleMgr)
    int32_t systemAppUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    std::string systemAppBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.CheckIsSystemAppByBundleName(nullBundleMgr, systemAppUserId, systemAppBundleName);

    // Fuzz IncreaseAddFormRequestTimeOutTask (private)
    int64_t increaseTimeoutFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.IncreaseAddFormRequestTimeOutTask(increaseTimeoutFormId);

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
