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

#include "formlifecycleadapter_fuzzer.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#define private public
#define protected public
#include "form_mgr/form_lifecycle_adapter.h"
#undef private
#undef protected

#include "configuration.h"
#include "form_constants.h"
#include "form_js_info.h"
#include "running_form_info.h"
#include "want.h"

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 0;
constexpr int32_t MAX_USER_ID = 1000;
constexpr int32_t MIN_USER_ID = 0;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_FORM_LOCATION = 4;
constexpr int32_t MAX_HOUR = 23;
constexpr int32_t MAX_MINUTE = 59;
constexpr int32_t MAX_NUM_FORMS_DELETED = 1000;

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

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    want.SetElementName(GenerateSafeString(fdp, MAX_LENGTH), GenerateSafeString(fdp, MAX_LENGTH));
    want.SetAction(GenerateSafeString(fdp, MAX_LENGTH));
    return want;
}

std::vector<int64_t> GenerateFormIdVector(FuzzedDataProvider *fdp)
{
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    std::vector<int64_t> formIds;
    for (int32_t i = 0; i < size; ++i) {
        formIds.push_back(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID));
    }
    return formIds;
}

RunningFormInfo GenerateRunningFormInfo(FuzzedDataProvider *fdp)
{
    RunningFormInfo runningFormInfo;
    runningFormInfo.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    runningFormInfo.bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.formName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.hostBundleName = GenerateSafeString(fdp, MAX_LENGTH);
    runningFormInfo.dimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    runningFormInfo.userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    return runningFormInfo;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormLifecycleAdapter::GetInstance();

    // Fuzz AddForm with nullptr callerToken (tests error path)
    int64_t addFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want addWant = GenerateWant(fdp);
    sptr<IRemoteObject> addCallerToken = nullptr;
    FormJsInfo addFormInfo;
    adapter.AddForm(addFormId, addWant, addCallerToken, addFormInfo);

    // Fuzz DeleteForm with nullptr callerToken
    int64_t deleteFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> deleteCallerToken = nullptr;
    adapter.DeleteForm(deleteFormId, deleteCallerToken);

    // Fuzz ReleaseForm with nullptr callerToken
    int64_t releaseFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> releaseCallerToken = nullptr;
    bool delCache = fdp->ConsumeBool();
    adapter.ReleaseForm(releaseFormId, releaseCallerToken, delCache);

    // Fuzz CastTempForm with nullptr callerToken
    int64_t castFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    sptr<IRemoteObject> castCallerToken = nullptr;
    adapter.CastTempForm(castFormId, castCallerToken);

    // Fuzz CreateForm
    Want createWant = GenerateWant(fdp);
    RunningFormInfo createRunningFormInfo;
    adapter.CreateForm(createWant, createRunningFormInfo);

    // Fuzz StopRenderingForm
    int64_t stopFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string stopCompId = GenerateSafeString(fdp, MAX_LENGTH);
    adapter.StopRenderingForm(stopFormId, stopCompId);

    // Fuzz ReleaseRenderer
    int64_t releaseRendererFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string releaseCompId = GenerateSafeString(fdp, MAX_LENGTH);
    adapter.ReleaseRenderer(releaseRendererFormId, releaseCompId);

    // Fuzz DeleteInvalidForms with nullptr callerToken
    std::vector<int64_t> invalidFormIds = GenerateFormIdVector(fdp);
    sptr<IRemoteObject> invalidCallerToken = nullptr;
    int32_t numFormsDeleted = 0;
    adapter.DeleteInvalidForms(invalidFormIds, invalidCallerToken, numFormsDeleted);

    // Fuzz EnableForms
    std::string enableBundleName = GenerateSafeString(fdp, MAX_LENGTH);
    int32_t enableUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    bool enable = fdp->ConsumeBool();
    adapter.EnableForms(enableBundleName, enableUserId, enable);

    // Fuzz ProtectLockForms
    std::string protectBundleName = GenerateSafeString(fdp, MAX_LENGTH);
    int32_t protectUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    bool protect = fdp->ConsumeBool();
    adapter.ProtectLockForms(protectBundleName, protectUserId, protect);

    // Fuzz RecoverForms
    std::vector<int64_t> recoverFormIds = GenerateFormIdVector(fdp);
    Want recoverWant = GenerateWant(fdp);
    adapter.RecoverForms(recoverFormIds, recoverWant);

    // Fuzz RecycleForms
    std::vector<int64_t> recycleFormIds = GenerateFormIdVector(fdp);
    Want recycleWant = GenerateWant(fdp);
    bool isCheckCallingUid = fdp->ConsumeBool();
    adapter.RecycleForms(recycleFormIds, recycleWant, isCheckCallingUid);

    // Fuzz SwitchLockForms
    std::string switchBundleName = GenerateSafeString(fdp, MAX_LENGTH);
    int32_t switchUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    bool lock = fdp->ConsumeBool();
    adapter.SwitchLockForms(switchBundleName, switchUserId, lock);

    // Fuzz BatchNotifyFormsConfigurationUpdate
    Configuration configuration;
    adapter.BatchNotifyFormsConfigurationUpdate(configuration);

    // Fuzz HandleFormRemoveObserver
    RunningFormInfo removeObserverInfo = GenerateRunningFormInfo(fdp);
    adapter.HandleFormRemoveObserver(removeObserverInfo);

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
