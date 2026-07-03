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

#include "formeventadapter_fuzzer.h"

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
#include "want.h"

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 0;
constexpr int32_t MAX_OPEN_TYPE = 4;
constexpr int32_t MIN_OPEN_TYPE = 0;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;
constexpr int32_t MAX_FORM_LOCATION = 4;
constexpr int32_t MAX_HOUR = 23;
constexpr int32_t MAX_MINUTE = 59;
constexpr int32_t MAX_USER_ID = 1000;
constexpr int32_t MIN_USER_ID = 0;

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

FormRecord GenerateFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord record;
    record.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    record.bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    record.moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    record.abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    record.formName = GenerateSafeString(fdp, MAX_LENGTH);
    record.specification = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    record.isEnableUpdate = fdp->ConsumeBool();
    record.formTempFlag = fdp->ConsumeBool();
    record.updateDuration = fdp->ConsumeIntegral<int64_t>();
    record.updateAtHour = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_HOUR);
    record.updateAtMin = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_MINUTE);
    record.providerUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.isDataProxy = fdp->ConsumeBool();
    record.isSystemApp = fdp->ConsumeBool();
    record.uid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.formLocation = static_cast<Constants::FormLocation>(
        fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_LOCATION));
    return record;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormEventAdapter::GetInstance();

    // Fuzz MessageEvent with nullptr callerToken (tests error path)
    int64_t messageFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want messageWant = GenerateWant(fdp);
    messageWant.SetParam(Constants::PARAM_MESSAGE_KEY, GenerateSafeString(fdp, MAX_LENGTH));
    sptr<IRemoteObject> messageCallerToken = nullptr;
    adapter.MessageEvent(messageFormId, messageWant, messageCallerToken);

    // Fuzz RouterEvent with nullptr callerToken
    int64_t routerFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want routerWant = GenerateWant(fdp);
    sptr<IRemoteObject> routerCallerToken = nullptr;
    adapter.RouterEvent(routerFormId, routerWant, routerCallerToken);

    // Fuzz BackgroundEvent with nullptr callerToken
    int64_t backgroundFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    Want backgroundWant = GenerateWant(fdp);
    sptr<IRemoteObject> backgroundCallerToken = nullptr;
    adapter.BackgroundEvent(backgroundFormId, backgroundWant, backgroundCallerToken);

    // Fuzz SetFreeInstallFlag
    FormRecord freeInstallRecord = GenerateFormRecord(fdp);
    Want freeInstallWant = GenerateWant(fdp);
    adapter.SetFreeInstallFlag(freeInstallRecord, freeInstallWant);

    // Fuzz OpenByOpenType with varied openType values (covers all enum branches)
    FormRecord openRecord = GenerateFormRecord(fdp);
    Want openWant = GenerateWant(fdp);
    sptr<IRemoteObject> openCallerToken = nullptr;
    int32_t openResult = 0;
    int32_t openType = fdp->ConsumeIntegralInRange<int32_t>(MIN_OPEN_TYPE, MAX_OPEN_TYPE);
    adapter.OpenByOpenType(openType, openRecord, openCallerToken, openWant, openResult);

    // Fuzz OpenByOpenType with another random openType for more branch coverage
    FormRecord openRecord2 = GenerateFormRecord(fdp);
    Want openWant2 = GenerateWant(fdp);
    int32_t openResult2 = 0;
    int32_t openType2 = fdp->ConsumeIntegralInRange<int32_t>(MIN_OPEN_TYPE, MAX_OPEN_TYPE);
    adapter.OpenByOpenType(openType2, openRecord2, openCallerToken, openWant2, openResult2);

    // Fuzz NotifyFormClickEvent (private, exposed via #define private public)
    int64_t clickFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::string clickType = GenerateSafeString(fdp, MAX_LENGTH);
    int32_t clickUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_USER_ID, MAX_USER_ID);
    adapter.NotifyFormClickEvent(clickFormId, clickType, clickUserId);

    // Fuzz CheckKeepBackgroundRunningPermission with nullptr iBundleMgr (error path)
    sptr<IBundleMgr> bundleMgr = nullptr;
    std::string keepBundleName = GenerateSafeString(fdp, MAX_LENGTH);
    adapter.CheckKeepBackgroundRunningPermission(bundleMgr, keepBundleName);

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
