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

#include "formvisibilityadapter_fuzzer.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unordered_map>
#include <vector>

#define private public
#define protected public
#include "form_mgr/form_visibility_adapter.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_instance.h"
#include "want.h"

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 0;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_FORM_VISIBLE_TYPE = 3;
constexpr int32_t MIN_FORM_VISIBLE_TYPE = 0;
constexpr int32_t MAX_TOKEN_ID = 100000;
constexpr int32_t MIN_TOKEN_ID = 0;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_FORM_LOCATION = 4;
constexpr int32_t MAX_HOUR = 23;
constexpr int32_t MAX_MINUTE = 59;

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

FormInstance GenerateFormInstance(FuzzedDataProvider *fdp)
{
    FormInstance formInstance;
    formInstance.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    formInstance.bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    formInstance.moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    formInstance.abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    formInstance.formName = GenerateSafeString(fdp, MAX_LENGTH);
    formInstance.specification = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    return formInstance;
}

std::unordered_map<std::string, std::vector<FormInstance>> GenerateFormInstanceMaps(FuzzedDataProvider *fdp)
{
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    int32_t mapSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < mapSize; ++i) {
        std::string key = GenerateSafeString(fdp, MAX_LENGTH);
        int32_t vecSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
        std::vector<FormInstance> instances;
        for (int32_t j = 0; j < vecSize; ++j) {
            instances.push_back(GenerateFormInstance(fdp));
        }
        formInstanceMaps[key] = instances;
    }
    return formInstanceMaps;
}

std::unordered_map<std::string, std::vector<int64_t>> GenerateEventMaps(FuzzedDataProvider *fdp)
{
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    int32_t mapSize = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < mapSize; ++i) {
        std::string key = GenerateSafeString(fdp, MAX_LENGTH);
        eventMaps[key] = GenerateFormIdVector(fdp);
    }
    return eventMaps;
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

    auto &adapter = FormVisibilityAdapter::GetInstance();

    // Fuzz Init
    adapter.Init();

    // Fuzz NotifyWhetherVisibleForms with nullptr callerToken (tests error path)
    std::vector<int64_t> visibleFormIds = GenerateFormIdVector(fdp);
    sptr<IRemoteObject> visibleCallerToken = nullptr;
    int32_t formVisibleType = fdp->ConsumeIntegralInRange<int32_t>(MIN_FORM_VISIBLE_TYPE, MAX_FORM_VISIBLE_TYPE);
    adapter.NotifyWhetherVisibleForms(visibleFormIds, visibleCallerToken, formVisibleType);

    // Fuzz HasFormVisible
    uint32_t tokenId = static_cast<uint32_t>(fdp->ConsumeIntegralInRange<int32_t>(MIN_TOKEN_ID, MAX_TOKEN_ID));
    adapter.HasFormVisible(tokenId);

    // Fuzz NotifyFormsVisible with nullptr callerToken
    std::vector<int64_t> notifyVisibleFormIds = GenerateFormIdVector(fdp);
    bool isVisible = fdp->ConsumeBool();
    sptr<IRemoteObject> notifyVisibleCallerToken = nullptr;
    adapter.NotifyFormsVisible(notifyVisibleFormIds, isVisible, notifyVisibleCallerToken);

    // Fuzz NotifyFormsEnableUpdate with nullptr callerToken
    std::vector<int64_t> enableUpdateFormIds = GenerateFormIdVector(fdp);
    bool isEnableUpdate = fdp->ConsumeBool();
    sptr<IRemoteObject> enableUpdateCallerToken = nullptr;
    adapter.NotifyFormsEnableUpdate(enableUpdateFormIds, isEnableUpdate, enableUpdateCallerToken);

    // Fuzz SetFormsRecyclable
    std::vector<int64_t> recyclableFormIds = GenerateFormIdVector(fdp);
    adapter.SetFormsRecyclable(recyclableFormIds);

    // Fuzz NotifyFormLocked
    int64_t lockedFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    bool isLocked = fdp->ConsumeBool();
    adapter.NotifyFormLocked(lockedFormId, isLocked);

    // Fuzz PaddingNotifyVisibleFormsMap
    int32_t paddingVisibleType = fdp->ConsumeIntegralInRange<int32_t>(MIN_FORM_VISIBLE_TYPE, MAX_FORM_VISIBLE_TYPE);
    int64_t paddingFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    std::unordered_map<std::string, std::vector<FormInstance>> paddingMaps = GenerateFormInstanceMaps(fdp);
    adapter.PaddingNotifyVisibleFormsMap(paddingVisibleType, paddingFormId, paddingMaps);

    // Fuzz HandlerNotifyWhetherVisibleForms with nullptr callerToken
    std::vector<int64_t> handlerFormIds = GenerateFormIdVector(fdp);
    std::unordered_map<std::string, std::vector<FormInstance>> handlerInstanceMaps = GenerateFormInstanceMaps(fdp);
    std::unordered_map<std::string, std::vector<int64_t>> handlerEventMaps = GenerateEventMaps(fdp);
    int32_t handlerVisibleType = fdp->ConsumeIntegralInRange<int32_t>(MIN_FORM_VISIBLE_TYPE, MAX_FORM_VISIBLE_TYPE);
    sptr<IRemoteObject> handlerCallerToken = nullptr;
    adapter.HandlerNotifyWhetherVisibleForms(handlerFormIds, handlerInstanceMaps, handlerEventMaps,
        handlerVisibleType, handlerCallerToken);

    // Fuzz SetVisibleChange (private)
    int64_t setVisibleFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t setVisibleType = fdp->ConsumeIntegralInRange<int32_t>(MIN_FORM_VISIBLE_TYPE, MAX_FORM_VISIBLE_TYPE);
    int32_t setUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    adapter.SetVisibleChange(setVisibleFormId, setVisibleType, setUserId);

    // Fuzz HandleEventNotify (private). Use a provider key with delimiters to exercise both
    // success path and error path (no delimiter) via fuzzed string.
    std::string providerKey = GenerateSafeString(fdp, MAX_LENGTH);
    std::vector<int64_t> eventFormIds = GenerateFormIdVector(fdp);
    int32_t eventVisibleType = fdp->ConsumeIntegralInRange<int32_t>(MIN_FORM_VISIBLE_TYPE, MAX_FORM_VISIBLE_TYPE);
    adapter.HandleEventNotify(providerKey, eventFormIds, eventVisibleType);

    // Fuzz PostVisibleNotify (private) with minimal inputs and nullptr callerToken
    std::vector<int64_t> postVisibleFormIds = GenerateFormIdVector(fdp);
    std::unordered_map<std::string, std::vector<FormInstance>> postInstanceMaps;
    std::unordered_map<std::string, std::vector<int64_t>> postEventMaps;
    int32_t postVisibleType = fdp->ConsumeIntegralInRange<int32_t>(MIN_FORM_VISIBLE_TYPE, MAX_FORM_VISIBLE_TYPE);
    int32_t postNotifyDelay = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    sptr<IRemoteObject> postCallerToken = nullptr;
    adapter.PostVisibleNotify(postVisibleFormIds, postInstanceMaps, postEventMaps, postVisibleType,
        postNotifyDelay, postCallerToken);

    // Fuzz CreateHandleEventMap (private)
    int64_t createHandleFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    FormRecord createHandleRecord = GenerateFormRecord(fdp);
    std::unordered_map<std::string, std::vector<int64_t>> createHandleEventMaps = GenerateEventMaps(fdp);
    adapter.CreateHandleEventMap(createHandleFormId, createHandleRecord, createHandleEventMaps);

    // Fuzz UpdateProviderInfoToHost (private) with nullptr callerToken
    int64_t updateFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t updateUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    sptr<IRemoteObject> updateCallerToken = nullptr;
    int32_t updateVisibleType = fdp->ConsumeIntegralInRange<int32_t>(MIN_FORM_VISIBLE_TYPE, MAX_FORM_VISIBLE_TYPE);
    FormRecord updateRecord = GenerateFormRecord(fdp);
    adapter.UpdateProviderInfoToHost(updateFormId, updateUserId, updateCallerToken, updateVisibleType, updateRecord);

    // Fuzz isFormShouldUpdateProviderInfoToHost (private) with nullptr callerToken
    int64_t checkFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int32_t checkUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    sptr<IRemoteObject> checkCallerToken = nullptr;
    FormRecord checkRecord = GenerateFormRecord(fdp);
    adapter.isFormShouldUpdateProviderInfoToHost(checkFormId, checkUserId, checkCallerToken, checkRecord);

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
