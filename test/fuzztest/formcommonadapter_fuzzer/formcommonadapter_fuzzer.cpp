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

#include "formcommonadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unordered_map>
#include <vector>

#define private public
#define protected public
#include "form_mgr/form_common_adapter.h"
#undef private
#undef protected

#include "form_info.h"
#include "form_major_info.h"
#include "want.h"

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 1;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    want.SetElementName(fdp->ConsumeRandomLengthString(MAX_LENGTH),
                        fdp->ConsumeRandomLengthString(MAX_LENGTH));
    want.SetAction(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    return want;
}

FormInfo GenerateFormInfo(FuzzedDataProvider *fdp)
{
    FormInfo formInfo;
    formInfo.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.name = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.description = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.type = static_cast<FormType>(fdp->ConsumeIntegral<int32_t>());
    formInfo.uiSyntax = static_cast<FormType>(fdp->ConsumeIntegral<int32_t>());
    formInfo.defaultDimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    formInfo.updateEnabled = fdp->ConsumeBool();
    formInfo.updateDuration = fdp->ConsumeIntegral<int64_t>();
    formInfo.scheduledUpdateTime = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.isDynamic = fdp->ConsumeBool();
    formInfo.isTemplateForm = fdp->ConsumeBool();
    formInfo.transparencyEnabled = fdp->ConsumeBool();
    formInfo.privacyLevel = fdp->ConsumeIntegral<int32_t>();
    return formInfo;
}

FormMajorInfo GenerateFormMajorInfo(FuzzedDataProvider *fdp)
{
    FormMajorInfo majorInfo;
    majorInfo.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    majorInfo.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    majorInfo.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    majorInfo.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    majorInfo.dimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    return majorInfo;
}

FormRecord GenerateFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord record;
    record.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    record.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.specification = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    record.isEnableUpdate = fdp->ConsumeBool();
    record.formTempFlag = fdp->ConsumeBool();
    record.updateDuration = fdp->ConsumeIntegral<int64_t>();
    record.updateAtHour = fdp->ConsumeIntegralInRange<int32_t>(0, 23);
    record.updateAtMin = fdp->ConsumeIntegralInRange<int32_t>(0, 59);
    record.providerUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.isDataProxy = fdp->ConsumeBool();
    record.isSystemApp = fdp->ConsumeBool();
    record.formLocation = static_cast<Constants::FormLocation>(fdp->ConsumeIntegral<int32_t>());
    return record;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormCommonAdapter::GetInstance();

    // Fuzz GetFormConfigInfo
    Want want = GenerateWant(fdp);
    FormItemInfo formItemInfo;
    adapter.GetFormConfigInfo(want, formItemInfo);

    // Fuzz GetBundleInfo
    BundleInfo bundleInfo;
    std::string packageName;
    adapter.GetBundleInfo(want, bundleInfo, packageName);

    // Fuzz GetFormInfo
    FormInfo formInfo;
    adapter.GetFormInfo(want, formInfo);

    // Fuzz CreateFormItemInfo
    FormInfo fuzzedFormInfo = GenerateFormInfo(fdp);
    FormItemInfo itemInfo;
    adapter.CreateFormItemInfo(bundleInfo, fuzzedFormInfo, itemInfo);

    // Fuzz GetFormItemInfo
    FormItemInfo formItemInfo2;
    adapter.GetFormItemInfo(want, bundleInfo, fuzzedFormInfo, formItemInfo2);

    // Fuzz SetFormItemInfoParams
    adapter.SetFormItemInfoParams(bundleInfo, fuzzedFormInfo, itemInfo);

    // Fuzz SetFormItemModuleInfo
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    hapModuleInfo.packageName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    hapModuleInfo.hapPath = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.SetFormItemModuleInfo(hapModuleInfo, fuzzedFormInfo, itemInfo);

    // Fuzz SetHostBundleName
    FormItemInfo hostItemInfo;
    adapter.SetHostBundleName(want, hostItemInfo);

    // Fuzz IsDimensionValid
    int32_t dimensionId = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    adapter.IsDimensionValid(fuzzedFormInfo, dimensionId);

    // Fuzz GetFormInfoByFormRecord
    FormRecord record = GenerateFormRecord(fdp);
    FormInfo formInfoByRecord;
    adapter.GetFormInfoByFormRecord(record, formInfoByRecord);

    // Fuzz RegisterAddObserver
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    sptr<IRemoteObject> callerToken = nullptr;
    adapter.RegisterAddObserver(bundleName, callerToken);

    // Fuzz RegisterRemoveObserver
    adapter.RegisterRemoveObserver(bundleName, callerToken);

    // Fuzz CleanResource
    wptr<IRemoteObject> remoteObj = nullptr;
    adapter.CleanResource(remoteObj);

    // Fuzz SetDeathRecipient
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    adapter.SetDeathRecipient(callerToken, deathRecipient);

    // Fuzz GetCallerType
    std::string callerBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.GetCallerType(callerBundleName);

    // Fuzz GetCallingUserId
    adapter.GetCallingUserId();

    // Fuzz GetAppMgr
    adapter.GetAppMgr();

    // Fuzz GetFormObservers
    adapter.GetFormObservers();

    // Fuzz SetFormEnableAndLockState
    FormInfo enableFormInfo = GenerateFormInfo(fdp);
    FormItemInfo enableItemInfo;
    int32_t formLocation = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
    adapter.SetFormEnableAndLockState(enableFormInfo, enableItemInfo, formLocation);

    // Fuzz SetLockFormStateOfFormItemInfo
    adapter.SetLockFormStateOfFormItemInfo(enableFormInfo, enableItemInfo);

    // Fuzz CheckUpdateFormRecord
    FormItemInfo checkItemInfo;
    FormRecord checkRecord = GenerateFormRecord(fdp);
    adapter.CheckUpdateFormRecord(checkRecord.formId, checkItemInfo, checkRecord);

    // Fuzz CheckFormDueControl
    FormMajorInfo majorInfo = GenerateFormMajorInfo(fdp);
    bool isDisablePolicy = fdp->ConsumeBool();
    adapter.CheckFormDueControl(majorInfo, isDisablePolicy);

    // Fuzz HandleFormAddObserver
    int64_t observerFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.HandleFormAddObserver(observerFormId);

    // Fuzz AddFormTimer
    FormRecord timerRecord = GenerateFormRecord(fdp);
    adapter.AddFormTimer(timerRecord);

    // Fuzz GetValidFormUpdateDuration
    int64_t durationFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    int64_t updateDuration = 0;
    adapter.GetValidFormUpdateDuration(durationFormId, updateDuration);

    // Fuzz UpdateFormCloudUpdateDuration
    std::string cloudBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    adapter.UpdateFormCloudUpdateDuration(cloudBundleName);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}