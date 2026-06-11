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

#include <cctype>
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
constexpr int32_t MAX_UPDATE_DURATION = 3600;
constexpr int32_t MAX_HOUR = 23;
constexpr int32_t MAX_MINUTE = 59;
constexpr int32_t MAX_VERSION_CODE = 1000;
constexpr int32_t MIN_VERSION_CODE = 1;
constexpr int32_t MAX_COMPATIBLE_VERSION = 100;
constexpr int32_t MIN_COMPATIBLE_VERSION = 1;
constexpr int32_t MAX_FORM_TYPE = 2;
constexpr int32_t MAX_PRIVACY_LEVEL = 3;
constexpr int32_t MAX_FORM_LOCATION = 4;
constexpr int32_t MAX_FORM_LOCATION_TYPE = 5;
constexpr int32_t MAX_STRING_LENGTH_16 = 16;
constexpr int32_t MAX_STRING_LENGTH_32 = 32;
constexpr int32_t MAX_STRING_LENGTH_64 = 64;
constexpr int32_t MAX_STRING_LENGTH_256 = 256;
constexpr int32_t MAX_BUNDLE_TYPE = 2;
constexpr int32_t MAX_RENDERING_MODE = 2;

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

FormInfo GenerateFormInfo(FuzzedDataProvider *fdp)
{
    FormInfo formInfo;
    formInfo.bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    formInfo.moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    formInfo.abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    formInfo.name = GenerateSafeString(fdp, MAX_LENGTH);
    formInfo.description = GenerateSafeString(fdp, MAX_LENGTH);
    formInfo.type = static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE));
    formInfo.uiSyntax = static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE));
    formInfo.defaultDimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    formInfo.updateEnabled = fdp->ConsumeBool();
    formInfo.updateDuration = fdp->ConsumeIntegral<int64_t>();
    formInfo.scheduledUpdateTime = GenerateSafeString(fdp, MAX_LENGTH);
    formInfo.isDynamic = fdp->ConsumeBool();
    formInfo.isTemplateForm = fdp->ConsumeBool();
    formInfo.transparencyEnabled = fdp->ConsumeBool();
    formInfo.privacyLevel = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_PRIVACY_LEVEL);
    return formInfo;
}

FormMajorInfo GenerateFormMajorInfo(FuzzedDataProvider *fdp)
{
    FormMajorInfo majorInfo;
    majorInfo.bundleName = GenerateSafeString(fdp, MAX_LENGTH);
    majorInfo.moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    majorInfo.abilityName = GenerateSafeString(fdp, MAX_LENGTH);
    majorInfo.formName = GenerateSafeString(fdp, MAX_LENGTH);
    majorInfo.dimension = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    return majorInfo;
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
    record.formLocation = static_cast<Constants::FormLocation>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_LOCATION));
    return record;
}

HapModuleInfo GenerateHapModuleInfo(FuzzedDataProvider *fdp)
{
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.moduleName = GenerateSafeString(fdp, MAX_LENGTH);
    hapModuleInfo.packageName = GenerateSafeString(fdp, MAX_LENGTH);
    hapModuleInfo.hapPath = GenerateSafeString(fdp, MAX_LENGTH);
    hapModuleInfo.versionCode = fdp->ConsumeIntegralInRange<uint32_t>(MIN_VERSION_CODE, MAX_VERSION_CODE);

    hapModuleInfo.abilityInfos.clear();

    return hapModuleInfo;
}

FormItemInfo GenerateFormItemInfo(FuzzedDataProvider *fdp)
{
    FormItemInfo itemInfo;
    itemInfo.SetFormId(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID));

    itemInfo.SetPackageName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetProviderBundleName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetHostBundleName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetModuleName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetAbilityName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetFormName(GenerateSafeString(fdp, MAX_LENGTH));

    itemInfo.SetSpecificationId(fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID));
    itemInfo.SetEnableUpdateFlag(fdp->ConsumeBool());
    itemInfo.SetUpdateDuration(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_UPDATE_DURATION));

    itemInfo.SetScheduledUpdateTime(GenerateSafeString(fdp, MAX_STRING_LENGTH_16));

    itemInfo.SetTemporaryFlag(fdp->ConsumeBool());
    itemInfo.SetFormVisibleNotify(fdp->ConsumeBool());

    itemInfo.SetFormSrc(GenerateSafeString(fdp, MAX_LENGTH));

    itemInfo.SetVersionCode(fdp->ConsumeIntegralInRange<uint32_t>(MIN_VERSION_CODE, MAX_VERSION_CODE));

    itemInfo.SetVersionName(GenerateSafeString(fdp, MAX_STRING_LENGTH_32));

    itemInfo.SetCompatibleVersion(fdp->ConsumeIntegralInRange<uint32_t>(MIN_COMPATIBLE_VERSION,
        MAX_COMPATIBLE_VERSION));
    itemInfo.SetType(static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE)));
    itemInfo.SetUiSyntax(static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE)));
    itemInfo.SetIsDynamic(fdp->ConsumeBool());
    itemInfo.SetTransparencyEnabled(fdp->ConsumeBool());
    itemInfo.SetPrivacyLevel(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_PRIVACY_LEVEL));

    itemInfo.SetJsComponentName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetAbilityModuleName(GenerateSafeString(fdp, MAX_LENGTH));
    itemInfo.SetDeviceId(GenerateSafeString(fdp, MAX_STRING_LENGTH_64));

    itemInfo.SetDataProxyFlag(fdp->ConsumeBool());
    itemInfo.SetSystemAppFlag(fdp->ConsumeBool());
    itemInfo.SetProviderUid(fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID));

    itemInfo.SetDescription(GenerateSafeString(fdp, MAX_STRING_LENGTH_256));

    itemInfo.SetFormLocation(static_cast<OHOS::AppExecFwk::Constants::FormLocation>(
        fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_LOCATION)));
    itemInfo.SetIsThemeForm(fdp->ConsumeBool());
    itemInfo.SetFormBundleType(static_cast<BundleType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_BUNDLE_TYPE)));
    itemInfo.SetEnableForm(fdp->ConsumeBool());
    itemInfo.SetRenderingMode(static_cast<OHOS::AppExecFwk::Constants::RenderingMode>(
        fdp->ConsumeIntegralInRange<int32_t>(0, MAX_RENDERING_MODE)));
    itemInfo.SetLockForm(fdp->ConsumeBool());
    itemInfo.SetProtectForm(fdp->ConsumeBool());
    itemInfo.SetDataProxyIgnoreFormVisibility(fdp->ConsumeBool());
    itemInfo.SetDistributedForm(fdp->ConsumeBool());

    itemInfo.SetUiModuleName(GenerateSafeString(fdp, MAX_LENGTH));

    itemInfo.SetIsTemplateForm(fdp->ConsumeBool());

    itemInfo.SetTemplateFormImperativeFwk(GenerateSafeString(fdp, MAX_STRING_LENGTH_64));

    return itemInfo;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormCommonAdapter::GetInstance();

    // Fuzz GetFormConfigInfo
    Want want = GenerateWant(fdp);
    FormItemInfo formItemInfo = GenerateFormItemInfo(fdp);
    adapter.GetFormConfigInfo(want, formItemInfo);

    // Fuzz GetBundleInfo
    BundleInfo bundleInfo;
    std::string packageName;
    adapter.GetBundleInfo(want, bundleInfo, packageName);

    // Fuzz GetFormInfo
    FormInfo formInfo = GenerateFormInfo(fdp);
    adapter.GetFormInfo(want, formInfo);

    // Fuzz CreateFormItemInfo
    FormInfo fuzzedFormInfo = GenerateFormInfo(fdp);
    FormItemInfo itemInfo = GenerateFormItemInfo(fdp);
    adapter.CreateFormItemInfo(bundleInfo, fuzzedFormInfo, itemInfo);

    // Fuzz GetFormItemInfo
    FormItemInfo formItemInfo2 = GenerateFormItemInfo(fdp);
    adapter.GetFormItemInfo(want, bundleInfo, fuzzedFormInfo, formItemInfo2);

    // Fuzz SetFormItemInfoParams
    adapter.SetFormItemInfoParams(bundleInfo, fuzzedFormInfo, itemInfo);

    // Fuzz SetFormItemModuleInfo
    HapModuleInfo hapModuleInfo = GenerateHapModuleInfo(fdp);
    FormItemInfo newItemInfo = GenerateFormItemInfo(fdp);
    adapter.SetFormItemModuleInfo(hapModuleInfo, fuzzedFormInfo, newItemInfo);

    // Fuzz SetHostBundleName
    FormItemInfo hostItemInfo = GenerateFormItemInfo(fdp);
    adapter.SetHostBundleName(want, hostItemInfo);

    // Fuzz IsDimensionValid
    int32_t dimensionId = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    adapter.IsDimensionValid(fuzzedFormInfo, dimensionId);

    // Fuzz GetFormInfoByFormRecord
    FormRecord record = GenerateFormRecord(fdp);
    FormInfo formInfoByRecord = GenerateFormInfo(fdp);
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
    FormItemInfo enableItemInfo = GenerateFormItemInfo(fdp);
    int32_t formLocation = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_LOCATION_TYPE);
    adapter.SetFormEnableAndLockState(enableFormInfo, enableItemInfo, formLocation);

    // Fuzz SetLockFormStateOfFormItemInfo
    adapter.SetLockFormStateOfFormItemInfo(enableFormInfo, enableItemInfo);

    // Fuzz CheckUpdateFormRecord
    FormItemInfo checkItemInfo = GenerateFormItemInfo(fdp);
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