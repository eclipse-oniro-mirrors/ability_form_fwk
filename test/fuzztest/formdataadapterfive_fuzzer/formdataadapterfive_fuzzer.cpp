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

#include "formdataadapterfive_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <chrono>
#include <thread>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#define private public
#define protected public
#include "form_mgr/form_data_adapter.h"
#undef private
#undef protected

#include "form_info.h"
#include "form_instance.h"
#include "form_major_info.h"
#include "form_provider_data.h"
#include "form_record_filter.h"
#include "want.h"
#include "want_params.h"
#include "data_center/form_info/form_item_info.h"

using namespace OHOS::AppExecFwk;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 128;
constexpr int32_t MAX_VECTOR_SIZE = 10;
constexpr int32_t MAX_FORM_ID = 10000;
constexpr int32_t MIN_FORM_ID = 1;
constexpr int32_t MAX_CALLING_UID = 10000;
constexpr int32_t MIN_CALLING_UID = 0;
constexpr int32_t MAX_DIMENSION_ID = 10;
constexpr int32_t MIN_DIMENSION_ID = 0;
constexpr int32_t MAX_DATA_SIZE = 1024;
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
constexpr int32_t MAX_BUNDLE_TYPE = 2;
constexpr int32_t MAX_RENDERING_MODE = 2;
constexpr int32_t MAX_STRING_LENGTH_16 = 16;
constexpr int32_t MAX_STRING_LENGTH_32 = 32;
constexpr int32_t MAX_STRING_LENGTH_64 = 64;

Want GenerateWant(FuzzedDataProvider *fdp)
{
    Want want;
    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string action = fdp->ConsumeRandomLengthString(MAX_LENGTH);

    if (!bundleName.empty() && !abilityName.empty()) {
        want.SetElementName(bundleName, abilityName);
    }

    if (!action.empty()) {
        want.SetAction(action);
    }

    return want;
}

std::vector<int64_t> GenerateFormIds(FuzzedDataProvider *fdp)
{
    std::vector<int64_t> formIds;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        formIds.push_back(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID));
    }
    return formIds;
}

FormItemInfo GenerateFormItemInfo(FuzzedDataProvider *fdp)
{
    FormItemInfo formInfo;
    formInfo.SetFormId(fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID));

    std::string packageName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetPackageName(packageName.empty() ? "default.package" : packageName);

    std::string providerBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetProviderBundleName(providerBundleName.empty() ? "default.provider.bundle" : providerBundleName);

    std::string hostBundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetHostBundleName(hostBundleName.empty() ? "default.host.bundle" : hostBundleName);

    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetModuleName(moduleName.empty() ? "default.module" : moduleName);

    std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetAbilityName(abilityName.empty() ? "default.ability" : abilityName);

    std::string formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetFormName(formName.empty() ? "default.form" : formName);

    formInfo.SetSpecificationId(fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID));
    formInfo.SetEnableUpdateFlag(fdp->ConsumeBool());
    formInfo.SetUpdateDuration(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_UPDATE_DURATION));

    std::string scheduledUpdateTime = fdp->ConsumeRandomLengthString(MAX_STRING_LENGTH_16);
    formInfo.SetScheduledUpdateTime(scheduledUpdateTime);

    formInfo.SetTemporaryFlag(fdp->ConsumeBool());
    formInfo.SetFormVisibleNotify(fdp->ConsumeBool());

    std::string formSrc = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetFormSrc(formSrc);

    formInfo.SetVersionCode(fdp->ConsumeIntegralInRange<uint32_t>(MIN_VERSION_CODE, MAX_VERSION_CODE));

    std::string versionName = fdp->ConsumeRandomLengthString(MAX_STRING_LENGTH_32);
    formInfo.SetVersionName(versionName.empty() ? "1.0.0" : versionName);

    formInfo.SetCompatibleVersion(fdp->ConsumeIntegralInRange<uint32_t>(MIN_COMPATIBLE_VERSION,
        MAX_COMPATIBLE_VERSION));
    formInfo.SetType(static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE)));
    formInfo.SetUiSyntax(static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE)));
    formInfo.SetIsDynamic(fdp->ConsumeBool());
    formInfo.SetTransparencyEnabled(fdp->ConsumeBool());
    formInfo.SetPrivacyLevel(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_PRIVACY_LEVEL));

    std::string jsComponentName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetJsComponentName(jsComponentName);

    std::string abilityModuleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetAbilityModuleName(abilityModuleName);

    std::string deviceId = fdp->ConsumeRandomLengthString(MAX_STRING_LENGTH_64);
    formInfo.SetDeviceId(deviceId);

    formInfo.SetDataProxyFlag(fdp->ConsumeBool());
    formInfo.SetSystemAppFlag(fdp->ConsumeBool());
    formInfo.SetProviderUid(fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID));

    std::string description = fdp->ConsumeRandomLengthString(256);
    formInfo.SetDescription(description);

    formInfo.SetFormLocation(static_cast<OHOS::AppExecFwk::Constants::FormLocation>(
        fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_LOCATION)));
    formInfo.SetIsThemeForm(fdp->ConsumeBool());
    formInfo.SetFormBundleType(static_cast<BundleType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_BUNDLE_TYPE)));
    formInfo.SetEnableForm(fdp->ConsumeBool());
    formInfo.SetRenderingMode(static_cast<OHOS::AppExecFwk::Constants::RenderingMode>(
        fdp->ConsumeIntegralInRange<int32_t>(0, MAX_RENDERING_MODE)));
    formInfo.SetLockForm(fdp->ConsumeBool());
    formInfo.SetProtectForm(fdp->ConsumeBool());
    formInfo.SetDataProxyIgnoreFormVisibility(fdp->ConsumeBool());
    formInfo.SetDistributedForm(fdp->ConsumeBool());

    std::string uiModuleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formInfo.SetUiModuleName(uiModuleName);

    formInfo.SetIsTemplateForm(fdp->ConsumeBool());

    std::string templateFormImperativeFwk = fdp->ConsumeRandomLengthString(64);
    formInfo.SetTemplateFormImperativeFwk(templateFormImperativeFwk);

    return formInfo;
}

FormRecord GenerateFormRecord(FuzzedDataProvider *fdp)
{
    FormRecord record;
    record.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);

    std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.bundleName = bundleName.empty() ? "default.bundle" : bundleName;

    std::string moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.moduleName = moduleName.empty() ? "default.module" : moduleName;

    std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.abilityName = abilityName.empty() ? "default.ability" : abilityName;

    std::string formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    record.formName = formName.empty() ? "default.form" : formName;

    record.specification = fdp->ConsumeIntegralInRange<int32_t>(MIN_DIMENSION_ID, MAX_DIMENSION_ID);
    record.isEnableUpdate = fdp->ConsumeBool();
    record.formTempFlag = fdp->ConsumeBool();
    record.updateDuration = fdp->ConsumeIntegralInRange<int64_t>(0, MAX_UPDATE_DURATION);
    record.updateAtHour = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_HOUR);
    record.updateAtMin = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_MINUTE);
    record.providerUserId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.isDataProxy = fdp->ConsumeBool();
    record.isSystemApp = fdp->ConsumeBool();
    record.needRefresh = fdp->ConsumeBool();
    record.formLocation = static_cast<Constants::FormLocation>(fdp->ConsumeIntegralInRange<int32_t>(0,
        MAX_FORM_LOCATION));

    record.userId = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.uid = fdp->ConsumeIntegralInRange<int32_t>(MIN_CALLING_UID, MAX_CALLING_UID);
    record.versionCode = fdp->ConsumeIntegralInRange<uint32_t>(MIN_VERSION_CODE, MAX_VERSION_CODE);
    record.versionName = fdp->ConsumeRandomLengthString(MAX_STRING_LENGTH_32);
    if (record.versionName.empty()) {
        record.versionName = "1.0.0";
    }
    record.compatibleVersion = fdp->ConsumeIntegralInRange<uint32_t>(MIN_COMPATIBLE_VERSION, MAX_COMPATIBLE_VERSION);
    record.type = static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE));
    record.uiSyntax = static_cast<FormType>(fdp->ConsumeIntegralInRange<int32_t>(0, MAX_FORM_TYPE));
    record.isDynamic = fdp->ConsumeBool();
    record.transparencyEnabled = fdp->ConsumeBool();
    record.privacyLevel = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_PRIVACY_LEVEL);

    return record;
}

std::vector<FormRecord> GenerateFormRecords(FuzzedDataProvider *fdp)
{
    std::vector<FormRecord> records;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        records.push_back(GenerateFormRecord(fdp));
    }
    return records;
}

FormProviderData GenerateFormProviderData(FuzzedDataProvider *fdp)
{
    std::string data = fdp->ConsumeRandomLengthString(MAX_DATA_SIZE);
    if (data.empty()) {
        data = "{}";
    }
    FormProviderData formProviderData(data);
    return formProviderData;
}

std::vector<FormDataProxy> GenerateFormDataProxies(FuzzedDataProvider *fdp)
{
    std::vector<FormDataProxy> proxies;
    int32_t size = fdp->ConsumeIntegralInRange<int32_t>(0, MAX_VECTOR_SIZE);
    for (int32_t i = 0; i < size; i++) {
        std::string bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        std::string abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        if (!bundleName.empty() && !abilityName.empty()) {
            FormDataProxy proxy(bundleName, abilityName);
            proxies.push_back(proxy);
        }
    }
    return proxies;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    auto &adapter = FormDataAdapter::GetInstance();

    // Fuzz AcquireProviderFormInfoByFormRecord
    FormRecord providerRecord = GenerateFormRecord(fdp);
    WantParams providerWantParams;
    adapter.AcquireProviderFormInfoByFormRecord(providerRecord, providerWantParams);

    // Fuzz AcquireProviderFormInfoAsync
    FormItemInfo formItemInfo = GenerateFormItemInfo(fdp);
    WantParams wantParams;
    int64_t acquireFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.AcquireProviderFormInfoAsync(acquireFormId, formItemInfo, wantParams);

    // Fuzz ReAcquireProviderFormInfoAsync
    adapter.ReAcquireProviderFormInfoAsync(formItemInfo, wantParams);

    // Fuzz InnerAcquireProviderFormInfoAsync (private, accessible via macro)
    int64_t innerAcquireFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    FormItemInfo innerFormItemInfo = GenerateFormItemInfo(fdp);
    WantParams innerWantParams;
    adapter.InnerAcquireProviderFormInfoAsync(innerAcquireFormId, innerFormItemInfo, innerWantParams);

    // Fuzz OnNotifyRefreshForm
    int64_t notifyFormId = fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
    adapter.OnNotifyRefreshForm(notifyFormId);

    return true;
}
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(1));
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
