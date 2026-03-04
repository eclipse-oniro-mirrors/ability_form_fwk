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

#include "formiteminfo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_info/form_item_info.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    FormItemInfo formItemInfo;

    std::string dir(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    std::vector<std::string> dirs;
    dirs.emplace_back(dir);
    formItemInfo.SetHapSourceDirs(dirs);
    formItemInfo.GetHapSourceDirs(dirs);

    std::string moduleName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.GetHapSourceByModuleName(moduleName);

    std::string hapSourceDir(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.AddModuleInfo(moduleName, hapSourceDir);

    std::string packageName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.AddModulePkgName(moduleName, packageName);

    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    formItemInfo.SetFormId(formId);
    formItemInfo.GetFormId();

    formItemInfo.SetPackageName(packageName);
    formItemInfo.GetPackageName();

    std::string providerBundleName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetProviderBundleName(providerBundleName);
    formItemInfo.GetProviderBundleName();

    std::string hostBundleName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetHostBundleName(hostBundleName);
    formItemInfo.GetHostBundleName();

    formItemInfo.SetModuleName(moduleName);
    formItemInfo.GetModuleName();

    std::string abilityName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetAbilityName(abilityName);
    formItemInfo.GetAbilityName();

    std::string formName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetFormName(formName);
    formItemInfo.GetFormName();

    std::string jsComponentName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetJsComponentName(jsComponentName);
    formItemInfo.GetJsComponentName();

    std::string abilityModuleName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetAbilityModuleName(abilityModuleName);
    formItemInfo.GetAbilityModuleName();

    int specificationId = fdp->ConsumeIntegral<int>();
    formItemInfo.SetSpecificationId(specificationId);
    formItemInfo.GetSpecificationId();

    bool isEnableUpdateFlag = fdp->ConsumeBool();
    formItemInfo.SetEnableUpdateFlag(isEnableUpdateFlag);
    formItemInfo.IsEnableUpdateFlag();

    int updateDuration = fdp->ConsumeIntegral<int>();
    formItemInfo.SetUpdateDuration(updateDuration);
    formItemInfo.GetUpdateDuration();

    std::string scheduledUpdateTime(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetScheduledUpdateTime(scheduledUpdateTime);
    formItemInfo.GetScheduledUpdateTime();

    std::string multiScheduledUpdateTime(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetMultiScheduledUpdateTime(multiScheduledUpdateTime);
    formItemInfo.GetMultiScheduledUpdateTime();

    bool temporaryFlag = fdp->ConsumeBool();
    formItemInfo.SetTemporaryFlag(temporaryFlag);
    formItemInfo.IsTemporaryForm();

    bool isFormVisibleNotify = fdp->ConsumeBool();
    formItemInfo.SetFormVisibleNotify(isFormVisibleNotify);
    formItemInfo.IsFormVisibleNotify();

    std::string formSrc(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetFormSrc(formSrc);
    formItemInfo.GetFormSrc();

    FormWindow formWindow;
    formWindow.designWidth = fdp->ConsumeIntegral<int32_t>();
    formItemInfo.SetFormWindow(formWindow);
    formItemInfo.GetFormWindow();

    uint32_t versionCode = fdp->ConsumeIntegral<uint32_t>();
    formItemInfo.SetVersionCode(versionCode);
    formItemInfo.GetVersionCode();

    std::string versionName(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetVersionName(versionName);
    formItemInfo.GetVersionName();

    uint32_t compatibleVersion = fdp->ConsumeIntegral<uint32_t>();
    formItemInfo.SetCompatibleVersion(compatibleVersion);
    formItemInfo.GetCompatibleVersion();

    formItemInfo.GetIcon();

    std::string deviceId(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetDeviceId(deviceId);
    formItemInfo.GetDeviceId();

    FormType type = FormType::ETS;
    formItemInfo.SetType(type);
    formItemInfo.GetType();

    bool isDynamic = fdp->ConsumeBool();
    formItemInfo.SetIsDynamic(isDynamic);
    formItemInfo.IsDynamic();

    bool transparencyEnabled = fdp->ConsumeBool();
    formItemInfo.SetTransparencyEnabled(transparencyEnabled);
    formItemInfo.IsTransparencyEnabled();

    int32_t privacyLevel = fdp->ConsumeIntegral<int32_t>();
    formItemInfo.SetPrivacyLevel(privacyLevel);
    formItemInfo.GetPrivacyLevel();

    FormType uiSyntax = FormType::ETS;
    formItemInfo.SetUiSyntax(uiSyntax);
    formItemInfo.GetUiSyntax();

    bool isSystemApp = fdp->ConsumeBool();
    formItemInfo.SetSystemAppFlag(isSystemApp);
    formItemInfo.GetSystemAppFlag();

    bool dataProxyEnabled = fdp->ConsumeBool();
    formItemInfo.SetDataProxyFlag(dataProxyEnabled);
    formItemInfo.GetDataProxyFlag();

    int32_t uid = fdp->ConsumeIntegral<int32_t>();
    formItemInfo.SetProviderUid(uid);
    formItemInfo.GetProviderUid();

    std::string description(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetDescription(description);
    formItemInfo.GetDescription();

    Constants::FormLocation formLocation = Constants::FormLocation::DESKTOP;
    formItemInfo.SetFormLocation(formLocation);
    formItemInfo.GetFormLocation();

    bool isThemeForm = fdp->ConsumeBool();
    formItemInfo.SetIsThemeForm(isThemeForm);
    formItemInfo.GetIsThemeForm();
    BundleType bundleType = BundleType::APP_SERVICE_FWK;
    formItemInfo.SetFormBundleType(bundleType);
    formItemInfo.GetFormBundleType();

    bool enableForm = fdp->ConsumeBool();
    formItemInfo.SetEnableForm(enableForm);
    formItemInfo.IsEnableForm();

    Constants::RenderingMode renderingMode = Constants::RenderingMode::FULL_COLOR;
    formItemInfo.SetRenderingMode(renderingMode);
    formItemInfo.GetRenderingMode();

    bool lockForm = fdp->ConsumeBool();
    formItemInfo.SetLockForm(lockForm);
    formItemInfo.IsLockForm();

    bool protectForm = fdp->ConsumeBool();
    formItemInfo.SetProtectForm(protectForm);
    formItemInfo.IsProtectForm();

    std::vector<int32_t> conditionUpdate;
    int32_t numConditions = fdp->ConsumeIntegralInRange(0, 10);
    for (int32_t i = 0; i < numConditions; i++) {
        conditionUpdate.push_back(fdp->ConsumeIntegral<int32_t>());
    }
    formItemInfo.SetConditionUpdate(conditionUpdate);
    formItemInfo.GetConditionUpdate();

    bool dataProxyIgnoreFormVisibility = fdp->ConsumeBool();
    formItemInfo.SetDataProxyIgnoreFormVisibility(dataProxyIgnoreFormVisibility);
    formItemInfo.GetDataProxyIgnoreFormVisibility();

    bool isDistributedForm = fdp->ConsumeBool();
    formItemInfo.SetDistributedForm(isDistributedForm);
    formItemInfo.IsDistributedForm();

    std::string uiModule(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetUiModuleName(uiModule);
    formItemInfo.GetUiModuleName();

    std::string templateFormImperativeFwk(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.SetTemplateFormImperativeFwk(templateFormImperativeFwk);
    formItemInfo.GetTemplateFormImperativeFwk();

    bool isTemplateForm = fdp->ConsumeBool();
    formItemInfo.SetIsTemplateForm(isTemplateForm);
    formItemInfo.GetIsTemplateForm();

    formItemInfo.IsValidItem();

    std::string left(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    std::string right(fdp->ConsumeRandomLengthString(MAX_LENGTH));
    formItemInfo.IsEqual(left, right);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
