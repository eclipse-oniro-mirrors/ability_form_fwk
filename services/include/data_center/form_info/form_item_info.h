/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#ifndef OHOS_FORM_FWK_FORM_ITEM_INFO_H
#define OHOS_FORM_FWK_FORM_ITEM_INFO_H

#include <string>
#include <unordered_map>
#include <vector>
#include "form_constants.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
class FormItemInfo {
public:
    /**
     * @brief Get formId_.
     * @return formId_.
     */
    int64_t GetFormId() const;
    /**
     * @brief Set value of formId_.
     * @param formId Form Id.
     */
    void SetFormId(int64_t formId);
    /**
     * @brief Get packageName_.
     * @return packageName_.
     */
    std::string GetPackageName() const;
    /**
     * @brief Set value of packageName_.
     * @param packageName Package name.
     */
    void SetPackageName(const std::string &packageName);
    /**
     * @brief Get providerBundleName_.
     * @return providerBundleName_.
     */
    std::string GetProviderBundleName() const;
    /**
     * @brief Set value of providerBundleName_.
     * @param providerBundleName Provider bundle Name.
     */
    void SetProviderBundleName(const std::string &providerBundleName);
    /**
     * @brief Get hostBundleName_.
     * @return hostBundleName_.
     */
    std::string GetHostBundleName() const;
    /**
     * @brief Set value of hostBundleName_.
     * @param hostBundleName_ Host bundle Name.
     */
    void SetHostBundleName(const std::string &hostBundleName);
    /**
     * @brief Get moduleName_.
     * @return moduleName_.
     */
    std::string GetModuleName() const;
    /**
     * @brief Set value of moduleName_.
     * @param moduleName Module Name.
     */
    void SetModuleName(const std::string &moduleName);
    /**
     * @brief Get abilityName_.
     * @return abilityName_.
     */
    std::string GetAbilityName() const;
    /**
     * @brief Set value of abilityName_.
     * @param abilityName Ability name.
     */
    void SetAbilityName(const std::string &abilityName);
    /**
     * @brief Get formName_.
     * @return formName_.
     */
    std::string GetFormName() const;
    /**
     * @brief Set value of formName_.
     * @param formName Form name.
     */
    void SetFormName(const std::string &formName);
    /**
     * @brief Get jsComponentName_.
     * @return jsComponentName_.
     */
    std::string GetJsComponentName() const;
    /**
     * @brief Set value of jsComponentName_.
     * @param jsComponentName Js component name.
     */
    void SetJsComponentName(const std::string &jsComponentName);
    /**
     * @brief Get abilityModuleName_.
     * @return abilityModuleName_.
     */
    std::string GetAbilityModuleName() const;
    /**
     * @brief Set value of abilityModuleName_.
     * @param abilityModuleName ability module name_.
     */
    void SetAbilityModuleName(const std::string &abilityModuleName);
    /**
     * @brief Get specificationId_.
     * @return specificationId_.
     */
    int GetSpecificationId() const;
    /**
     * @brief Set value of specificationId_.
     * @param specificationId Specification id.
     */
    void SetSpecificationId(const int specificationId);

    /**
     * @brief Obtains the updateFlag.
     * @return Returns updateFlag.
     */
    bool IsEnableUpdateFlag() const;
    /**
     * @brief Set value of updateFlag_.
     * @param isEnableUpdateFlag Enable update flag or not.
     */
    void SetEnableUpdateFlag(bool isEnableUpdateFlag);
    /**
     * @brief Get updateDuration_.
     * @return updateDuration_.
     */
    int GetUpdateDuration() const;
    /**
     * @brief Set value of updateDuration_.
     * @param updateDuration Update duration.
     */
    void SetUpdateDuration(int updateDuration);
    /**
     * @brief Get scheduledUpdateTime_.
     * @return scheduledUpdateTime_.
     */
    std::string GetScheduledUpdateTime() const;
    /**
     * @brief Get multiScheduledUpdateTime_.
     * @return multiScheduledUpdateTime_.
     */
    std::string GetMultiScheduledUpdateTime() const;
    /**
     * @brief Set value of scheduledUpdateTime_.
     * @param scheduledUpdateTime Scheduled update time.
     */
    void SetScheduledUpdateTime(const std::string &scheduledUpdateTime);
    /**
     * @brief Set value of multiScheduledUpdateTime_.
     * @param multiScheduledUpdateTime Scheduled update time.
     */
    void SetMultiScheduledUpdateTime(const std::string &multiScheduledUpdateTime);
    /**
     * @brief Get hapSourceDirs_.
     * @param dirs Hap source dirs.
     * @return Returns true on success, false on failure.
     */
    bool GetHapSourceDirs(std::vector<std::string> &dirs) const;
    /**
     * @brief Add hap source dir.
     * @param hapSourceDir Hap source dir.
     */
    void AddHapSourceDirs(const std::string &hapSourceDir);
    /**
     * @brief Set value of hapSourceDirs_.
     * @param hapSourceDirs Hap source dirs.
     */
    void SetHapSourceDirs(const std::vector<std::string> &hapSourceDirs);
    /**
     * @brief Obtains the temporaryFlag.
     * @return Returns temporaryFlag.
     */
    bool IsTemporaryForm() const;
    /**
     * @brief Set value of temporaryFlag_.
     * @param temporaryFlag Temporary flag.
     */
    void SetTemporaryFlag(bool temporaryFlag);
    /**
     * @brief Obtains the hap source by ability module name.
     * @param moduleName ability module name
     * @return Returns hap source.
     */
    std::string GetHapSourceByModuleName(const std::string &moduleName) const;
    /**
     * @brief Add module info.
     * @param moduleName Module name.
     * @param moduleSourceDir Module source dir.
     */
    void AddModuleInfo(const std::string &moduleName, const std::string &moduleSourceDir);
    /**
     * @brief Add module package name.
     * @param moduleName Module name.
     * @param packageName Package name.
     */
    void AddModulePkgName(const std::string &moduleName, const std::string &packageName);
    /**
     * @brief Get module package name map.
     * @return Module package name map
     */
    const std::map<std::string, std::string>& GetModulePkgNameMap() const;
    /**
     * @brief Check if item valid or not.
     * @return Valid or not
     */
    bool IsValidItem() const;
    /**
     * @brief Check if item match or not.
     * @return Match or not
     */
    bool IsMatch(const FormRecord &record) const;
    /**
     * @brief Check if form config same or not.
     * @return Same or not
     */
    bool IsSameFormConfig(const FormRecord &record) const;
    /**
     * @brief Check if visible notify or not.
     * @return visible notify or not
     */
    bool IsFormVisibleNotify() const;
    /**
     * @brief Set value of formVisibleNotify_.
     * @param isFormVisibleNotify visible notify or not.
     */
    void SetFormVisibleNotify(bool isFormVisibleNotify);
    /**
     * @brief Get formSrc_.
     * @return formSrc_.
     */
    std::string GetFormSrc() const;
    /**
     * @brief Set value of formSrc_.
     * @param formSrc form src.
     */
    void SetFormSrc(const std::string &formSrc);
    /**
     * @brief Get formWindow_.
     * @return formWindow_.
     */
    FormWindow GetFormWindow() const;
    /**
     * @brief Set value of formWindow_.
     * @param formWindow form window.
     */
    void SetFormWindow(const FormWindow &formWindow);
    /**
     * @brief Get versionCode_.
     * @return versionCode_.
     */
    uint32_t GetVersionCode() const;
    /**
     * @brief Set value of versionCode_.
     * @param versionCode bundle version code.
     */
    void SetVersionCode(const uint32_t versionCode);
    /**
     * @brief Get versionName_.
     * @return versionName_.
     */
    std::string GetVersionName() const;
    /**
     * @brief Set value of versionName_.
     * @param versionName bundle version name.
     */
    void SetVersionName(const std::string &versionName);
    /**
     * @brief Get compatibleVersion_.
     * @return compatibleVersion_.
     */
    uint32_t GetCompatibleVersion() const;
    /**
     * @brief Set value of compatibleVersion_.
     * @param compatibleVersion API compatible version.
     */
    void SetCompatibleVersion(const uint32_t &compatibleVersion);
    /**
     * @brief Get icon_.
     * @return icon_.
     */
    std::string GetIcon() const;
    /**
     * @brief Get deviceId_.
     * @return deviceId_.
     */
    std::string GetDeviceId();
    /**
     * @brief Set value of  deviceId_.
     * @param deviceId.
     */
    void SetDeviceId(const std::string &deviceId);
    /**
     * @brief Get type_.
     * @return type_.
     */
    FormType GetType() const;
    /**
     * @brief Set value of type_.
     * @param type.
     */
    void SetType(const FormType &type);
    /**
     * @brief Obtains the isDynamic.
     * @return Returns isDynamic.
     */
    bool IsDynamic() const;
    /**
     * @brief Set value of isDynamic.
     * @param isDynamic isDynamic flag.
     */
    void SetIsDynamic(bool isDynamic);
    /**
     * @brief Obtains the transparencyEnabled.
     * @return Returns transparencyEnabled.
     */
    bool IsTransparencyEnabled() const;
    /**
     * @brief Set value of transparencyEnabled.
     * @param isTransparencyEnabled transparencyEnabled flag.
     */
    void SetTransparencyEnabled(bool isTransparencyEnabled);
    /**
     * @brief Obtains the privacyLevel.
     * @return Returns privacyLevel.
     */
    int32_t GetPrivacyLevel() const;
    /**
     * @brief Set value of privacyLevel.
     * @param level privacyLevel.
     */
    void SetPrivacyLevel(int32_t level);
    /**
     * @brief Get uiSyntax.
     * @return uiSyntax.
     */
    FormType GetUiSyntax() const;
    /**
     * @brief Set value of uiSyntax.
     * @param uiSyntax.
     */
    void SetUiSyntax(const FormType &uiSyntax);
    /**
     * @brief Set value of isSystemApp.
     * @param isSystemApp systemAppFlag.
     */
    void SetSystemAppFlag(bool isSystemApp);
    /**
     * @brief Get systemAppFlag.
     * @return systemAppFlag.
     */
    bool GetSystemAppFlag() const;

    void SetDataProxyFlag(bool dataProxyEnabled);
    bool GetDataProxyFlag() const;

    /**
     * @brief save the uid of formProvider.
     * @param uid the uid of formProvider.
     */
    void SetProviderUid(int32_t uid);
    /**
     * @brief Get the uid of formProvider.
     * @return uid.
     */
    int32_t GetProviderUid() const;

    /**
     * @brief Save the description of formInfo.
     * @param description The description of formInfo.
     */
    void SetDescription(const std::string &description);
    /**
     * @brief Get the description of formInfo.
     * @return description.
     */
    std::string GetDescription() const;

    /**
     * @brief Get the formLocation of formInfo.
     * @return formLocation.
     */
    Constants::FormLocation GetFormLocation() const;

    /**
     * @brief set the formLocation.
     * @param formLocation The FormLocation.
     */
    void SetFormLocation(Constants::FormLocation formLocation);

    /**
     * @brief Get whether it belongs to theme form.
     * @return is theme form or not.
     */
    bool GetIsThemeForm() const;

    /**
     * @brief Set whether it belongs to theme form.
     * @param isThemeForm is theme form or not.
     */
    void SetIsThemeForm(bool isThemeForm);

    /**
     * @brief Get bundleType of formProvider.
     * @return bundleType of from.
     */
    BundleType GetFormBundleType() const;

    /**
     * @brief Set bundleType of formProvider.
     * @param formBundleType formBundleType
     */
    void SetFormBundleType(BundleType formBundleType);

    /**
     * @brief Get whether form bundle is enable.
     * @return True for enable form bundle, false for disable form bundle.
     */
    bool IsEnableForm() const;

    /**
     * @brief Set whether form bundle is enable.
     * @param enableForm True for enable form bundle, false for disable form bundle.
     */
    void SetEnableForm(bool enableForm);

    /**
     * @brief Get renderingMode of form.
     * @return renderingMode of from.
     */
    Constants::RenderingMode GetRenderingMode() const;

    /**
     * @brief Set renderingMode of form.
     * @param renderingMode renderingMode
     */
    void SetRenderingMode(Constants::RenderingMode renderingMode);

    /**
     * @brief Get whether is lock.
     * @return True for lock, false for unlock.
     */
    bool IsLockForm() const;

    /**
     * @brief Set whether is lock.
     * @param lockForm True for lock, false for unlock.
     */
    void SetLockForm(bool lockForm);

    /**
     * @brief Get whether is protect.
     * @return True for protect, false for unprotect.
     */
    bool IsProtectForm() const;

    /**
     * @brief Set whether is protect.
     * @param protectForm True for protect, false for unprotect.
     */
    void SetProtectForm(bool protectForm);
    /**
     * @brief Get updateDuration_.
     * @return updateDuration_.
     */
    std::vector<int32_t> GetConditionUpdate() const;
    /**
     * @brief Set value of updateDuration_.
     * @param updateDuration Update duration.
     */
    void SetConditionUpdate(const std::vector<int32_t> &conditionUpdate);
    /**
     * @brief Set value of ignore visibility flag.
     * @param True of visibility mean form visible, otherwise invisible.
     */
    void SetDataProxyIgnoreFormVisibility(bool visibility);
    /**
     * @brief get value of ignore visibility flag.
     */
    bool GetDataProxyIgnoreFormVisibility() const;
    /**
     * @brief Get whether is distributed.
     * @return True for distributed, false for not distributed.
     */
    bool IsDistributedForm() const;
    /**
     * @brief Set whether is distributed.
     * @param isDistributed True for distributed, false for not distributed.
     */
    void SetDistributedForm(bool isDistributed);
    /**
     * @brief Set ui moduleName.
     * @param uiModule distributed moduleName.
     */
    void SetUiModuleName(const std::string &uiModule);
    /**
     * @brief Get distributed ui moduleName.
     * @return Ui moduleName.
     */
    const std::string& GetUiModuleName() const;
    /**
     * @brief Set templateFormImperativeFwk Mode.
     * @param templateFormImperativeFwk Mode.
     */
    void SetTemplateFormImperativeFwk(const std::string &templateFormImperativeFwk);
    /**
     * @brief Get templateFormImperativeFwk.
     * @return templateFormImperativeFwk Mode.
     */
    const std::string &GetTemplateFormImperativeFwk() const;

    /**
     * @brief Set isTemplateForm.
     * @param isTemplateForm istemplateForm.
     */
    void SetIsTemplateForm(const bool isTemplateForm);

    /**
     * @brief Set isTemplateForm.
     * @return isTemplateForm;
     */
    bool GetIsTemplateForm() const;

private:
    /**
     * @brief Equal or not.
     * @param left left string.
     * @param right right string.
     * @return Equal or not
     */
    bool IsEqual(const std::string &left, const std::string &right);

private:
    int64_t formId_ = -1;
    std::string packageName_ = "";
    std::string providerBundleName_ = "";
    std::string hostBundleName_ = "";
    std::string moduleName_ = ""; // ExtensionAbility module name
    std::string abilityName_ = "";
    std::string formName_ = "";
    int32_t specificationId_ = 0;
    bool updateFlag_ = false;
    int32_t updateDuration_ = 0;
    std::string scheduledUpdateTime_ = "";
    std::string multiScheduledUpdateTime_ = "";
    std::vector<std::string> hapSourceDirs_;
    bool temporaryFlag_ = false;
    bool formVisibleNotify_ = false;
    std::string formSrc_ = "";
    FormWindow formWindow_;
    uint32_t versionCode_ = 0;
    std::string versionName_ = "";
    uint32_t compatibleVersion_ = 0;
    FormType type_ = FormType::JS;
    FormType uiSyntax_ = FormType::JS;
    std::string icon_ = "";
    bool isDynamic_ = true;
    bool transparencyEnabled_ = false;
    int32_t privacyLevel_ = 0;
    std::string jsComponentName_ = "";
    std::string abilityModuleName_ = "";
    std::unordered_map<std::string, std::string> moduleInfoMap_;
    std::map<std::string, std::string> modulePkgNameMap_;
    std::string deviceId_ = "";
    bool dataProxyEnabled_ = false;
    bool isSystemApp_ = false;
    int32_t uid_ = -1;
    std::string description_ = "";
    Constants::FormLocation formLocation_;
    bool isThemeForm_ = false;
    BundleType bundleType_ = BundleType::APP;
    bool enableForm_ = true;
    Constants::RenderingMode renderingMode_ = Constants::RenderingMode::FULL_COLOR;
    bool lockForm_ = false;
    bool protectForm_ = false;
    std::vector<int32_t> conditionUpdate_;
    bool isDataProxyIgnoreFormVisibility_ = false;
    bool isDistributedForm_ = false;
    std::string uiModule_ = ""; // widget module name
    std::string templateFormImperativeFwk_ = Constants::TEMPLATE_FORM_IMPERATIVE_FWK_NONE;
    bool isTemplateForm_ = false;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_ITEM_INFO_H
