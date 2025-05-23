/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_FORM_BASIC_INFO_MGR_H
#define OHOS_FORM_FWK_FORM_BASIC_INFO_MGR_H

#include <unordered_map>
#include <mutex>
#include <singleton.h>
#include <string>

namespace OHOS {
namespace AppExecFwk {
struct FormBasicInfo {
    int64_t formId{0};
    std::string abilityName{""};
    std::string bundleName{""};
    std::string moduleName{""};
    std::string formName{""};
    std::string packageName{""};
};

/**
 * @class FormBaseInfoMgr
 * form basic info mananger.
 */
class FormBasicInfoMgr final : public DelayedRefSingleton<FormBasicInfoMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormBasicInfoMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormBasicInfoMgr);

public:
    void AddFormBasicInfo(const FormBasicInfo& baseInfo);
    void DeleteFormBasicInfo(int64_t formId);
    void ClearFormBasicInfo();

    int GetBasicInfoCount() const;
    bool GetBasicInfoByFormId(int64_t formId, FormBasicInfo& basicInfo);

    const std::string& GetFormAbilityName(int64_t formId);
    const std::string& GetFormBundleName(int64_t formId);
    const std::string& GetFormModuleName(int64_t formId);
    const std::string& GetFormName(int64_t formId);
    const std::string& GetFormPackageName(int64_t formId);

    void UpdateAbilityName(int64_t formId, const std::string& abilityName);
    void UpdateBundleName(int64_t formId, const std::string& bundleName);
    void UpdateModuleName(int64_t formId, const std::string& moduleName);
    void UpdateFormName(int64_t formId, const std::string& formName);
    void UpdatePackageName(int64_t formId, const std::string& packageName);

private:
    mutable std::mutex formBasicInfoMutex_;
    std::unordered_map<int64_t, FormBasicInfo> formBasicInfoMap_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_BASIC_INFO_MGR_H