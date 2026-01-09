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
#include "data_center/form_basic_info_mgr.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string INVALID_VALUE = "";
}

FormBasicInfoMgr::FormBasicInfoMgr()
{
    HILOG_INFO("Create");
}

FormBasicInfoMgr::~FormBasicInfoMgr()
{
    HILOG_INFO("Destroy");
}

void FormBasicInfoMgr::AddFormBasicInfo(const FormBasicInfo &baseInfo)
{
    HILOG_INFO("FormBasicInfoMgr::AddFormBasicInfo");
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    auto iter = formBasicInfoMap_.find(baseInfo.formId);
    if (iter != formBasicInfoMap_.end()) {
        iter->second = baseInfo;
        return;
    }
    formBasicInfoMap_.emplace(baseInfo.formId, baseInfo);
}

void FormBasicInfoMgr::DeleteFormBasicInfo(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        formBasicInfoMap_.erase(iter);
    }
}

void FormBasicInfoMgr::ClearFormBasicInfo()
{
    formBasicInfoMap_.clear();
}

int FormBasicInfoMgr::GetBasicInfoCount() const
{
    return formBasicInfoMap_.size();
}

bool FormBasicInfoMgr::GetBasicInfoByFormId(int64_t formId, FormBasicInfo &basicInfo)
{
    HILOG_DEBUG("get form basic info by formId");
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        HILOG_DEBUG("get form basic info successfully");
        basicInfo = iter->second;
        return true;
    }
    HILOG_ERROR("form basic info not find");
    return false;
}

const std::string& FormBasicInfoMgr::GetFormAbilityName(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        return iter->second.abilityName;
    }
    return INVALID_VALUE;
}

const std::string& FormBasicInfoMgr::GetFormBundleName(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        return iter->second.bundleName;
    }
    return INVALID_VALUE;
}

const std::string& FormBasicInfoMgr::GetFormModuleName(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        return iter->second.moduleName;
    }
    return INVALID_VALUE;
}

const std::string& FormBasicInfoMgr::GetFormName(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        return iter->second.formName;
    }
    return INVALID_VALUE;
}

const std::string& FormBasicInfoMgr::GetFormPackageName(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        return iter->second.packageName;
    }
    return INVALID_VALUE;
}

void FormBasicInfoMgr::UpdateAbilityName(int64_t formId, const std::string &abilityName)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        iter->second.abilityName = abilityName;
    }
}

void FormBasicInfoMgr::UpdateBundleName(int64_t formId, const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        iter->second.bundleName = bundleName;
    }
}

void FormBasicInfoMgr::UpdateModuleName(int64_t formId, const std::string &moduleName)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        iter->second.moduleName = moduleName;
    }
}

void FormBasicInfoMgr::UpdateFormName(int64_t formId, const std::string &formName)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        iter->second.formName = formName;
    }
}

void FormBasicInfoMgr::UpdatePackageName(int64_t formId, const std::string &packageName)
{
    std::lock_guard<std::mutex> lock(formBasicInfoMutex_);
    const auto iter = formBasicInfoMap_.find(formId);
    if (iter != formBasicInfoMap_.end()) {
        iter->second.packageName = packageName;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
