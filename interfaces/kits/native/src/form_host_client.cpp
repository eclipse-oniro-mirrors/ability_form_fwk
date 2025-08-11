/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_host_client.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_caller_mgr.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AppExecFwk {
sptr<FormHostClient> FormHostClient::instance_ = nullptr;
std::mutex FormHostClient::instanceMutex_;

FormHostClient::FormHostClient()
{
}

FormHostClient::~FormHostClient()
{
}

/**
 * @brief Get FormHostClient instance.
 *
 * @return FormHostClient instance.
 */
sptr<FormHostClient> FormHostClient::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock_l(instanceMutex_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) FormHostClient();
            if (instance_ == nullptr) {
                HILOG_ERROR("create FormHostClient failed");
            }
        }
    }
    return instance_;
}

/**
 * @brief Add form callback.
 *
 * @param formCallback the host's form callback.
 * @param formId The Id of the form.
 * @return none.
 */
void FormHostClient::AddForm(std::shared_ptr<FormCallbackInterface> formCallback, const FormJsInfo &formJsInfo)
{
    auto formId = formJsInfo.formId;
    HILOG_INFO("formId:%{public}" PRId64, formId);
    if (formId <= 0 || formCallback == nullptr) {
        HILOG_ERROR("invalid formId or formCallback");
        return;
    }
    std::lock_guard<std::mutex> lock(callbackMutex_);
    auto iter = formCallbackMap_.find(formId);
    if (iter == formCallbackMap_.end()) {
        std::set<std::shared_ptr<FormCallbackInterface>> callbacks;
        callbacks.emplace(formCallback);
        formCallbackMap_.emplace(formId, callbacks);
    } else {
        iter->second.emplace(formCallback);
    }

    if (formJsInfo.uiSyntax == FormType::ETS) {
        etsFormIds_.emplace(formId);
    }
}

/**
 * @brief Remove form callback.
 *
 * @param formCallback the host's form callback.
 * @param formId The Id of the form.
 * @return none.
 */
void FormHostClient::RemoveForm(std::shared_ptr<FormCallbackInterface> formCallback, const int64_t formId)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    if (formId <= 0 || formCallback == nullptr) {
        HILOG_ERROR("invalid formId or formCallback");
        return;
    }
    std::lock_guard<std::mutex> lock(callbackMutex_);
    auto iter = formCallbackMap_.find(formId);
    if (iter == formCallbackMap_.end()) {
        HILOG_ERROR("not find formId:%{public}s", std::to_string(formId).c_str());
        return;
    }
    iter->second.erase(formCallback);
    if (iter->second.empty()) {
        HILOG_INFO("All callbacks have been removed");
        formCallbackMap_.erase(iter);
        etsFormIds_.erase(formId);
    }
}

/**
 * @brief Check whether the form exist in the formhosts.
 *
 * @param formId The Id of the form.
 * @return Returns true if contains form; returns false otherwise.
 */
bool FormHostClient::ContainsForm(int64_t formId)
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(callbackMutex_);
    return formCallbackMap_.find(formId) != formCallbackMap_.end();
}

/**
 * @brief Add form state.
 *
 * @param formStateCallback the host's form state callback.
 * @param want the want of acquiring form state.
 * @return Returns true if contains form; returns false otherwise.
 */
bool FormHostClient::AddFormState(const std::shared_ptr<FormStateCallbackInterface> &formStateCallback,
                                  const AAFwk::Want &want)
{
    HILOG_INFO("call");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    const std::string doubleColon = "::";
    std::string key;
    key.append(bundleName).append(doubleColon).append(abilityName).append(doubleColon)
        .append(want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY)).append(doubleColon)
        .append(want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_NAME_KEY)).append(doubleColon)
        .append(std::to_string(want.GetIntParam(AppExecFwk::Constants::PARAM_FORM_DIMENSION_KEY, 1)));
    std::lock_guard<std::mutex> lock(formStateCallbackMutex_);
    auto iter = formStateCallbackMap_.find(key);
    if (iter == formStateCallbackMap_.end()) {
        std::set<std::shared_ptr<FormStateCallbackInterface>> callbacks;
        callbacks.emplace(formStateCallback);
        formStateCallbackMap_.emplace(key, callbacks);
    } else {
        iter->second.insert(formStateCallback);
    }
    HILOG_INFO("done");
    return true;
}

void FormHostClient::RemoveFormState(const AAFwk::Want &want)
{
    HILOG_INFO("call");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    const std::string doubleColon = "::";
    std::string key;
    key.append(bundleName).append(doubleColon).append(abilityName).append(doubleColon)
        .append(want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY)).append(doubleColon)
        .append(want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_NAME_KEY)).append(doubleColon)
        .append(std::to_string(want.GetIntParam(AppExecFwk::Constants::PARAM_FORM_DIMENSION_KEY, 1)));
    std::lock_guard<std::mutex> lock(formStateCallbackMutex_);
    auto iter = formStateCallbackMap_.find(key);
    if (iter != formStateCallbackMap_.end()) {
        formStateCallbackMap_.erase(key);
    }
    HILOG_INFO("end");
}

bool FormHostClient::RegisterUninstallCallback(UninstallCallback callback)
{
    std::lock_guard<std::mutex> lock(uninstallCallbackMutex_);
    uninstallCallback_ = callback;
    return true;
}

void FormHostClient::OnAcquired(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &token)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    if (token != nullptr) {
        HILOG_DEBUG("save token to form remote mgr");
        FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, token);
    }
    UpdateForm(formJsInfo);
}

/**
 * @brief Update form.
 *
 * @param formJsInfo Form js info.
 * @return none.
 */
void FormHostClient::OnUpdate(const FormJsInfo &formJsInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    UpdateForm(formJsInfo);
}

/**
 * @brief UnInstall the forms.
 *
 * @param formIds The Id of the forms.
 * @return none.
 */
void FormHostClient::OnUninstall(const std::vector<int64_t> &formIds)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("call");
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(uninstallCallbackMutex_);
        if (uninstallCallback_ != nullptr) {
            uninstallCallback_(formIds);
        }
    }
    for (auto &formId : formIds) {
        if (formId < 0) {
            HILOG_ERROR("the passed form id can't be negative");
            continue;
        }
        std::lock_guard<std::mutex> lock(callbackMutex_);
        auto iter = formCallbackMap_.find(formId);
        if (iter == formCallbackMap_.end()) {
            HILOG_ERROR("not find formId:%{public}s", std::to_string(formId).c_str());
            continue;
        }
        for (const auto& callback : iter->second) {
            HILOG_ERROR("uninstall formId:%{public}s", std::to_string(formId).c_str());
            callback->ProcessFormUninstall(formId);
        }
    }
}

/**
 * @brief Form provider is acquire state
 * @param state The form state.
 * @param want The form want.
 */
void FormHostClient::OnAcquireState(FormState state, const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("state:%{public}d", state);
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    const std::string doubleColon = "::";
    std::string key;
    key.append(bundleName).append(doubleColon).append(abilityName).append(doubleColon)
        .append(want.GetStringParam(AppExecFwk::Constants::PARAM_MODULE_NAME_KEY)).append(doubleColon)
        .append(want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_NAME_KEY)).append(doubleColon)
        .append(std::to_string(want.GetIntParam(AppExecFwk::Constants::PARAM_FORM_DIMENSION_KEY, 1)));

    std::lock_guard<std::mutex> lock(formStateCallbackMutex_);
    auto iter = formStateCallbackMap_.find(key);
    if (iter == formStateCallbackMap_.end()) {
        HILOG_ERROR("state callback not found");
    } else {
        std::set<std::shared_ptr<FormStateCallbackInterface>> &callbackSet = iter->second;
        for (auto &callback: callbackSet) {
            callback->ProcessAcquireState(state);
        }
        formStateCallbackMap_.erase(iter);
    }
    HILOG_INFO("done");
}

bool FormHostClient::AddShareFormCallback(const std::shared_ptr<ShareFormCallBack> &shareFormCallback,
    int64_t requestCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(shareFormCallbackMutex_);
    auto iter = shareFormCallbackMap_.find(requestCode);
    if (iter == shareFormCallbackMap_.end()) {
        shareFormCallbackMap_.emplace(requestCode, shareFormCallback);
    }
    HILOG_DEBUG("done");
    return true;
}

bool FormHostClient::AddAcqiureFormDataCallback(const std::shared_ptr<FormDataCallbackInterface> &acquireFormDataTask,
    int64_t requestCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(AcquireDataCallbackMutex_);
    auto iter = acquireDataCallbackMap_.find(requestCode);
    if (iter == acquireDataCallbackMap_.end()) {
        acquireDataCallbackMap_.emplace(requestCode, acquireFormDataTask);
    }
    HILOG_DEBUG("done");
    return true;
}

void FormHostClient::OnAcquireDataResponse(const AAFwk::WantParams &wantParams, int64_t requestCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<std::mutex> lock(AcquireDataCallbackMutex_);
    auto iter = acquireDataCallbackMap_.find(requestCode);
    if (iter == acquireDataCallbackMap_.end()) {
        HILOG_DEBUG("acquire form data callback not found");
        return;
    }

    if (iter->second) {
        iter->second->ProcessAcquireFormData(wantParams);
    }
    acquireDataCallbackMap_.erase(requestCode);
    HILOG_DEBUG("done");
}

void FormHostClient::OnShareFormResponse(int64_t requestCode, int32_t result)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("result:%{public}d", result);
    std::lock_guard<std::mutex> lock(shareFormCallbackMutex_);
    auto iter = shareFormCallbackMap_.find(requestCode);
    if (iter == shareFormCallbackMap_.end()) {
        HILOG_DEBUG("invalid shareFormCallback");
        return;
    }

    if (iter->second) {
        iter->second->ProcessShareFormResponse(result);
    }
    shareFormCallbackMap_.erase(requestCode);
    HILOG_DEBUG("done");
}

void FormHostClient::OnError(int32_t errorCode, const std::string &errorMsg)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_ERROR("Receive error form FMS, errorCode:%{public}d, errorMsg:%{public}s, etsFormIds_ size:%{public}zu",
        errorCode,
        errorMsg.c_str(),
        etsFormIds_.size());
    std::lock_guard<std::mutex> lock(callbackMutex_);
    for (auto formIdIter = etsFormIds_.begin(); formIdIter != etsFormIds_.end();) {
        int64_t formId = *formIdIter;
        auto callbackMapIter = formCallbackMap_.find(formId);
        if (callbackMapIter == formCallbackMap_.end()) {
            HILOG_ERROR("Can't find form:%{public}" PRId64 " remove it", formId);
            formIdIter = etsFormIds_.erase(formIdIter);
            continue;
        }
        ++formIdIter;

        const std::set<std::shared_ptr<FormCallbackInterface>> &callbackSet = callbackMapIter->second;
        HILOG_INFO("callbackSet.size:%{public}zu", callbackSet.size());
        for (const auto &callback : callbackSet) {
            if (callback == nullptr) {
                HILOG_ERROR("null FormCallback");
                continue;
            }
            callback->OnError(errorCode, errorMsg);
        }
    }
}

void FormHostClient::OnError(int32_t errorCode, const std::string &errorMsg, std::vector<int64_t> &formIds)
{
    HILOG_INFO("call");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    std::lock_guard<std::mutex> lock(callbackMutex_);
    for (auto formId : formIds) {
        if (etsFormIds_.find(formId) == etsFormIds_.end()) {
            continue;
        }
        auto callbackMapIter = formCallbackMap_.find(formId);
        if (callbackMapIter == formCallbackMap_.end()) {
            HILOG_ERROR("Can't find form:%{public}" PRId64 " remove it", formId);
            etsFormIds_.erase(formId);
            continue;
        }
        HILOG_ERROR("Receive error form FMS formId:%{public}s", std::to_string(formId).c_str());
        const std::set<std::shared_ptr<FormCallbackInterface>> &callbackSet = callbackMapIter->second;
        HILOG_DEBUG("callbackSet.size:%{public}zu", callbackSet.size());
        for (const auto &callback : callbackSet) {
            if (callback == nullptr) {
                HILOG_ERROR("null FormCallback");
                continue;
            }
            callback->OnError(errorCode, errorMsg);
        }
    }
}

void FormHostClient::RemoveShareFormCallback(int64_t requestCode)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(shareFormCallbackMutex_);
    auto iter = shareFormCallbackMap_.find(requestCode);
    if (iter != shareFormCallbackMap_.end()) {
        shareFormCallbackMap_.erase(requestCode);
    }
    HILOG_INFO("end");
}

void FormHostClient::RemoveAcquireDataCallback(int64_t requestCode)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(AcquireDataCallbackMutex_);
    auto iter = acquireDataCallbackMap_.find(requestCode);
    if (iter != acquireDataCallbackMap_.end()) {
        acquireDataCallbackMap_.erase(requestCode);
    }
    HILOG_INFO("end");
}

void FormHostClient::UpdateForm(const FormJsInfo &formJsInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("call,image number is %{public}zu", formJsInfo.imageDataMap.size());
    int64_t formId = formJsInfo.formId;
    if (formId < 0) {
        HILOG_ERROR("the passed form id can't be negative");
        return;
    }
    std::lock_guard<std::mutex> lock(callbackMutex_);
    auto iter = formCallbackMap_.find(formId);
    if (iter == formCallbackMap_.end()) {
        HILOG_ERROR("not find formId:%{public}s", std::to_string(formId).c_str());
        return;
    }
    for (const auto &callback : iter->second) {
        HILOG_DEBUG("formId:%{public}" PRId64 ", jspath:%{public}s, data: %{private}s",
            formId, formJsInfo.jsFormCodePath.c_str(), formJsInfo.formData.c_str());
        callback->ProcessFormUpdate(formJsInfo);
    }
}

void FormHostClient::OnRecycleForm(const int64_t &formId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_DEBUG("formId:%{public}s", std::to_string(formId).c_str());

    if (formId < 0) {
        HILOG_ERROR("the passed form id can't be negative");
        return;
    }
    std::lock_guard<std::mutex> lock(callbackMutex_);
    auto iter = formCallbackMap_.find(formId);
    if (iter == formCallbackMap_.end()) {
        HILOG_ERROR("can't find formId:%{public}s", std::to_string(formId).c_str());
        return;
    }
    for (const auto &callback : iter->second) {
        callback->ProcessRecycleForm();
    }
}

void FormHostClient::OnEnableForm(const std::vector<int64_t> &formIds, const bool enable)
{
    HILOG_INFO("size:%{public}zu", formIds.size());
    for (auto &formId : formIds) {
        if (formId < 0) {
            HILOG_ERROR("the passed form id can't be negative");
            continue;
        }
        std::lock_guard<std::mutex> lock(callbackMutex_);
        auto iter = formCallbackMap_.find(formId);
        if (iter == formCallbackMap_.end()) {
            HILOG_ERROR("not find formId:%{public}s", std::to_string(formId).c_str());
            continue;
        }
        for (const auto& callback : iter->second) {
            if (!callback) {
                HILOG_ERROR("null callback");
                continue;
            }
            callback->ProcessEnableForm(enable);
        }
    }
}

void FormHostClient::OnLockForm(const std::vector<int64_t> &formIds, const bool lock)
{
    HILOG_INFO("OnLockForm size:%{public}zu", formIds.size());
    for (auto &formId : formIds) {
        if (formId < 0) {
            HILOG_ERROR("the passed form id can't be negative");
            continue;
        }
        std::lock_guard<std::mutex> lockMutex(callbackMutex_);
        auto iter = formCallbackMap_.find(formId);
        if (iter == formCallbackMap_.end()) {
            HILOG_ERROR("not find formId:%{public}s", std::to_string(formId).c_str());
            continue;
        }
        for (const auto& callback : iter->second) {
            if (!callback) {
                HILOG_ERROR("null callback");
                continue;
            }
            callback->ProcessLockForm(lock);
        }
    }
}
} // namespace AppExecFwk
} // namespace OHOS
