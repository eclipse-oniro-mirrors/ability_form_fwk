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

#include "form_host/form_host_record.h"

#include <cinttypes>
#include "form_host/form_host_task_mgr.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Add form id.
 * @param formId The Id of the form.
 */
void FormHostRecord::AddForm(int64_t formId)
{
    if (forms_.find(formId) != forms_.end()) {
        return;
    }
    forms_[formId] = true;
}
/**
 * @brief Delete form id.
 * @param formId The Id of the form.
 */
void FormHostRecord::DelForm(int64_t formId)
{
    forms_.erase(formId);
}
/**
 * @brief forms_ is empty or not.
 * @return forms_ is empty or not.
 */
bool FormHostRecord::IsEmpty() const
{
    return forms_.empty();
}
/**
 * @brief formId is in forms_ or not.
 * @param formId The Id of the form.
 * @return formId is in forms_ or not.
 */
bool FormHostRecord::Contains(int64_t formId) const
{
    return forms_.find(formId) != forms_.end();
}

/**
 * @brief Set refresh enable flag.
 * @param formId The Id of the form.
 * @param flag True for enable, false for disable.
 */
void FormHostRecord::SetEnableRefresh(int64_t formId, bool flag)
{
    if (forms_.find(formId) == forms_.end()) {
        return;
    }
    forms_[formId] = flag;
}
/**
 * @brief Refresh enable or not.
 * @param formId The Id of the form.
 * @return true on enable, false on disable.
 */
bool FormHostRecord::IsEnableRefresh(int64_t formId) const
{
    auto result = forms_.find(formId);
    if (result != forms_.end()) {
        return result->second;
    }
    return false;
}
/**
 * @brief Set Update enable flag.
 * @param formId The Id of the form.
 * @param enable True for enable, false for disable.
 */
void FormHostRecord::SetEnableUpdate(int64_t formId, bool enable)
{
    auto result = forms_.find(formId);
    if (result == forms_.end()) {
        HILOG_ERROR("formId:%{public}" PRId64 "not found", formId);
        return;
    }
    enableUpdateMap_[formId] = enable;
}
/**
 * @brief update enable or not.
 * @param formId The Id of the form.
 * @return true on enable, false on disable.
 */
bool FormHostRecord::IsEnableUpdate(int64_t formId) const
{
    auto result = enableUpdateMap_.find(formId);
    if (result == enableUpdateMap_.end()) {
        return false;
    }
    return result->second;
}
/**
 * @brief Set need refresh enable flag.
 * @param formId The Id of the form.
 * @param flag True for enable, false for disable.
 */
void FormHostRecord::SetNeedRefresh(int64_t formId, bool flag)
{
    needRefresh_[formId] = flag;
}
/**
 * @brief Need Refresh enable or not.
 * @param formId The Id of the form.
 * @return true on enable, false on disable.
 */
bool FormHostRecord::IsNeedRefresh(int64_t formId) const
{
    auto result = needRefresh_.find(formId);
    if (result != needRefresh_.end()) {
        return result->second;
    }
    return false;
}
/**
 * @brief Get formHostClient_.
 * @return formHostClient_.
 */
sptr<IRemoteObject> FormHostRecord::GetFormHostClient() const
{
    return formHostClient_;
}

/**
 * @brief Send form data to form host.
 * @param id The Id of the form.
 * @param record Form record.
 */
void FormHostRecord::OnAcquire(int64_t id, const FormRecord &record)
{
    HILOG_DEBUG("FormHostRecord OnAcquire");
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnAcquired(id, record, formHostClient_);
}

/**
 * @brief Update form data to form host.
 * @param id The Id of the form.
 * @param record Form record.
 */
void FormHostRecord::OnUpdate(int64_t id, const FormRecord &record)
{
    HILOG_INFO("start");
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnUpdate(id, record, formHostClient_);
}

/**
 * @brief Send form uninstall message to form host.
 * @param formIds The id list of the form.
 */
void FormHostRecord::OnFormUninstalled(std::vector<int64_t> &formIds)
{
    HILOG_INFO("start");
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnUninstall(formIds, formHostClient_);
}

/**
 * Send form state message to form host.
 *
 * @param state The form state.
 * @param want The want of onAcquireFormState.
 */
void FormHostRecord::OnAcquireState(AppExecFwk::FormState state, const AAFwk::Want &want)
{
    HILOG_INFO("start");
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnAcquireState(state, want, formHostClient_);
}

void FormHostRecord::OnAcquireFormData(const AAFwk::WantParams &wantParams, int64_t requestCode)
{
    HILOG_INFO("start");
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnAcquireFormData(wantParams, requestCode, formHostClient_);
}

/**
 * @brief Release resource.
 * @param id The Id of the form.
 * @param record Form record.
 */
void FormHostRecord::CleanResource()
{
    if (formHostClient_ != nullptr && deathRecipient_ != nullptr) {
        formHostClient_->RemoveDeathRecipient(deathRecipient_);
        formHostClient_ = nullptr;
        deathRecipient_ = nullptr;
    }
}
/**
 * @brief Set value of callerUid_.
 * @param callerUid Caller uid.
 */
void FormHostRecord::SetCallerUid(const int callerUid)
{
    callerUid_ = callerUid;
}
/**
 * @brief Set value of formHostClient_.
 * @param formHostClient remote object.
 */
void FormHostRecord::SetFormHostClient(const sptr<IRemoteObject> &formHostClient)
{
    formHostClient_ = formHostClient;
}
/**
 * @brief Set value of formHostCallback_.
 * @param formHostCallback Form host callback object.
 */
void FormHostRecord::SetCallback(const std::shared_ptr<FormHostCallback> &formHostCallback)
{
    formHostCallback_ = formHostCallback;
}
/**
 * @brief Get deathRecipient_.
 * @return deathRecipient_.
 */
sptr<IRemoteObject::DeathRecipient> FormHostRecord::GetDeathRecipient() const
{
    return deathRecipient_;
}
/**
 * @brief Set value of deathRecipient_.
 * @param formHostCallback DeathRecipient object.
 */
void FormHostRecord::SetDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &deathRecipient)
{
    deathRecipient_ = deathRecipient;
}
/**
 * @brief Add deathRecipient object to formHostClient_.
 * @param deathRecipient DeathRecipient object.
 */
void FormHostRecord::AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &deathRecipient)
{
    if (formHostClient_ == nullptr) {
        return;
    }
    formHostClient_->AddDeathRecipient(deathRecipient);
}

/**
 * @brief Create form host record.
 * @param info The form item info.
 * @param callback remote object.
 * @param callingUid Calling uid.
 */
FormHostRecord FormHostRecord::CreateRecord(const FormItemInfo &info,
    const sptr<IRemoteObject> &callback, int callingUid)
{
    FormHostRecord record;
    std::string bundleName = info.GetHostBundleName();
    record.SetHostBundleName(bundleName);
    record.SetCallerUid(callingUid);
    record.SetFormHostClient(callback);
    record.SetCallback(std::make_shared<FormHostCallback>());
    record.SetDeathRecipient(new (std::nothrow) FormHostRecord::ClientDeathRecipient(bundleName));
    record.AddDeathRecipient(record.GetDeathRecipient());
    return record;
}

/**
 * @brief handle remote object died event.
 * @param remote remote object.
 */
void FormHostRecord::ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_INFO("Form remote died hostBundleName: %{public}s", hostBundleName_.c_str());
    FormHostTaskMgr::GetInstance().PostHostDiedTask(remote.promote());
}

/**
 * @brief Get hostBundleName_.
 * @return hostBundleName_.
 */
std::string FormHostRecord::GetHostBundleName() const
{
    return hostBundleName_;
}
/**
 * @brief Set hostBundleName_.
 * @param hostBundleName Host bundle name.
 */
void FormHostRecord::SetHostBundleName(const std::string &hostBundleName)
{
    hostBundleName_ = hostBundleName;
}

int32_t FormHostRecord::GetFormsCount() const
{
    return static_cast<int32_t>(forms_.size());
}

void FormHostRecord::OnRecycleForms(const std::vector<int64_t> &formIds, const Want &want) const
{
    HILOG_DEBUG("start");
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnRecycleForms(formIds, want, formHostClient_);
}

void FormHostRecord::OnEnableForms(const std::vector<int64_t> &formIds, const bool enable)
{
    HILOG_DEBUG("start");
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnEnableForms(formIds, enable, formHostClient_);
}

void FormHostRecord::OnLockForms(const std::vector<int64_t> &formIds, const bool lock)
{
    HILOG_DEBUG("start");
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnLockForms(formIds, lock, formHostClient_);
}

void FormHostRecord::OnCheckForms(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("start");
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnCheckForms(formIds, formHostClient_);
}

void FormHostRecord::GetForms(std::vector<int64_t> &formIds)
{
    for (const auto &iter : forms_) {
        formIds.emplace_back(iter.first);
    }
}

void FormHostRecord::OnDueControlForms(
    const std::vector<int64_t> &formIds, const bool isDisablePolicy, const bool isControl)
{
    HILOG_DEBUG("start");
    if (formIds.empty()) {
        HILOG_ERROR("empty formIds");
        return;
    }
    if (formHostCallback_ == nullptr) {
        HILOG_ERROR("null formHostCallback_");
        return;
    }
    formHostCallback_->OnDueControlForms(formIds, isDisablePolicy, isControl, formHostClient_);
}
}  // namespace AppExecFwk
}  // namespace OHOS
