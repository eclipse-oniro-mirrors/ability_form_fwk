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

#ifndef OHOS_FORM_FWK_FORM_HOST_CLIENT_H
#define OHOS_FORM_FWK_FORM_HOST_CLIENT_H

#include <map>
#include <memory>
#include <mutex>
#include <vector>
#include <set>
#include <unordered_set>
#include "form_callback_interface.h"
#include "form_host_stub.h"
#include "form_state_info.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormHostClient
 * The service of the form host.
 */
class FormHostClient : public FormHostStub {
public:
    FormHostClient();
    virtual ~FormHostClient();

    /**
     * @brief Get FormHostClient instance.
     *
     * @return FormHostClient instance.
     */
    static sptr<FormHostClient> GetInstance();

    /**
     * @brief Add form.
     *
     * @param formCallback the host's form callback.
     * @param formJsInfo The info of the form.
     * @return none.
     */
    void AddForm(std::shared_ptr<FormCallbackInterface> formCallback, const FormJsInfo &formJsInfo);

    /**
     * @brief Remove form.
     *
     * @param formCallback the host's form callback.
     * @param formId The Id of the form.
     * @return none.
     */
    void RemoveForm(std::shared_ptr<FormCallbackInterface> formCallback, const int64_t formId);

    /**
     * @brief Check whether the form exist in the formhosts.
     *
     * @param formId The Id of the form.
     * @return Returns true if contains form; returns false otherwise.
     */
    bool ContainsForm(int64_t formId);

    /**
     * @brief Add form state.
     *
     * @param formStateCallback the host's form state callback.
     * @param want the want of acquiring form state.
     * @return Returns true if contains form; returns false otherwise.
     */
    bool AddFormState(const std::shared_ptr<FormStateCallbackInterface> &formStateCallback, const AAFwk::Want &want);

    /**
     * @brief Remove form state.
     *
     * @param want the want of acquiring form state.
     */
    void RemoveFormState(const AAFwk::Want &want);

    using UninstallCallback = void (*)(const std::vector<int64_t> &formIds);
    /**
     * @brief register form uninstall function.
     *
     * @param callback the form uninstall callback.
     * @return Returns true if contains form; returns false otherwise.
     */
    bool RegisterUninstallCallback(UninstallCallback callback);

    /**
     * @brief Request to give back a form.
     *
     * @param formJsInfo Form js info.
     * @param token Provider client token.
     * @return none.
     */
    void OnAcquired(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &token) override;

     /**
     * @brief Update form.
     *
     * @param formJsInfo Form js info.
     * @return none.
     */
    void OnUpdate(const FormJsInfo &formJsInfo) override;

    /**
     * @brief UnInstall the forms.
     *
     * @param formIds The Id of the forms.
     * @return none.
     */
    void OnUninstall(const std::vector<int64_t> &formIds) override;

    /**
     * @brief Acquire the form state
     * @param state The form state.
     */
    void OnAcquireState(FormState state, const AAFwk::Want &want) override;

    /**
     * @brief Add shareForm callback.
     *
     * @param shareFormCallback The host's share form callback.
     * @param requestCode The request code of this share form.
     * @return Returns true if contains form; returns false otherwise.
     */
    bool AddShareFormCallback(const std::shared_ptr<ShareFormCallBack> &shareFormCallback, int64_t requestCode);

    /**
     * @brief Add Acquire form data callback.
     *
     * @param acquireFormDataTask The host's acquire form callback.
     * @param requestCode The request code of this acquire form.
     * @return Returns true if contains form; returns false otherwise.
     */
    bool AddAcqiureFormDataCallback(const std::shared_ptr<FormDataCallbackInterface> &acquireFormDataTask,
        int64_t requestCode);

    /**
     * @brief Responsive form sharing.
     * @param requestCode The request code of this share form.
     * @param result Share form result.
     */
    void OnShareFormResponse(int64_t requestCode, int32_t result) override;

    /**
     * @brief Responsive form acquiring form data.
     * @param requestCode The request code of this acquire form.
     */
    void OnAcquireDataResponse(const AAFwk::WantParams &wantParams, int64_t requestCode) override;

    /**
     * @brief Return error to host.
     *
     * @param errorCode Indicates error-code of the form.
     * @param errorMsg Indicates error-message of the form.
     */
    void OnError(int32_t errorCode, const std::string &errorMsg) override;

    /**
     * @brief Return error to host for forms.
     *
     * @param errorCode Indicates error-code of the form.
     * @param errorMsg Indicates error-message of the form.
     * @param formIds Indicates ids of the form.
     */
    void OnError(int32_t errorCode, const std::string &errorMsg, std::vector<int64_t> &formIds) override;
    
    /**
     * @brief Remove shareForm callback.
     * @param requestCode The request code of this share form.
     */
    void RemoveShareFormCallback(int64_t requestCode);

    /**
     * @brief Remove AcquireData callback.
     * @param requestCode The request code of this acquire form data.
     */
    void RemoveAcquireDataCallback(int64_t requestCode);

    /**
     * @brief Update form.
     * @param formJsInfo Form js info.
     */
    void UpdateForm(const FormJsInfo &formJsInfo);

    /**
     * @brief Recycle dynamic ArkTS form.
     * @param formId The id of form to be recycled.
     */
    void OnRecycleForm(const int64_t &formId) override;

    /**
     * @brief enable form style
     * @param formIds The Id list of the forms.
     * @param enable True is enableform, false is disableform.
     */
    void OnEnableForm(const std::vector<int64_t> &formIds, const bool enable) override;

    /**
     * @brief lock form style
     * @param formIds The Id list of the forms.
     * @param lock True is lockform, false is unlockform.
     */
    void OnLockForm(const std::vector<int64_t> &formIds, const bool lock) override;

    /**
     * @brief due disable form style
     * @param formIds The Id list of the forms.
     * @param lock True is due disable form, false is enable form.
     */
    void OnDueDisableForm(const std::vector<int64_t> &formIds, const bool isDisable) override;

    /**
     * @brief due remove form style
     * @param formIds The Id list of the forms.
     * @param lock True is due remove form, false is enable form.
     */
    void OnDueRemoveForm(const std::vector<int64_t> &formIds, const bool isRemove) override;
private:
    static std::mutex instanceMutex_;
    static sptr<FormHostClient> instance_;
    mutable std::mutex callbackMutex_;
    mutable std::mutex formStateCallbackMutex_;
    mutable std::mutex uninstallCallbackMutex_;
    mutable std::mutex shareFormCallbackMutex_;
    mutable std::mutex AcquireDataCallbackMutex_;
    std::map<int64_t, std::set<std::shared_ptr<FormCallbackInterface>>> formCallbackMap_;
    std::map<int64_t, std::shared_ptr<ShareFormCallBack>> shareFormCallbackMap_;
    std::map<int64_t, std::shared_ptr<FormDataCallbackInterface>> acquireDataCallbackMap_;
    std::map<std::string, std::set<std::shared_ptr<FormStateCallbackInterface>>> formStateCallbackMap_;
    UninstallCallback uninstallCallback_ = nullptr;
    std::unordered_set<int64_t> etsFormIds_;

    DISALLOW_COPY_AND_MOVE(FormHostClient);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_HOST_CLIENT_H
