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

#ifndef OHOS_FORM_FWK_FORM_HOST_RECORD_H
#define OHOS_FORM_FWK_FORM_HOST_RECORD_H

#include <unordered_map>
#include <vector>
#include "fms_log_wrapper.h"
#include "form_host/form_host_callback.h"
#include "data_center/form_info/form_item_info.h"
#include "data_center/form_record/form_record.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormHostRecord
 * Form host data.
 */
class FormHostRecord {
public:
    /**
     * @brief Create form host record.
     * @param callback remote object.
     * @param callingUid Calling uid.
     */
    static FormHostRecord CreateRecord(const FormItemInfo &info, const sptr<IRemoteObject> &callback, int callingUid);
    /**
     * @brief Add form id.
     * @param formId The Id of the form.
     */
    void AddForm(int64_t formId);
    /**
     * @brief Delete form id.
     * @param formId The Id of the form.
     */
    void DelForm(int64_t formId);
    /**
     * @brief forms_ is empty or not.
     * @return forms_ is empty or not.
     */
    bool IsEmpty() const;
    /**
     * @brief formId is in forms_ or not.
     * @param formId The Id of the form.
     * @return formId is in forms_ or not.
     */
    bool Contains(int64_t formId) const;

    /**
     * @brief Set refresh enable flag.
     * @param formId The Id of the form.
     * @param flag True for enable, false for disable.
     */
    void SetEnableRefresh(int64_t formId, bool flag);

    /**
     * @brief Refresh enable or not.
     * @param formId The Id of the form.
     * @return true on enable, false on disable.
     */
    bool IsEnableRefresh(int64_t formId) const;

    /**
     * @brief Set Update enable flag.
     * @param formId The Id of the form.
     * @param enable True for enable, false for disable.
     */
    void SetEnableUpdate(int64_t formId, bool enable);

    /**
     * @brief update enable or not.
     * @param formId The Id of the form.
     * @return true on enable, false on disable.
     */
    bool IsEnableUpdate(int64_t formId) const;

    /**
     * @brief Set need refresh enable flag.
     * @param formId The Id of the form.
     * @param flag True for enable, false for disable.
     */
    void SetNeedRefresh(int64_t formId, bool flag);
    /**
     * @brief Need Refresh enable or not.
     * @param formId The Id of the form.
     * @return true on enable, false on disable.
     */
    bool IsNeedRefresh(int64_t formId) const;

    /**
     * @brief Send form data to form host.
     * @param id The Id of the form.
     * @param record Form record.
     */
    void OnAcquire(int64_t id, const FormRecord &record);

    /**
     * @brief Update form data to form host.
     * @param id The Id of the form.
     * @param record Form record.
     */
    void OnUpdate(int64_t id, const FormRecord &record);
    /**
     * Send form uninstall message to form host.
     *
     * @param formIds the uninstalled form id list.
     */
    void OnFormUninstalled(std::vector<int64_t> &formIds);
    /**
     * Send form state message to form host.
     *
     * @param state The form state.
     * @param want The want of onAcquireFormState.
     */
    void OnAcquireState(AppExecFwk::FormState state, const AAFwk::Want &want);

    /**
     * Send form data to form host.
     *
     * @param wantParams Indicates the data information acquired by the form.
     * @param requestCode Indicates the requested id.
     */
    void OnAcquireFormData(const AAFwk::WantParams &wantParams, int64_t requestCode);

    /**
     * @brief Release resource.
     */
    void CleanResource();
    /**
     * @brief Get caller Uid.
     * @return the caller Uid.
     */
    int GetCallerUid() const
    {
        return callerUid_;
    }
    /**
     * @brief Get client stub.
     * @return client stub.
     */
    sptr<IRemoteObject> GetFormHostClient() const;
    /**
     * @brief Get death recipient.
     * @return death recipient.
     */
    sptr<IRemoteObject::DeathRecipient> GetDeathRecipient() const;
    /**
     * @brief Set value of caller uid.
     * @param callerUid Caller uid.
     */
    void SetCallerUid(const int callerUid);
    /**
     * @brief Set value of client stub.
     * @param formHostClient remote object.
     */
    void SetFormHostClient(const sptr<IRemoteObject> &formHostClient);
    /**
     * @brief Set value of formHostCallback_.
     * @param formHostCallback Form host callback object.
     */
    void SetCallback(const std::shared_ptr<FormHostCallback> &formHostCallback);
    /**
     * @brief Set value of deathRecipient_.
     * @param formHostCallback DeathRecipient object.
     */
    void SetDeathRecipient(const sptr<IRemoteObject::DeathRecipient> &deathRecipient);
    /**
     * @brief Add deathRecipient object to formHostClient_.
     * @param deathRecipient DeathRecipient object.
     */
    void AddDeathRecipient(const sptr<IRemoteObject::DeathRecipient>& deathRecipient);
    /**
     * @brief Get hostBundleName_.
     * @return hostBundleName_.
     */
    std::string GetHostBundleName() const;
    /**
     * @brief Set hostBundleName_.
     * @param hostBundleName Host bundle name.
     */
    void SetHostBundleName(const std::string &hostBundleName);

    /**
     * @brief get forms count.
     * @return the number of host form.
     */
    int32_t GetFormsCount() const;

    /**
     * @brief Send recycle form message to form host.
     * @param formIds The Id list of forms.
     * @param want The want of forms to be recycled.
     */
    void OnRecycleForms(const std::vector<int64_t> &formIds, const AAFwk::Want &want) const;

    /**
     * @brief Enable form or disable form.
     * @param formIds The Id list of forms.
     * @param enable True is enable form, false is disable form.
     */
    void OnEnableForms(const std::vector<int64_t> &formIds, const bool enable);

    /**
     * @brief Lock form or unlock form.
     * @param formIds The Id list of forms.
     * @param lock True is lock form, false is unlock form.
     */
    void OnLockForms(const std::vector<int64_t> &formIds, const bool lock);

    /**
     * @brief get forms.
     * @param formIds The output parameter store the formId list.
     */
    void GetForms(std::vector<int64_t> &formIds);
private:
    int callerUid_ = 0;
    sptr<IRemoteObject> formHostClient_ = nullptr;
    std::shared_ptr<FormHostCallback> formHostCallback_ = nullptr;
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ = nullptr;
    std::unordered_map<int64_t, bool> forms_;
    std::unordered_map<int64_t, bool> enableUpdateMap_;
    std::unordered_map<int64_t, bool> needRefresh_;
    std::string hostBundleName_ = "";

    /**
     * @class ClientDeathRecipient
     * notices IRemoteBroker died.
     */
    class ClientDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        /**
         * @brief Constructor
         */
        explicit ClientDeathRecipient(std::string &hostBundleName) : hostBundleName_(hostBundleName) {};
        ~ClientDeathRecipient() = default;
        /**
         * @brief handle remote object died event.
         * @param remote remote object.
         */
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    private:
        std::string hostBundleName_ = "";
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_HOST_RECORD_H
