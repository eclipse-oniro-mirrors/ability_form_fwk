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

#ifndef OHOS_FORM_FWK_FORM_HOST_CALLBACK_H
#define OHOS_FORM_FWK_FORM_HOST_CALLBACK_H

#include <vector>

#include "form_js_info.h"
#include "data_center/form_record/form_record.h"
#include "form_state_info.h"
#include "ipc_types.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormHostCallback
 * FormHost callback is used to call form host service.
 */
class FormHostCallback {
public:
    FormHostCallback() = default;
    virtual ~FormHostCallback() = default;
    /**
     * @brief Request to give back a Form.
     * @param formId The Id of the forms to create.
     * @param record Form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    void OnAcquired(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &callerToken);

     /**
     * @brief Form is updated.
     * @param formId The Id of the form to update.
     * @param record Form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    void OnUpdate(const int64_t formId, const FormRecord &record, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Form provider is uninstalled.
     * @param formIds The Id list of the forms.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    void OnUninstall(std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Form provider is uninstalled.
     * @param state The form state.
     * @param want The want of onAcquireFormState.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    void OnAcquireState(AppExecFwk::FormState state, const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Send form data to form host.
     * @param wantParams Indicates the data information acquired by the form.
     * @param requestCode Indicates the requested id.
     */
    void OnAcquireFormData(const AAFwk::WantParams &wantParams, int64_t requestCode,
                            const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Send recycle form message to form host.
     * @param formIds The Id list of forms.
     * @param want The want of forms to be recycled.
     * @param callerToken Caller ability token.
     */
    void OnRecycleForms(const std::vector<int64_t> &formIds, const AAFwk::Want &want,
        const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Enable form or disable form.
     * @param formIds The Id list of forms.
     * @param enable True is enable form, false is disable form.
     * @param callerToken Caller ability token.
     */
    void OnEnableForms(const std::vector<int64_t> &formIds, const bool enable, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Lock form or unlock form.
     * @param formIds The Id list of forms.
     * @param lock True is lock form, false is unlock form.
     * @param callerToken Caller ability token.
     */
    void OnLockForms(const std::vector<int64_t> &formIds, const bool lock, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief due control form or not.
     * @param formIds The Id list of forms.
     * @param isDisablePolicy True is disable form, false is remove form.
     * @param isControl True is control form, false is not control form.
     * @param callerToken Caller ability token.
     */
    void OnDueControlForms(const std::vector<int64_t> &formIds, const bool isDisablePolicy, const bool isControl,
        const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Check if form is abnormal.
     * @param formIds The Id list of forms.
     * @param callerToken Caller ability token.
     */
    void OnCheckForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_HOST_CALLBACK_H
