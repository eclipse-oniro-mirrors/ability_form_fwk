/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_HOST_PROXY_H
#define OHOS_FORM_FWK_FORM_HOST_PROXY_H

#include "fms_log_wrapper.h"
#include "form_host_interface.h"
#include "form_state_info.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormHostProxy
 * Form host proxy is used to access form host service.
 */
class FormHostProxy : public IRemoteProxy<IFormHost> {
public:
    explicit FormHostProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IFormHost>(impl)
    {}

    virtual ~FormHostProxy() = default;

    /**
     * @brief Request to give back a Form.
     * @param formInfo Form info.
     * @param token Provider client token.
     */
    void OnAcquired(const FormJsInfo &formInfo, const sptr<IRemoteObject> &token) override;

    /**
     * @brief Form is updated.
     * @param formInfo Form info.
     */
    virtual void OnUpdate(const FormJsInfo &formInfo) override;

    /**
     * @brief Form provider is uninstalled.
     * @param formIds The Id list of the forms.
     */
    virtual void OnUninstall(const std::vector<int64_t> &formIds) override;

    /**
     * @brief Form provider is acquire state
     * @param state The form state.
     * @param want The form want.
     */
    virtual void OnAcquireState(FormState state, const AAFwk::Want &want) override;

    /**
     * @brief Responsive form sharing.
     * @param requestCode The request code of this share form.
     * @param result Share form result.
     */
    void OnShareFormResponse(int64_t requestCode, int32_t result) override;

    /**
     * @brief Form provider has acquired data
     * @param wantParams Indicates the data information acquired by the form.
     * @param requestCode Indicates the requested id.
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
     * @brief Return error to host.
     *
     * @param errorCode Indicates error-code of the form.
     * @param errorMsg Indicates error-message of the form.
     * @param formIds Indicates ids of the form.
     */
    void OnError(int32_t errorCode, const std::string &errorMsg, std::vector<int64_t> &formIds) override;
 
    /**
     * @brief Recycle form.
     *
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
     * @brief disable form style
     * @param formIds The Id list of the forms.
     * @param isDisable True is disable form, false is enable form.
     */
    void OnDueDisableForm(const std::vector<int64_t> &formIds, const bool isDisable) override;

    /**
     * @brief remove form style
     * @param formIds The Id list of the forms.
     * @param isRemove True is remove form, false is enable form.
     */
    void OnDueRemoveForm(const std::vector<int64_t> &formIds, const bool isRemove) override;
private:
    template <typename T>
    int GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos);
    bool WriteInterfaceToken(MessageParcel &data);
    int SendTransactCmd(IFormHost::Message code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

private:
    static inline BrokerDelegator<FormHostProxy> delegator_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_HOST_PROXY_H
