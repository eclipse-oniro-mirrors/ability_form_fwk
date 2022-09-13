/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_HOST_CALLER_H
#define OHOS_FORM_FWK_FORM_HOST_CALLER_H

#include <iremote_object.h>

#include "form_js_info.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormHostCaller
 * The caller of the form host.
 */
class FormHostCaller {
public:
    FormHostCaller(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &callerToken) :
        formJsInfo_(formJsInfo), callerToken_(callerToken) {}
    ~FormHostCaller() = default;

    /**
     * @brief Update form with formId.
     * @param formId Indicates the Id of the form to update.
     * @param formProviderData Indicates the form provider data.
     */
    void UpdateForm(int64_t formId, const FormProviderData &formProviderData);

    /**
    * @brief Notify the form service that the form user's lifecycle is updated.
    *
    * This should be called when form user request form.
    *
    * @param formId Indicates the unique id of form.
    * @param callerToken Indicates the callback remote object of specified form user.
    * @param want Indicates information passed to supplier.
    * @return Returns ERR_OK on success, others on failure.
    */
    ErrCode RequestForm(int64_t formId, const sptr<IRemoteObject> &callerToken, const AAFwk::Want &want);

    /**
     * @brief Process js message event.
     * @param formId Indicates the unique id of form.
     * @param want Indicates information passed to supplier.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode MessageEvent(int64_t formId, const AAFwk::Want &want, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Add deathRecipient object to formHostClient_.
     * @param deathRecipient DeathRecipient object.
     */
    void AddDeathRecipient(sptr<IRemoteObject::DeathRecipient> deathRecipient);

    /**
     * @brief Is the same caller token.
     * @param callerToken Caller ability token.
     */
    bool IsSameToken(const sptr<IRemoteObject> &callerToken) const;
private:
    FormJsInfo formJsInfo_;
    sptr<IRemoteObject> callerToken_;
};

/**
 * @class FormHostCallerRecipient
 * FormHostCallerRecipient notices IRemoteBroker died.
 */
class FormHostCallerRecipient : public IRemoteObject::DeathRecipient {
public:
    using RemoteDiedHandler = std::function<void(const wptr<IRemoteObject> &)>;
    FormHostCallerRecipient(RemoteDiedHandler handler) : handler_(handler) {}
    ~FormHostCallerRecipient() = default;

    /**
     * @brief handle remote object died event.
     * @param remote remote object.
     */
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
private:
    RemoteDiedHandler handler_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_HOST_CALLER_H
