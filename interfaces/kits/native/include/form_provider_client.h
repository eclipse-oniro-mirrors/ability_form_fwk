/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_PROVIDER_CLIENT_H
#define OHOS_FORM_FWK_FORM_PROVIDER_CLIENT_H

#include <iremote_object.h>
#include <iremote_stub.h>
#include <map>
#include "ability.h"
#include "form_constants.h"
#include "form_js_info.h"
#include "form_provider_info.h"
#include "form_provider_stub.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormProviderStub
 * The service of the form provider.
 */
class FormProviderClient : public FormProviderStub {
public:
    FormProviderClient() = default;
    virtual ~FormProviderClient() = default;

    /**
     * @brief Acquire to give back an ProviderFormInfo. This is sync API.
     * @param formJsInfo The form js info.
     * @param want Indicates the {@link Want} structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int AcquireProviderFormInfo(const FormJsInfo &formJsInfo, const Want &want,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Notify provider when the form was deleted.
     *
     * @param formId The Id of the form.
     * @param want Indicates the structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyFormDelete(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Notify provider when the form was deleted.
     *
     * @param formIds The id list of forms.
     * @param want Indicates the structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyFormsDelete(const std::vector<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Notify provider when the form need update.
     *
     * @param formId The Id of the form.
     * @param want Indicates the structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyFormUpdate(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Event notify when change the form visible.
     *
     * @param formIds The vector of form ids.
     * @param formVisibleType The form visible type, including FORM_VISIBLE and FORM_INVISIBLE.
     * @param want Indicates the structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int EventNotify(const std::vector<int64_t> &formIds, const int32_t formVisibleType, const Want &want,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Notify provider when the temp form was cast to normal form.
     *
     * @param formId The Id of the form to update.
     * @param want Indicates the structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyFormCastTempForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Notify provider when the system configuration changed.
     *
     * @param configuration system Configuration.
     * @param want Indicates the structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    int NotifyConfigurationUpdate(const AppExecFwk::Configuration &configuration,
        const Want &want, const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Fire message event to form provider.
     * @param formId The Id of the from.
     * @param message Event message.
     * @param want The want of the request.
     * @param callerToken Form provider proxy object.
     * @return Returns ERR_OK on success, others on failure.
     */
    int FireFormEvent(const int64_t formId, const std::string &message, const Want &want,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Acquire form state to form provider.
     * @param wantArg The want of onAcquireFormState.
     * @param provider The provider info.
     * @param want The want of the request.
     * @param callerToken Form provider proxy object.
     * @return Returns ERR_OK on success, others on failure.
     */
    int AcquireState(const Want &wantArg, const std::string &provider, const Want &want,
        const sptr<IRemoteObject> &callerToken) override;

    /**
     * @brief Acquire to share form information data. This is sync API.
     * @param formId The Id of the form.
     * @param remoteDeviceId Indicates the remote device ID.
     * @param formSupplyCallback Indicates lifecycle callbacks.
     * @param requestCode Indicates the request code of this share form.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId,
        const sptr<IRemoteObject> &formSupplyCallback, int64_t requestCode) override;

    /**
     * @brief Acquire form data.
     * @param formId The Id of the form.
     * @param formSupplyCallback Indicates lifecycle callbacks.
     * @param requestCode Indicates the request code.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t AcquireFormData(int64_t formId, const sptr<IRemoteObject> &formSupplyCallback,
        int64_t requestCode) override
    {
        return ERR_OK;
    }

    /**
     * @brief Set the owner ability of the form provider client.
     *
     * @param ability The owner ability of the form provider client.
     * @return none.
     */
    void SetOwner(const std::shared_ptr<Ability> ability);

    /**
     * @brief Clear the owner ability of the form provider client.
     *
     * @param ability The owner ability of the form provider client.
     * @return none.
     */
    void ClearOwner(const std::shared_ptr<Ability> ability);

    /**
     * @brief Notify provider when the form need update.
     *
     * @param formId The Id of the form.
     * @param want Indicates the structure containing form info.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
     virtual int NotifyFormLocationUpdate(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }

protected:
    bool CheckIsSystemApp() const;
    int HandleDisconnect(const Want &want, const sptr<IRemoteObject> &callerToken);
    int HandleAcquire(const FormProviderInfo &formProviderInfo, const Want &newWant,
        const sptr<IRemoteObject> &callerToken);
    int HandleAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg, const Want &want,
                                 const sptr<IRemoteObject> &callerToken);
    void HandleRemoteAcquire(const FormJsInfo &formJsInfo, const FormProviderInfo &formProviderInfo,
        const Want &want, const sptr<IRemoteObject> &token);
    bool IsCallBySelfBundle();

private:
    std::shared_ptr<Ability> GetOwner();
    /**
     * @brief Eliminates duplicate code of returning functional error code and error code of handling disconnection.
     * This function will call HandleDisconnect() and return functional errorCode when possible, only return error
     * code of HandleDisconnect() if there's no functional error.
     * @param errCode The functional error the caller has.
     * @param want The input parameter of the caller function and is required by HandleDisconnect().
     * @param callerToken callerToken
     * @return int32_t The error code (functional/HandleDisconnect).
     */
    int DCRtnHelper(const int &errCode, const Want &want, const sptr<IRemoteObject> &callerToken);

private:
    DISALLOW_COPY_AND_MOVE(FormProviderClient);
    mutable std::mutex abilityMutex_;
    std::weak_ptr<Ability> owner_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_PROVIDER_CLIENT_H
