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

#ifndef OHOS_FORM_FWK_FORM_SUPPLY_PROXY_H
#define OHOS_FORM_FWK_FORM_SUPPLY_PROXY_H

#include "form_supply_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormSupplyProxy
 * FormSupplyProxy is used to access form supply service.
 */
class FormSupplyProxy : public IRemoteProxy<IFormSupply> {
public:
    explicit FormSupplyProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IFormSupply>(impl)
    {}

    virtual ~FormSupplyProxy() = default;

    /**
     * @brief Send form binding data from form provider to fms.
     * @param providerFormInfo Form binding data.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override;

    /**
     * @brief Send other event  to fms.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnEventHandle(const Want &want) override;

    /**
     * @brief Accept form state from form provider.
     * @param state Form state.
     * @param provider provider info.
     * @param wantArg The want of onAcquireFormState.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg,
                                     const Want &want) override;

    /**
     * @brief Accept form sharing data from form provider.
     * @param formId The Id of the from.
     * @param remoteDeviceId Indicates the remote device ID.
     * @param wantParams Indicates the data information shared by the form.
     * @param requestCode Indicates the requested id.
     * @param result Indicates the results of parsing shared data.
     * @return Returns ERR_OK on success, others on failure.
     */
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override;

    /**
     * @brief Accept form data from form provider.
     * @param wantParams Indicates the data information acquired by the form.
     * @param requestCode Indicates the requested id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode) override;

    /**
     * @brief Accept form render task done from render service.
     * @param formId The Id of the form.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override;

    /**
     * @brief Accept form stop rendering task done from render service.
     * @param formId The Id of the form.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override;

    /**
     * @brief Accept rendering block from render service.
     * @param bundleName The block of bundleName.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnRenderingBlock(const std::string &bundleName) override;

    /**
     * @brief Accept status data of form to be recycled from render service.
     * @param formId The id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnRecycleForm(const int64_t formId, const Want &want) override;

    /**
     * @brief Trigger card recover when configuration changes occur.
     * @param formIds The ids of the forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnRecoverFormsByConfigUpdate(std::vector<int64_t> &formIds) override;

    int32_t OnNotifyRefreshForm(const int64_t formId) override;

    /**
     * @brief Accept form render done from form render service.
     * @param formId The Id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnRenderFormDone(const int64_t formId, const Want &want) override;

    /**
     * @brief Accept form recover done from form render service.
     * @param formId The Id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnRecoverFormDone(const int64_t formId, const Want &want) override;

    /**
     * @brief Accept form recycle done from form render service.
     * @param formId The Id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnRecycleFormDone(const int64_t formId, const Want &want) override;

    /**
     * @brief Accept form delete done from form render service.
     * @param formId The Id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t OnDeleteFormDone(const int64_t formId, const Want &want) override;

private:
    template<typename T>
    int GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos);
    bool WriteInterfaceToken(MessageParcel &data);
    int SendTransactCmd(IFormSupply::Message code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option);

private:
    static inline BrokerDelegator<FormSupplyProxy> delegator_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_SUPPLY_PROXY_H
