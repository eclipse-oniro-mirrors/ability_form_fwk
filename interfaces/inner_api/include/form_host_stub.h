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

#ifndef OHOS_FORM_FWK_FORM_HOST_STUB_H
#define OHOS_FORM_FWK_FORM_HOST_STUB_H

#include <map>

#include "form_host_interface.h"
#include "iremote_object.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormHostStub
 * Form host service stub.
 */
class FormHostStub : public IRemoteStub<IFormHost> {
public:
    FormHostStub();
    virtual ~FormHostStub();
    /**
     * @brief handle remote request.
     * @param data input param.
     * @param reply output param.
     * @param option message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

private:
    /**
     * @brief handle OnAcquired message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int HandleAcquired(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief handle OnUpdate message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int HandleOnUpdate(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief handle OnUnInstall message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int HandleOnUninstall(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnAcquireState message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int HandleOnAcquireState(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnShareFormResponse message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnShareFormResponse(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnError message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnError(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnError message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnErrorForms(MessageParcel &data, MessageParcel &reply);
    
    /**
     * @brief handle OnAcquireDataResponse message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnAcquireDataResponse(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnRecycleForm message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnRecycleForm(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnEnableForm message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnEnableForm(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnLockForm message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnLockForm(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnDueControlForm message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnDueControlForm(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle HandleOnCheckForm message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnCheckForm(MessageParcel &data, MessageParcel &reply);

private:
    DISALLOW_COPY_AND_MOVE(FormHostStub);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_HOST_STUB_H
