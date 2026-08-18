/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_SUPPLY_STUB_H
#define OHOS_FORM_FWK_FORM_SUPPLY_STUB_H

#include <map>
#include "form_supply_interface.h"
#include "iremote_object.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormSupplyStub
 * form supply service stub.
 */
class FormSupplyStub : public IRemoteStub<IFormSupply> {
public:
    enum class CallerType : uint8_t {
        PROVIDER,  // Form provider process
        FRS,       // Form render service process
    };

    struct HandlerEntry {
        uint32_t code;             // IPC message code from IFormSupply::Message
        CallerType callerType;     // Expected caller type for this message
        int32_t (FormSupplyStub::*handler)(MessageParcel &data, MessageParcel &reply);  // Member function pointer
    };

    FormSupplyStub();
    virtual ~FormSupplyStub();
    /**
     * @brief handle remote request.
     * @param data input param.
     * @param reply output param.
     * @param option message option.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);

protected:
    /**
     * @brief Verify caller identity based on caller type;
     *        override in services layer to add actual verification logic.
     * @param callerType Indicates whether the request originates from
     *        form provider or form render service.
     * @return true if caller is authorized, false if rejected.
     *        Default returns false (deny); subclasses override for custom permission checks.
     */
    virtual bool VerifyCaller(CallerType callerType);

private:
    /**
     * @brief handle OnAcquire message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnAcquire(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief handle OnEventHandle message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnEventHandle(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief handle OnAcquireStateResult message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnAcquireStateResult(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief handle OnShareAcquire message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnShareAcquire(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief handle OnRenderTaskDone message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnRenderTaskDone(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnAcquireDataResult message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnAcquireDataResult(MessageParcel &data, MessageParcel &reply);
    /**
     * @brief handle OnStopRenderingTaskDone message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnStopRenderingTaskDone(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnRenderingBlock message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnRenderingBlock(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnRecycleForm message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnRecycleForm(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief Trigger form recover when configuration changes occur.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnRecoverFormsByConfigUpdate(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnNotifyRefreshForm message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnNotifyRefreshForm(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnRenderFormDone message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnRenderFormDone(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnRecoverFormDone message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnRecoverFormDone(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnRecycleFormDone message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnRecycleFormDone(MessageParcel &data, MessageParcel &reply);

    /**
     * @brief handle OnDeleteFormDone message.
     * @param data input param.
     * @param reply output param.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t HandleOnDeleteFormDone(MessageParcel &data, MessageParcel &reply);

private:
    static const HandlerEntry handlerTable_[];

    DISALLOW_COPY_AND_MOVE(FormSupplyStub);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_SUPPLY_STUB_H
