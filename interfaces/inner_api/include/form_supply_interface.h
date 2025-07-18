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

#ifndef OHOS_FORM_FWK_FORM_SUPPLY_INTERFACE_H
#define OHOS_FORM_FWK_FORM_SUPPLY_INTERFACE_H

#include <vector>

#include "form_provider_info.h"
#include "form_state_info.h"
#include "ipc_types.h"
#include "iremote_broker.h"

#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using OHOS::AAFwk::Want;

/**
 * @class IFormSupply
 * IFormSupply interface is used to access form supply service.
 */
class IFormSupply : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.FormSupply");

    /**
     * @brief Accept form binding data from form provider.
     * @param providerFormInfo Form binding data.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnAcquire(const FormProviderInfo &formInfo, const Want &want) = 0;

    /**
     * @brief Accept other event.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnEventHandle(const Want &want) = 0;

    /**
     * @brief Accept form state from form provider.
     * @param state Form state.
     * @param provider provider info.
     * @param wantArg The want of onAcquireFormState.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg,
                                     const Want &want) = 0;

    /**
     * @brief Accept form sharing data from form provider.
     * @param formId The Id of the from.
     * @param remoteDeviceId Indicates the remote device ID.
     * @param wantParams Indicates the data information shared by the form.
     * @param requestCode Indicates the requested id.
     * @param result Indicates the results of parsing shared data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) = 0;

    /**
     * @brief Accept form data from form provider.
     * @param wantParams Indicates the data information acquired by the form.
     * @param requestCode Indicates the requested id.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode) = 0;

    /**
     * @brief Accept form render task done from render service.
     * @param formId The Id of the form.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRenderTaskDone(int64_t formId, const Want &want) = 0;

    /**
     * @brief Accept form stop rendering task done from render service.
     * @param formId The Id of the form.
     * @param want input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) = 0;

    /**
     * @brief Accept rendering block from render service.
     * @param bundleName The block of bundleName.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRenderingBlock(const std::string &bundleName) { return ERR_OK; }

    /**
     * @brief Accept status data of form to be recycled from render service.
     * @param formId The id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRecycleForm(const int64_t formId, const Want &want) { return ERR_OK; }

    /**
     * @brief Trigger card recover when configuration changes occur.
     * @param formIds The ids of the forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRecoverFormsByConfigUpdate(std::vector<int64_t> &formIds) { return ERR_OK; }

    virtual int32_t OnNotifyRefreshForm(const int64_t formId) { return ERR_OK; }

    /**
     * @brief Accept form render done from form render service.
     * @param formId The Id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRenderFormDone(const int64_t formId, const Want &want) { return ERR_OK; }

    /**
     * @brief Accept form recover done from form render service.
     * @param formId The Id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRecoverFormDone(const int64_t formId, const Want &want) { return ERR_OK; }

    /**
     * @brief Accept form recycle done from form render service.
     * @param formId The Id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnRecycleFormDone(const int64_t formId, const Want &want) { return ERR_OK; }

    /**
     * @brief Accept form delete done from form render service.
     * @param formId The Id of the form.
     * @param want Input data.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t OnDeleteFormDone(const int64_t formId, const Want &want) { return ERR_OK; }

    enum class Message {
        // ipc id 1-1000 for kit
        // ipc id 1001-2000 for DMS
        // ipc id 2001-3000 for tools
        // ipc id for create (3201)
        TRANSACTION_FORM_ACQUIRED = 3201,
        TRANSACTION_EVENT_HANDLE,
        TRANSACTION_FORM_STATE_ACQUIRED,
        TRANSACTION_FORM_SHARE_ACQUIRED,
        TRANSACTION_FORM_RENDER_TASK_DONE,
        TRANSACTION_FORM_STOP_RENDERING_TASK_DONE,
        TRANSACTION_FORM_ACQUIRED_DATA,
        TRANSACTION_FORM_RENDERING_BLOCK,
        TRANSACTION_FORM_RECYCLE_FORM,
        TRANSACTION_FORM_RECOVER_FORM_BY_CONFIG_UPDATE,
        TRANSACTION_NOTIFY_REFRESH,
        TRANSACTION_FORM_RENDER_FORM_DONE,
        TRANSACTION_FORM_RECOVER_FORM_DONE,
        TRANSACTION_FORM_RECYCLE_FORM_DONE,
        TRANSACTION_FORM_DELETE_FORM_DONE,
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_SUPPLY_INTERFACE_H
