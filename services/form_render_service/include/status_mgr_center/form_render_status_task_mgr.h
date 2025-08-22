/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_RENDER_STATUS_TASK_MGR_H
#define OHOS_FORM_FWK_FORM_RENDER_STATUS_TASK_MGR_H

#include <singleton.h>
#include "iremote_object.h"
#include "want.h"

#include "status_mgr_center/form_status_common.h"
#include "form_supply_proxy.h"
#include "form_render_serial_queue.h"

namespace OHOS {
namespace AppExecFwk {
namespace FormRender {
using Want = OHOS::AAFwk::Want;
class FormRenderStatusTaskMgr final : public DelayedRefSingleton<FormRenderStatusTaskMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormRenderStatusTaskMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormRenderStatusTaskMgr);

    void SetSerialQueue(const std::shared_ptr<FormRenderSerialQueue> &serialQueue)
    {
        if (serialQueue == nullptr) {
            return;
        }
        serialQueue_ = serialQueue;
    }

    /**
     * @brief Callback function after form rendering is completed
     * @param formId Form ID
     * @param event Form State Machine event
     * @param formSupplyClient Smart pointer to form supply client
     * @param want Form parameter object
     */
    void OnRenderFormDone(
        const int64_t formId, const FormFsmEvent event, const sptr<IFormSupply> formSupplyClient, const Want &want);

    /**
     * @brief Callback function after form recycling data is completed
     * @param formId Form ID
     * @param event Form State Machine event
     * @param statusData Serialized form status data
     * @param want Form parameter object
     * @param formSupplyClient Smart pointer to form supply client
     */
    void OnRecycleForm(const int64_t formId, const FormFsmEvent event, const std::string &statusData, const Want &want,
        const sptr<IFormSupply> formSupplyClient);

    /**
     * Callback function after form recovery is completed
     * @param formId Form ID
     * @param event Form State Machine event
     * @param formSupplyClient Smart pointer to form supply client
     * @param want Form parameter object
     */
    void OnRecoverFormDone(
        const int64_t formId, const FormFsmEvent event, const sptr<IFormSupply> formSupplyClient, const Want &want);

    /**
     * @brief Callback function after form deletion is completed
     * @param formId Form ID
     * @param event Form State Machine event
     * @param formSupplyClient Smart pointer to form supply client
     * @param want Form parameter object
     */
    void OnDeleteFormDone(
        const int64_t formId, const FormFsmEvent event, const sptr<IFormSupply> formSupplyClient, const Want &want);

    /**
     * @brief Callback function after form recycling is completed
     * @param formId Form ID
     * @param event Form State Machine event
     * @param formSupplyClient Smart pointer to form supply client
     * @param want Form parameter object
     */
    void OnRecycleFormDone(
        const int64_t formId, const FormFsmEvent event, const sptr<IFormSupply> formSupplyClient, const Want &want);

    /**
     * @brief Schedules form recycle timeout task
     * @param formId Form ID
     * @return bool Returns true if the timeout was successfully scheduled, false otherwise
     */
    bool ScheduleRecycleTimeout(const int64_t formId);

    /**
     * @brief Cancel form recycle timeout task
     * @param formId Form ID
     * @return bool Returns true if the timeout was successfully canceled, false otherwise
     */
    bool CancelRecycleTimeout(const int64_t formId);

private:
    std::mutex serialQueueMutex_;
    std::shared_ptr<FormRenderSerialQueue> serialQueue_ = nullptr;
};
}  // namespace FormRender
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_RENDER_STATUS_TASK_MGR_H