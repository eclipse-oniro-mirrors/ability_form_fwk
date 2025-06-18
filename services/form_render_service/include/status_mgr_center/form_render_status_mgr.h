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

#ifndef OHOS_FORM_FWK_FORM_RENDER_STATUS_MGR_H
#define OHOS_FORM_FWK_FORM_RENDER_STATUS_MGR_H

#include <singleton.h>
#include <string>
#include <unordered_map>
#include <shared_mutex>

#include "status_mgr_center/form_status_common.h"
#include "status_mgr_center/form_render_status_table.h"
#include "status_mgr_center/form_render_status.h"

namespace OHOS {
namespace AppExecFwk {

class FormRenderStatusMgr final : public DelayedRefSingleton<FormRenderStatusMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormRenderStatusMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormRenderStatusMgr);

    /**
     * @brief Posts a form event
     * @param formId The ID of the form
     * @param event The event to trigger
     * @param func The function to handle the event
     * @return The event handling result (default is nullptr)
     */
    int32_t PostFormEvent(const int64_t formId, const FormFsmEvent event, std::function<int32_t()> func = nullptr);

    /**
     * @brief Gets the eventId form map
     * @param formId The ID of the form
     * @return The TID of the event
     */
    std::string GetFormEventId(const int64_t formId);

    /**
     * @brief Sets the <formId, eventId> pair to map
     * @param formId The ID of the form
     * @param eventId The ID of the event
     */
    void SetFormEventId(const int64_t formId, std::string &eventId);

    /**
     * @brief Delete <formId, eventId> pair form map
     * @param formId The ID of the form
     */
    void DeleteFormEventId(const int64_t formId);

private:
    /**
     * @brief Form task execution function
     * @param processType Form processing policy type
     * @param formId Form ID
     * @param event Triggering form event
     * @param status Current form status
     * @param func Process function
     * @return Returns the execution result, success returns 0, failure returns -1
     */
    int32_t ExecFormTask(FormFsmProcessType processType, const int64_t formId, const FormFsmEvent event,
        const FormFsmStatus status, std::function<int32_t()> func);

    /**
     * @brief Direct processing task
     * @param func Process function
     * @return Returns the execution result, success returns 0, failure returns -1
     */
    int32_t ProcessTaskDirect(std::function<int32_t()> func);

    /**
     * @brief Delete fsm info
     * @param formId Form ID
     * @return Returns the execution result, success returns 0, failure returns -1
     */
    int32_t ProcessTaskDelete(const int64_t formId);

    /**
     * @brief Print task information
     * @param formId Form ID
     * @param event Form FSM event
     * @param status Form FSM status
     * @return Returns the execution result, success returns 0, failure returns -1
     */
    int32_t PrintTaskInfo(const int64_t formId, const FormFsmEvent event, const FormFsmStatus status);

    // <formId, eventId>
    std::shared_mutex formEventIdMapMutex_;
    std::unordered_map<int64_t, std::string> formEventIdMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_RENDER_STATUS_MGR_H
