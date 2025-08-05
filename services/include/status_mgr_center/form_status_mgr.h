/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_STATUS_MGR_H
#define OHOS_FORM_FWK_FORM_STATUS_MGR_H

#include <singleton.h>
#include <string>
#include <unordered_map>
#include <shared_mutex>

#include "status_mgr_center/form_status_common.h"
#include "status_mgr_center/form_status_table.h"
#include "status_mgr_center/form_status_queue.h"
#include "status_mgr_center/form_event_queue.h"

namespace OHOS {
namespace AppExecFwk {

class FormStatusMgr final : public DelayedRefSingleton<FormStatusMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormStatusMgr)
    DISALLOW_COPY_AND_MOVE(FormStatusMgr);

public:
    /**
     * @brief Post a form event
     * @param formId The ID of the form
     * @param event The event to trigger
     * @param func The function to handle the event (default is nullptr)
     */
    void PostFormEvent(const int64_t formId, const FormFsmEvent event, std::function<void()> func = nullptr);

    /**
     * @brief Cancel a form event timeout task
     * @param formId Form ID
     * @param eventId Event ID
     */
    void CancelFormEventTimeout(const int64_t formId, std::string eventId);

    /**
     * @brief Gets the eventId form map
     * @param formId The ID of the form
     * @return The TID of the event
     */
    std::string GetFormEventId(const int64_t formId);

    /**
     * @brief Sets the <formId, eventId> pair to map
     * @param formId The ID of the form
     */
    void SetFormEventId(const int64_t formId);

    /**
     * @brief Delete <formId, eventId> pair form map
     * @param formId The ID of the form
     */
    void DeleteFormEventId(const int64_t formId);

private:
    /**
     * @brief Form task timeout execution
     * @param formId Form ID
     * @param timeoutMs Timeout in milliseconds
     * @param event Form FSM event
     * @param status Form FSM status
     */
    void ExecFormTaskTimeout(
        const int64_t formId, FormEventTimeout timeoutMs, FormFsmEvent event, FormFsmStatus status);

    /**
     * @brief Executing a State Machine Task
     * @param formId The ID of the form
     * @param event The event to trigger
     * @param func The function to handle the event (default is nullptr)
     * @return True on success, false on fail.
     */
    bool ExecStatusMachineTask(const int64_t formId, const FormFsmEvent event, std::function<void()> func = nullptr);

    /**
     * @brief Form task execution function
     * @param processType Form processing policy type
     * @param formId Form ID
     * @param event Triggering form event
     * @param func Process function
     */
    void ExecFormTask(
        FormFsmProcessType processType, const int64_t formId, const FormFsmEvent event, std::function<void()> func);

    /**
     * @brief Process a task directly
     * @param formId Form ID
     * @param event Form FSM event
     * @param func Function to execute
     */
    void ProcessTaskDirect(const int64_t formId, const FormFsmEvent event, std::function<void()> func);

    /**
     * @brief Add a task to the queue, retain only rendering tasks
     * @param formId Form ID
     * @param event Form FSM event
     * @param func Function to execute
     */
    void AddTaskToQueueUnique(const int64_t formId, const FormFsmEvent event, std::function<void()> func);

    /**
     * @brief Add a task to the queue, push directly to the queue
     * @param formId Form ID
     * @param event Form FSM event
     * @param func Function to execute
     */
    void AddTaskToQueuePush(const int64_t formId, const FormFsmEvent event, std::function<void()> func);

    /**
     * @brief Add a task to the queue, retain only inserted tasks
     * @param formId Form ID
     * @param event Form FSM event
     * @param func Function to execute
     */
    void AddTaskToQueueDelete(const int64_t formId, const FormFsmEvent event, std::function<void()> func);

    /**
     * @brief Process a task from the queue
     * @param formId Form ID
     */
    void ProcessTaskFromQueue(const int64_t formId);

    /**
     * @brief Delete fsm info
     * @param formId Form ID
     */
    void ProcessTaskDelete(const int64_t formId);

    /**
     * @brief Process a task from the retry queue
     * @param formId Form ID
     */
    void ProcessTaskFromRetry(const int64_t formId);

    /**
     * @brief Check if a form has an event queue from map
     * @param formId Form ID
     * @return True if the form has an event queue, false otherwise
     */
    bool HasFormEventQueue(const int64_t formId);

    /**
     * @brief Get the event queue from map
     * @param formId Form ID
     * @return Shared pointer to the form's event queue
     */
    const std::shared_ptr<FormEventQueue> GetFormEventQueue(const int64_t formId);

    /**
     * @brief Delete the event queue from map
     * @param formId Form ID
     */
    void DeleteFormEventQueue(const int64_t formId);

    // <formId, formEventQueue>
    std::shared_mutex formEventQueueMutex_;
    std::unordered_map<int64_t, std::shared_ptr<FormEventQueue>> formEventQueueMap_;

    // <formId, eventId>
    std::shared_mutex formEventIdMapMutex_;
    std::unordered_map<int64_t, std::string> formEventIdMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_STATUS_MGR_H
