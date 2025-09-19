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

#ifndef OHOS_FORM_FWK_FORM_EVENT_QUEUE_H
#define OHOS_FORM_FWK_FORM_EVENT_QUEUE_H

#include <string>
#include <mutex>
#include <queue>

#include "status_mgr_center/form_status_common.h"

namespace OHOS {
namespace AppExecFwk {

class FormEventTaskInfo {
public:
    FormEventTaskInfo() = default;
    FormEventTaskInfo(int64_t formId, FormFsmEvent formEvent, std::function<void()> func)
        : formId_(formId), formEvent_(formEvent), func_(func)
    {}

    inline int64_t getFormId() const
    {
        return formId_;
    }

    inline FormFsmEvent getFormEvent() const
    {
        return formEvent_;
    }

    inline std::function<void()> getFunc() const
    {
        return func_;
    }

protected:
    int64_t formId_;              // Form ID
    FormFsmEvent formEvent_;      // Form FSM event
    std::function<void()> func_;  // Executing Function
};

class FormEventQueue final {
public:
    explicit FormEventQueue(int64_t formId);
    ~FormEventQueue();

    /**
     * @brief Push form event to queue
     * @param eventInfo Form event task information
     * @return Returns true if execute success, false otherwise.
     */
    bool PushFormEvent(FormEventTaskInfo &eventInfo);

    /**
     * @brief Pop form event from queue
     * @param eventInfo Form event task information
     * @return Returns true if pop success, false otherwise
     */
    bool PopFormEvent(FormEventTaskInfo &eventInfo);

    /**
     * @brief Check if the event queue is empty
     * @return Returns true if the queue is empty, false otherwise
     */
    bool IsEventQueueEmpty();

    /**
     * @brief Get the event queue
     * @return Returns the reference to the event queue
     */
    const std::queue<FormEventTaskInfo> &GetEventQueue();

private:
    bool ReportQueueOverLimit(const int64_t formId);

    std::mutex eventQueueMutex_;
    std::queue<FormEventTaskInfo> eventQueue_;
    int64_t formId_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_EVENT_QUEUE_H
