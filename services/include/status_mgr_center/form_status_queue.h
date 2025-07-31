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

#ifndef OHOS_FORM_FWK_FORM_STATUS_QUEUE_H
#define OHOS_FORM_FWK_FORM_STATUS_QUEUE_H

#include <singleton.h>
#include "common/util/form_serial_queue.h"

namespace OHOS {
namespace AppExecFwk {
class FormStatusQueue final : public DelayedRefSingleton<FormStatusQueue> {
    DECLARE_DELAYED_REF_SINGLETON(FormStatusQueue)

public:
    DISALLOW_COPY_AND_MOVE(FormStatusQueue);

    /**
     * @brief Schedule a task
     * @param ms Delay time
     * @param func Function to execute
     * @return True if the task is scheduled successfully, false otherwise
     */
    bool ScheduleTask(uint64_t ms, std::function<void()> func);

    /**
     * @brief Schedule a delayed task
     * @param eventMsg Event message containing form ID and event ID
     * @param ms Delay time
     * @param func Function to execute
     * @return True if the task is scheduled successfully, false otherwise
     */
    bool ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg, uint64_t ms, std::function<void()> func);

    /**
     * @brief Cancel a delayed task
     * @param eventMsg Event message containing form ID and event ID
     * @return True if the task is canceled successfully, false otherwise
     */
    bool CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg);

private:
    std::shared_ptr<FormSerialQueue> serialQueue_ = nullptr;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_STATUS_QUEUE_H