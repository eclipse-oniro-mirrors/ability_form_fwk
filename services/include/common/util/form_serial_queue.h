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

#ifndef OHOS_FORM_FWK_FORM_SERIAL_QUEUE_H
#define OHOS_FORM_FWK_FORM_SERIAL_QUEUE_H

#include <functional>
#include <map>
#include <memory>
#include <shared_mutex>
#include <string>

#include "queue/form_base_serial_queue.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @brief FormSerialQueue - Wrapper class for backward compatibility
 * This class now wraps FormBaseSerialQueue from the common module.
 * It provides the same interface as the original implementation but
 * delegates all operations to the shared FormBaseSerialQueue.
 * Migration note: New code should use FormBaseSerialQueue directly.
 */
class FormSerialQueue final {
public:
    /**
     * @brief Constructor
     * @param queueName Name of the queue for identification
     */
    explicit FormSerialQueue(const std::string &queueName);

    /**
     * @brief Destructor
     */
    ~FormSerialQueue();

    /**
     * @brief Schedule a one-shot task
     * @param ms Delay time in milliseconds
     * @param func Task function to execute
     * @return true if scheduled successfully, false otherwise
     */
    bool ScheduleTask(uint64_t ms, std::function<void()> func);

    /**
     * @brief Schedule a delayed task using pair<int64_t, int64_t> as key
     * @param eventMsg Task key pair
     * @param ms Delay time in milliseconds
     * @param func Task function
     * @return true if successful
     */
    bool ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg,
        uint32_t ms, std::function<void()> func);

    /**
     * @brief Cancel a delayed task using pair<int64_t, int64_t> as key
     * @param eventMsg Task key pair
     * @return true if successful
     */
    bool CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg);

private:
    // Use FormBaseSerialQueue from common module
    std::shared_ptr<Common::FormBaseSerialQueue> baseQueue_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_SERIAL_QUEUE_H