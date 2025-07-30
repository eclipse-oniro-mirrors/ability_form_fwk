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

#include <map>
#include <shared_mutex>
#include <string>

#include "ffrt.h"

namespace OHOS {
namespace AppExecFwk {
class FormSerialQueue final {
public:
    explicit FormSerialQueue(const std::string &queueName);
    ~FormSerialQueue();
    bool ScheduleTask(uint64_t ms, std::function<void()> func);
    bool ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg, uint32_t ms, std::function<void()> func);
    bool CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg);
    bool ScheduleDelayTask(const std::pair<int64_t, std::string> &eventMsg, uint32_t ms, std::function<void()> func);
    bool CancelDelayTask(const std::pair<int64_t, std::string> &eventMsg);
private:
    std::shared_mutex mutex_;
    std::map<std::pair<int64_t, int64_t>, ffrt::task_handle> taskMap_;
    std::shared_mutex stringTaskMutex_;
    std::map<std::pair<int64_t, std::string>, ffrt::task_handle> stringTaskMap_;
    ffrt::queue queue_;
};
}
}
#endif // OHOS_FORM_FWK_FORM_SERIAL_QUEUE_H
