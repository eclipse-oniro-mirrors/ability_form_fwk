/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "common/util/form_serial_queue.h"

namespace OHOS {
namespace AppExecFwk {

FormSerialQueue::FormSerialQueue(const std::string &queueName) {}

FormSerialQueue::~FormSerialQueue() {}

bool FormSerialQueue::ScheduleTask(uint64_t ms, std::function<void()> func)
{
    return true;
}

bool FormSerialQueue::ScheduleDelayTask(const std::pair<int64_t, int64_t> &eventMsg,
    uint32_t ms, std::function<void()> func)
{
    return true;
}

bool FormSerialQueue::CancelDelayTask(const std::pair<int64_t, int64_t> &eventMsg)
{
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
