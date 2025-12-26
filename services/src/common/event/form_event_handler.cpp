/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "common/event/form_event_handler.h"

#include <memory>

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
int64_t FormEventHandler::eventId_ = 0;
FormEventHandler::FormEventHandler(const std::shared_ptr<FormSerialQueue> &serialQueue)
    : serialQueue_(serialQueue)
{
}

void FormEventHandler::ProcessEvent(int64_t msg, int64_t eventId, int64_t delayTime)
{
    if (serialQueue_ == nullptr) {
        HILOG_ERROR("null serialQueue_");
        return;
    }

    auto task = [thisWeakPtr = weak_from_this(), msg, eventId]() {
        auto sharedThis = thisWeakPtr.lock();
        if (sharedThis == nullptr) {
            HILOG_ERROR("null sharedThis");
            return;
        }
        std::lock_guard<std::mutex> lock(sharedThis->observerMutex_);
        for (auto &observer : sharedThis->observers_) {
            if (observer == nullptr) {
                HILOG_ERROR("null observer");
                continue;
            }
            observer->OnEventTimeoutResponse(msg, eventId);
        }
    };
    serialQueue_->ScheduleDelayTask(std::make_pair(msg, eventId), delayTime, task);
}

int64_t FormEventHandler::GetEventId()
{
    eventId_++;
    return eventId_;
}

void FormEventHandler::RegisterEventTimeoutObserver(const std::shared_ptr<FormEventTimeoutObserver> &observer)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(observerMutex_);
    auto iter = observers_.find(observer);
    if (iter != observers_.end()) {
        HILOG_ERROR("observer repeat attach");
        return;
    }
    observers_.emplace(observer);
}

void FormEventHandler::UnregisterEventTimeoutObserver(const std::shared_ptr<FormEventTimeoutObserver> &observer)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(observerMutex_);
    auto iter = observers_.find(observer);
    if (iter == observers_.end()) {
        HILOG_ERROR("observer not exist");
        return;
    }

    observers_.erase(iter);
}
} // namespace AppExecFwk
} // namespace OHOS
