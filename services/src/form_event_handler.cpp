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

#include "form_event_handler.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
int64_t FormEventHandler::eventId_ = 0;
FormEventHandler::FormEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner)
    : AppExecFwk::EventHandler(runner)
{
}

void FormEventHandler::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
    if (!event) {
        HILOG_ERROR("event is nullptr");
        return;
    }

    std::lock_guard<std::mutex> lock(observerMutex_);
    for (auto &observer : observers_) {
        if (observer == nullptr) {
            HILOG_ERROR("observer is nullptr");
            continue;
        }

        observer->OnEventTimeoutResponse(event->GetInnerEventId(), event->GetParam());
    }
}

int64_t FormEventHandler::GetEventId()
{
    eventId_++;
    return eventId_;
}

void FormEventHandler::RegisterEventTimeoutObserver(const std::shared_ptr<FormEventTimeoutObserver> &observer)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    std::lock_guard<std::mutex> lock(observerMutex_);
    auto iter = observers_.find(observer);
    if (iter != observers_.end()) {
        HILOG_ERROR("observer repeat attach.");
        return;
    }
    observers_.emplace(observer);
}

void FormEventHandler::UnregisterEventTimeoutObserver(const std::shared_ptr<FormEventTimeoutObserver> &observer)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    std::lock_guard<std::mutex> lock(observerMutex_);
    auto iter = observers_.find(observer);
    if (iter == observers_.end()) {
        HILOG_ERROR("observer is not exist.");
        return;
    }

    observers_.erase(iter);
}
} // namespace AppExecFwk
} // namespace OHOS
