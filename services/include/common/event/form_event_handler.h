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

#ifndef FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_EVENT_HANDLER_H
#define FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_EVENT_HANDLER_H

#include <memory>
#include <set>
#include "event_handler.h"
#include "event_runner.h"
#include "common/util/form_serial_queue.h"

namespace OHOS {
namespace AppExecFwk {
namespace MSG {
const int64_t FORM_SHARE_INFO_DELAY_MSG = 1;
const int64_t FORM_PACKAGE_FREE_INSTALL_DELAY_MSG = 2;
}

class FormEventTimeoutObserver {
public:
    FormEventTimeoutObserver() = default;
    virtual ~FormEventTimeoutObserver() = default;

    virtual void OnEventTimeoutResponse(int64_t msg, int64_t eventId) = 0;
};

/**
 * @class FormEventHandler
 * FormEventHandler handling the form event.
 */
class FormEventHandler : public std::enable_shared_from_this<FormEventHandler> {
public:
    FormEventHandler(const std::shared_ptr<FormSerialQueue> &serialQueue);
    virtual ~FormEventHandler() = default;

    static int64_t GetEventId();

    /**
     * Register event timeout observer.
     *
     * @param observer The observer of form event timeout.
     */
    void RegisterEventTimeoutObserver(const std::shared_ptr<FormEventTimeoutObserver> &observer);

    /**
     * Unregister event timeout observer.
     *
     * @param observer The observer of form event timeout.
     */
    void UnregisterEventTimeoutObserver(const std::shared_ptr<FormEventTimeoutObserver> &observer);

    /**
     * ProcessEvent with request.
     *
     * @param msg, The event message.
     * @param eventId, The event Id.
     * @param delayTime, The delay time.
     */
    void ProcessEvent(int64_t msg, int64_t eventId, int64_t delayTime = 0);

private:
    static std::atomic<int64_t> eventId_;
    std::shared_ptr<FormSerialQueue> serialQueue_ = nullptr;
    std::set<std::shared_ptr<FormEventTimeoutObserver>> observers_;
    mutable std::mutex observerMutex_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_EVENT_HANDLER_H
