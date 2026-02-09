/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_SYS_EVENT_RECEIVER_H
#define OHOS_FORM_FWK_FORM_SYS_EVENT_RECEIVER_H

#include "common_event_subscriber.h"
#include "common_event_subscribe_info.h"
#include "common/event/form_event_handler.h"
#include "common/event/form_event_util.h"
#include "common/util/form_serial_queue.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormSysEventReceiver
 * Receive system common event.
 */
class FormSysEventReceiver : public EventFwk::CommonEventSubscriber,
    public std::enable_shared_from_this<FormSysEventReceiver> {
public:
    FormSysEventReceiver() = default;
    FormSysEventReceiver(const EventFwk::CommonEventSubscribeInfo &subscriberInfo);
    virtual ~FormSysEventReceiver() = default;
    /**
     * @brief System common event receiver.
     * @param eventData Common event data.
     */
    virtual void OnReceiveEvent(const EventFwk::CommonEventData &eventData) override;

    /**
     * @brief Init form infos and register form bundle event callback.
     */
    void InitFormInfosAndRegister();

private:
    void HandleUserIdRemoved(const int32_t userId); // multiuser
    bool IsSameForm(const FormRecord &record, const FormInfo &formInfo);
    void HandleBundleScanFinished();
    void HandleUserSwitched(const EventFwk::CommonEventData &eventData);
    void HandleAbilityUpdate(const AAFwk::Want& want, std::string &bundleName);
    void HandlePackageDataCleared(std::string &bundleName, int32_t userId);
    void HandleScreenUnlocked(int32_t userId);
    void HandleUserUnlocked(int32_t userId);
    void HandleScreenOn();
    void RecycleForms(int32_t userId);
    void HandleUserStopped(const int32_t userId);
    void HandleUserStarted(const int32_t userId);
private:
    int32_t lastUserId_ = 0;
    std::mutex lastUserIdMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_SYS_EVENT_RECEIVER_H
