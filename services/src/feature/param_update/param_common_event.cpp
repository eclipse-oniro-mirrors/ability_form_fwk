/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "feature/param_update/param_common_event.h"

#include <common_event_data.h>
#include <common_event_manager.h>
#include <common_event_support.h>
#include "common_event_subscriber.h"
#include <memory>
#include <unistd.h>

#include "feature/param_update/param_manager.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_event_report.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t RETRY_SUBSCRIBER = 3;
constexpr const char *EVENT_INFO_TYPE = "type";
constexpr const char *EVENT_INFO_SUBTYPE = "subtype";
constexpr const char *CFG_UPDATED_ACTION = "usual.event.DUE_SA_CFG_UPDATED";
constexpr const char *PARAM_CONFIG_TYPE = "FormMgrConfig";
constexpr const char *RECEIVE_UPDATE_PERMISSION = "ohos.permission.RECEIVE_UPDATE_MESSAGE";
}

ParamCommonEvent::ParamCommonEvent()
{
    HILOG_INFO("call");
    handleEventFunc_[CFG_UPDATED_ACTION] = &ParamCommonEvent::HandleParamUpdate;
    for (auto it = handleEventFunc_.begin(); it != handleEventFunc_.end(); ++it) {
        HILOG_INFO("Add event: %{public}s", it->first.c_str());
        eventHandles_.emplace(it->first, std::bind(it->second, this, std::placeholders::_1));
    }
}

ParamCommonEvent::~ParamCommonEvent()
{
    UnSubscriberEvent();
}

void ParamCommonEvent::SubscriberEvent()
{
    HILOG_INFO("call");
    if (subscriber_) {
        HILOG_WARN("Common Event is already subscribered!");
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    for (auto &event : handleEventFunc_) {
        HILOG_INFO("Add event: %{public}s", event.first.c_str());
        matchingSkills.AddEvent(event.first);
    }
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetPermission(RECEIVE_UPDATE_PERMISSION);
    subscriber_ = std::make_shared<ParamCommonEventSubscriber>(subscribeInfo, *this);

    int32_t retry = RETRY_SUBSCRIBER;
    do {
        bool subscribeResult = EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
        if (subscribeResult) {
            HILOG_INFO("SubscriberEvent success.");
            return;
        } else {
            HILOG_ERROR("SubscriberEvent failed, retry %{public}d", retry);
            retry--;
            sleep(1);
        }
    } while (retry);
    HILOG_ERROR("SubscriberEvent failed.");
}

void ParamCommonEvent::UnSubscriberEvent()
{
    HILOG_INFO("call");
    eventHandles_.clear();
    handleEventFunc_.clear();
    if (subscriber_) {
        EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
        subscriber_ = nullptr;
    }
    HILOG_INFO("UnSubscriberEvent end.");
}

void ParamCommonEvent::OnReceiveEvent(const AAFwk::Want &want)
{
    std::string action = want.GetAction();
    auto it = eventHandles_.find(action);
    if (it == eventHandles_.end()) {
        HILOG_WARN("Ignore event: %{public}s", action.c_str());
        return;
    }
    it->second(want);
}


void ParamCommonEvent::HandleParamUpdate(const AAFwk::Want &want) const
{
    std::string action = want.GetAction();
    std::string type = want.GetStringParam(EVENT_INFO_TYPE);
    std::string subtype = want.GetStringParam(EVENT_INFO_SUBTYPE);
    HILOG_INFO("param update event: %{public}s, %{public}s, %{public}s", action.c_str(),
        type.c_str(), subtype.c_str());
    if (action != CFG_UPDATED_ACTION || type != PARAM_CONFIG_TYPE) {
        HILOG_WARN("Ignore type: %{public}s", type.c_str());
        return;
    }
    FormEventReport::SendFormFailedEvent(FormEventName::FORM_DUE_CONTROL, 0, "", "", 0, 0);
    ParamManager::GetInstance().InitParam();
}
}  // namespace AppExecFwk
}  // namespace OHOS