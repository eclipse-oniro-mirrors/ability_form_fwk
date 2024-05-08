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

#include "form_event_report.h"

#include <map>

#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// event params
constexpr const char *EVENT_KEY_FORM_ID = "FORM_ID";
constexpr const char *EVENT_KEY_BUNDLE_NAME = "BUNDLE_NAME";
constexpr const char *EVENT_KEY_MODULE_NAME = "MODULE_NAME";
constexpr const char *EVENT_KEY_ABILITY_NAME = "ABILITY_NAME";
constexpr const char *EVENT_KEY_HOST_BUNDLE_NAME = "HOST_BUNDLE_NAME";
constexpr const char *EVENT_KEY_FORM_APP_PID = "FORM_APP_PID";
constexpr const char *EVENT_KEY_TIMESTAMP = "TIMESTAMP";
const std::map<FormEventName, std::string> EVENT_NAME_MAP = {
    std::map<FormEventName, std::string>::value_type(FormEventName::ADD_FORM, "ADD_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::REQUEST_FORM, "REQUEST_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::REQUEST_FORM, "REQUEST_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::DELETE_FORM, "DELETE_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::CASTTEMP_FORM, "CASTTEMP_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::ACQUIREFORMSTATE_FORM, "ACQUIREFORMSTATE_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::MESSAGE_EVENT_FORM, "MESSAGE_EVENT_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::ROUTE_EVENT_FORM, "ROUTE_EVENT_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::BACKGROUND_EVENT_FORM, "BACKGROUND_EVENT_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::RELEASE_FORM, "RELEASE_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::DELETE_INVALID_FORM, "DELETE_INVALID_FORM"),
    std::map<FormEventName, std::string>::value_type(
        FormEventName::SET_NEXT_REFRESH_TIME_FORM, "SET_NEXT_REFRESH_TIME_FORM"),
    std::map<FormEventName, std::string>::value_type(FormEventName::FORM_RENDER_BLOCK, "FORM_RENDER_BLOCK"),
    std::map<FormEventName, std::string>::value_type(FormEventName::UNBIND_FORM_APP, "UNBIND_FORM_APP"),
};
}

void FormEventReport::SendFormEvent(const FormEventName &eventName, HiSysEventType type,
    const FormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }

    switch (eventName) {
        case FormEventName::DELETE_INVALID_FORM:
            HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type);
            break;
        case FormEventName::ACQUIREFORMSTATE_FORM:
            HiSysEventWrite(
                HiSysEvent::Domain::FORM_MANAGER,
                name,
                type,
                EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
                EVENT_KEY_MODULE_NAME, eventInfo.moduleName,
                EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
            break;
        case FormEventName::MESSAGE_EVENT_FORM:
            HiSysEventWrite(
                HiSysEvent::Domain::FORM_MANAGER,
                name,
                type,
                EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
                EVENT_KEY_MODULE_NAME, eventInfo.moduleName,
                EVENT_KEY_ABILITY_NAME, eventInfo.abilityName,
                EVENT_KEY_HOST_BUNDLE_NAME, eventInfo.hostBundleName);
            break;
        case FormEventName::ADD_FORM:
        case FormEventName::ROUTE_EVENT_FORM:
            HiSysEventWrite(
                HiSysEvent::Domain::FORM_MANAGER, name, type,
                EVENT_KEY_FORM_ID, eventInfo.formId,
                EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
                EVENT_KEY_MODULE_NAME, eventInfo.moduleName,
                EVENT_KEY_ABILITY_NAME, eventInfo.abilityName,
                EVENT_KEY_HOST_BUNDLE_NAME, eventInfo.hostBundleName);
            break;
        default:
            break;
    }
}

void FormEventReport::SendSecondFormEvent(const FormEventName &eventName, HiSysEventType type,
    const FormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }

    switch (eventName) {
        case FormEventName::REQUEST_FORM:
        case FormEventName::BACKGROUND_EVENT_FORM:
            HiSysEventWrite(
                HiSysEvent::Domain::FORM_MANAGER,
                name,
                type,
                EVENT_KEY_FORM_ID, eventInfo.formId,
                EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
                EVENT_KEY_MODULE_NAME, eventInfo.moduleName,
                EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
            break;
        case FormEventName::DELETE_FORM:
            HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type,
                EVENT_KEY_FORM_ID, eventInfo.formId,
                EVENT_KEY_HOST_BUNDLE_NAME, eventInfo.hostBundleName);
            break;
        case FormEventName::CASTTEMP_FORM:
        case FormEventName::RELEASE_FORM:
        case FormEventName::SET_NEXT_REFRESH_TIME_FORM:
            HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type, EVENT_KEY_FORM_ID, eventInfo.formId);
            break;
        case FormEventName::FORM_RENDER_BLOCK:
            HiSysEventWrite(
                HiSysEvent::Domain::FORM_MANAGER,
                name,
                type,
                EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
            break;
        default:
            break;
    }
}

void FormEventReport::SendThirdFormEvent(const FormEventName &eventName, HiSysEventType type,
    const FormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }

    switch (eventName) {
        case FormEventName::UNBIND_FORM_APP:
            HiSysEventWrite(
                HiSysEvent::Domain::FORM_MANAGER,
                name,
                type,
                EVENT_KEY_TIMESTAMP, eventInfo.timeStamp,
                EVENT_KEY_FORM_ID, eventInfo.formId,
                EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
                EVENT_KEY_FORM_APP_PID, eventInfo.formAppPid);
            break;
        default:
            break;
    }
}

std::string FormEventReport::ConvertEventName(const FormEventName &eventName)
{
    auto it = EVENT_NAME_MAP.find(eventName);
    if (it != EVENT_NAME_MAP.end()) {
        return it->second;
    }
    return "INVALIDEVENTNAME";
}
} // namespace AppExecFwk
} // namespace OHOS
