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

#include "common/event/form_event_report.h"
#include "common/event/form_event_util.h"

#include <map>

#include "fms_log_wrapper.h"
#include "form_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
// event params
constexpr const char *EVENT_KEY_FORM_ID = "FORM_ID";
constexpr const char *EVENT_KEY_BUNDLE_NAME = "BUNDLE_NAME";
constexpr const char *EVENT_KEY_MODULE_NAME = "MODULE_NAME";
constexpr const char *EVENT_KEY_ABILITY_NAME = "ABILITY_NAME";
constexpr const char *EVENT_KEY_HOST_BUNDLE_NAME = "HOST_BUNDLE_NAME";
constexpr const char *EVENT_KEY_ERROR_TYPE = "ERROR_TYPE";
constexpr const char *EVENT_KEY_SESSION_ID = "SESSION_ID";
constexpr const char *EVENT_KEY_BIND_DURATION = "BIND_DURATION";
constexpr const char *EVENT_KEY_GET_DURATION = "GET_DURATION";
constexpr const char *EVENT_KEY_FORM_NAME = "FORM_NAME";
constexpr const char *EVENT_KEY_FORM_DIMENSION = "FORM_DIMENSION";
constexpr const char *EVENT_KEY_ACQUIRE_DURATION = "ACQUIRE_DURATION";
constexpr const char *EVENT_KEY_DURATION = "DURATION";
constexpr const char *EVENT_KEY_DURATION_TYPE = "DURATION_TYPE";
constexpr const char *EVENT_KEY_DAILY_REFRESH_TIMES = "DAILY_REFRESH_TIMES";
constexpr const char *EVENT_KEY_INVISIBLE_REFRESH_TIMES = "INVISIBLE_REFRESH_TIMES";
constexpr const char *EVENT_KEY_HF_REFRESH_BLOCK_TIMES = "HF_REFRESH_BLOCK_TIMES";
constexpr const char *EVENT_KEY_INVISIBLE_REFRESH_BLOCK_TIMES = "INVISIBLE_REFRESH_BLOCK_TIMES";
constexpr const char *EVENT_KEY_HILOG_REFRESH_BLOCK_TIMES = "HILOG_REFRESH_BLOCK_TIMES";
constexpr const char *EVENT_KEY_ACTIVE_RECOVER_REFRESH_TIMES = "ACTIVE_RECOVER_REFRESH_TIMES";
constexpr const char *EVENT_KEY_PASSIVER_RECOVER_REFRESH_TIMES = "PASSIVER_RECOVER_REFRESH_TIMES";
constexpr const char *EVENT_KEY_HF_RECOVER_REFRESH_TIMES = "HF_RECOVER_REFRESH_TIMES";
constexpr const char *EVENT_KEY_OFFLOAD_RECOVER_REFRESH_TIMES = "OFFLOAD_RECOVER_REFRESH_TIMER";
constexpr const char *EVENT_KEY_CLIENT_BUNDLE_NAME = "CLIENT_BUNDLE_NAME";
constexpr const char *EVENT_KEY_FORM_BUNDLE_NAME = "FORM_BUNDLE_NAME";
constexpr const char *EVENT_KEY_FORM_APP_PID = "FORM_APP_PID";
constexpr const char *EVENT_KEY_TIMESTAMP = "TIMESTAMP";
constexpr const char *EVENT_KEY_RENDERING_MODE = "RENDERING_MODE";
constexpr const char *EVENT_KEY_CONDITION_TYPE = "CONDITION_TYPE";
constexpr const char *EVENT_KEY_BUNDLE_FORMNAME = "BUNDLE_FORMNAME";
constexpr const char *FORM_STORAGE_DIR_PATH = "/data/service/el1/public/database/form_storage";
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
    std::map<FormEventName, std::string>::value_type(FormEventName::INIT_FMS_FAILED, "INIT_FMS_FAILED"),
    std::map<FormEventName, std::string>::value_type(FormEventName::CALLEN_DB_FAILED, "CALLEN_DB_FAILED"),
    std::map<FormEventName, std::string>::value_type(FormEventName::ADD_FORM_FAILED, "ADD_FORM_FAILED"),
    std::map<FormEventName, std::string>::value_type(
        FormEventName::FIRST_ADD_FORM_DURATION, "FIRST_ADD_FORM_DURATION"),
    std::map<FormEventName, std::string>::value_type(
        FormEventName::FIRST_UPDATE_FORM_DURATION, "FIRST_UPDATE_FORM_DURATION"),
    std::map<FormEventName, std::string>::value_type(
        FormEventName::UPDATE_FORM_REFRESH_TIMES, "UPDATE_FORM_REFRESH_TIMES"),
    std::map<FormEventName, std::string>::value_type(FormEventName::PROXY_UPDATE_FORM, "PROXY_UPDATE_FORM"),
    std::map<FormEventName, std::string>::value_type(
        FormEventName::INVALID_PUBLISH_FORM_TO_HOST, "INVALID_PUBLISH_FORM_TO_HOST"),
    std::map<FormEventName, std::string>::value_type(FormEventName::UNBIND_FORM_APP, "UNBIND_FORM_APP"),
    std::map<FormEventName, std::string>::value_type(
        FormEventName::CONDITION_UPDATE_FORM, "CONDITION_UPDATE_FORM"),
    std::map<FormEventName, std::string>::value_type(
        FormEventName::LOAD_STAGE_FORM_CONFIG_INFO, "LOAD_STAGE_FORM_CONFIG_INFO"),
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

void FormEventReport::SendFormFailedEvent(const FormEventName &eventName, HiSysEventType type, int64_t errorType)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }
    switch (eventName) {
        case FormEventName::INIT_FMS_FAILED:
        case FormEventName::CALLEN_DB_FAILED:
        case FormEventName::ADD_FORM_FAILED:
            HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type, EVENT_KEY_ERROR_TYPE, errorType);
            break;
        default:
            break;
    }
}

void FormEventReport::SendFormRefreshCountEvent(const FormEventName &eventName, HiSysEventType type,
    const NewFormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }
    if (eventName == FormEventName::UPDATE_FORM_REFRESH_TIMES) {
        HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type,
            EVENT_KEY_FORM_ID, eventInfo.formId,
            EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
            EVENT_KEY_MODULE_NAME, eventInfo.moduleName,
            EVENT_KEY_FORM_NAME, eventInfo.formName,
            EVENT_KEY_DAILY_REFRESH_TIMES, static_cast<int32_t>(eventInfo.dailyRefreshTimes),
            EVENT_KEY_INVISIBLE_REFRESH_TIMES, static_cast<int32_t>(eventInfo.invisibleRefreshTimes),
            EVENT_KEY_HF_REFRESH_BLOCK_TIMES, static_cast<int32_t>(eventInfo.hfRefreshBlockTimes),
            EVENT_KEY_INVISIBLE_REFRESH_BLOCK_TIMES, static_cast<int32_t>(eventInfo.invisibleRefreshBlockTimes),
            EVENT_KEY_HILOG_REFRESH_BLOCK_TIMES, static_cast<int32_t>(eventInfo.highLoadRefreshBlockTimes),
            EVENT_KEY_ACTIVE_RECOVER_REFRESH_TIMES, static_cast<int32_t>(eventInfo.activeRecoverRefreshTimes),
            EVENT_KEY_PASSIVER_RECOVER_REFRESH_TIMES, static_cast<int32_t>(eventInfo.passiveRecoverRefreshTimes),
            EVENT_KEY_HF_RECOVER_REFRESH_TIMES, static_cast<int32_t>(eventInfo.hfRecoverRefreshTimes),
            EVENT_KEY_OFFLOAD_RECOVER_REFRESH_TIMES, static_cast<int32_t>(eventInfo.offloadRecoverRefreshTimes));
    }
}
void FormEventReport::SendFourthFormEvent(const FormEventName &eventName, HiSysEventType type,
    const NewFormEventInfo &eventInfo, const Want &want)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }
    switch (eventName) {
        case FormEventName::PROXY_UPDATE_FORM:
            HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type,
                EVENT_KEY_FORM_ID, eventInfo.formId,
                EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
                EVENT_KEY_MODULE_NAME, want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY),
                EVENT_KEY_FORM_NAME, want.GetStringParam(Constants::PARAM_FORM_NAME_KEY),
                EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(want.
                    GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0)),
                EVENT_KEY_ABILITY_NAME, want.GetStringParam(Constants::PARAM_ABILITY_NAME_KEY));
            break;
        case FormEventName::INVALID_PUBLISH_FORM_TO_HOST:
            HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type,
                EVENT_KEY_CLIENT_BUNDLE_NAME, want.GetStringParam(AppExecFwk::Constants::PARAM_CALLER_BUNDLE_NAME_KEY),
                EVENT_KEY_HOST_BUNDLE_NAME, want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_HOST_BUNDLENAME_KEY),
                EVENT_KEY_FORM_BUNDLE_NAME, want.GetElement().GetBundleName(),
                EVENT_KEY_MODULE_NAME, want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY),
                EVENT_KEY_FORM_NAME, want.GetStringParam(Constants::PARAM_FORM_NAME_KEY),
                EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(want.
                    GetIntParam(AppExecFwk::Constants::PARAM_FORM_DIMENSION_KEY, 0)),
                EVENT_KEY_ABILITY_NAME, want.GetElement().GetAbilityName());
            break;
        default:
            break;
    }
}

void FormEventReport::SendFirstAddFormEvent(const FormEventName &eventName, HiSysEventType type,
    const NewFormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }
    if (eventName == FormEventName::FIRST_ADD_FORM_DURATION) {
        HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type,
            EVENT_KEY_SESSION_ID, static_cast<int64_t>(eventInfo.sessionId),
            EVENT_KEY_FORM_ID, eventInfo.formId,
            EVENT_KEY_BIND_DURATION, static_cast<float>(eventInfo.bindDuration),
            EVENT_KEY_GET_DURATION, static_cast<float>(eventInfo.getDuration),
            EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
            EVENT_KEY_MODULE_NAME, eventInfo.moduleName,
            EVENT_KEY_ABILITY_NAME, eventInfo.abilityName,
            EVENT_KEY_FORM_NAME, eventInfo.formName,
            EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(eventInfo.formDimension),
            EVENT_KEY_ACQUIRE_DURATION, static_cast<float>(eventInfo.acquireDuration));
    }
}

void FormEventReport::SendFirstUpdateFormEvent(const FormEventName &eventName, HiSysEventType type,
    const NewFormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }
    if (eventName == FormEventName::FIRST_UPDATE_FORM_DURATION) {
        HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type,
            EVENT_KEY_SESSION_ID, static_cast<int64_t>(eventInfo.sessionId),
            EVENT_KEY_FORM_ID, eventInfo.formId,
            EVENT_KEY_DURATION, static_cast<float>(eventInfo.duration),
            EVENT_KEY_DURATION_TYPE, eventInfo.durationType);
    }
}

void FormEventReport::SendConditonUpdateFormEvent(const FormEventName &eventName, HiSysEventType type,
    const NewFormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }
    if (eventName == FormEventName::CONDITION_UPDATE_FORM) {
        HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type,
            EVENT_KEY_CONDITION_TYPE, static_cast<int32_t>(eventInfo.conditionType),
            EVENT_KEY_BUNDLE_FORMNAME, eventInfo.bundleAndFormName);
    }
}

void FormEventReport::SendLoadStageFormConfigInfoEvent(const FormEventName &eventName, HiSysEventType type,
    const NewFormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == "INVALIDEVENTNAME") {
        HILOG_ERROR("invalid eventName");
        return;
    }
    if (eventName == FormEventName::LOAD_STAGE_FORM_CONFIG_INFO) {
        HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type,
            EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
            EVENT_KEY_FORM_NAME, eventInfo.formName,
            EVENT_KEY_RENDERING_MODE, static_cast<int32_t>(eventInfo.renderingMode));
    }
}

void FormEventReport::SendDiskUseEvent()
{
    std::vector<std::string> files;
    std::vector<std::uint64_t> filesSize;
    FormEventUtil::GetDirFiles(FORM_STORAGE_DIR_PATH, files);
    if (files.empty()) {
        HILOG_ERROR("files is empty, not report disk use info");
        return;
    }
    FormEventUtil::GetFilesSize(files, filesSize);
    files.push_back(FORM_STORAGE_DIR_PATH);
    HiSysEventWrite(HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiSysEvent::EventType::STATISTIC,
        "COMPONENT_NAME", "form_fwk",
        "FILE_OR_FOLDER_PATH", files,
        "FILE_OR_FOLDER_SIZE", filesSize);
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
