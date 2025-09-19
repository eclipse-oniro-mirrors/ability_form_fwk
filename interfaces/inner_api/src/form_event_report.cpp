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

#include "form_file_util.h"
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
constexpr const char *EVENT_KEY_ERROR_NAME = "ERROR_NAME";
constexpr const char *EVENT_KEY_ERROR_TYPE = "ERROR_TYPE";
constexpr const char *EVENT_KEY_ERROR_CODE = "ERROR_CODE";
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
constexpr const char *EVENT_KEY_DISABLE_FORM_REFRESH_TIMES = "DISABLE_REFRESH_TIMES";
constexpr const char *EVENT_KEY_CLIENT_BUNDLE_NAME = "CLIENT_BUNDLE_NAME";
constexpr const char *EVENT_KEY_FORM_BUNDLE_NAME = "FORM_BUNDLE_NAME";
constexpr const char *EVENT_KEY_FORM_APP_PID = "FORM_APP_PID";
constexpr const char *EVENT_KEY_TIMESTAMP = "TIMESTAMP";
constexpr const char *EVENT_KEY_RENDERING_MODE = "RENDERING_MODE";
constexpr const char *EVENT_KEY_CONDITION_TYPE = "CONDITION_TYPE";
constexpr const char *EVENT_KEY_BUNDLE_FORMNAME = "BUNDLE_FORMNAME";
constexpr const char *EVENT_KEY_WITH_SNAPSHOT = "WITH_SNAPSHOT";
constexpr const char *EVENT_KEY_DISTRIBUTED_FORM = "DISTRIBUTED_FORM";
constexpr const char *INVALIDEVENTNAME = "INVALIDEVENTNAME";
constexpr const char *FORM_ERROR = "FORM_ERROR";
constexpr const char *FORM_STORAGE_DIR_PATH = "/data/service/el1/public/database/form_storage";
constexpr const char *EVENT_KEY_FORM_COUNT = "FORM_COUNT";
constexpr const char *EVENT_KEY_IS_LOW_MEMORY = "IS_LOW_MEMORY";
constexpr const char *EVENT_KEY_OCCURRENCE_TIME = "OCCURRENCE_TIME";
constexpr const char *EVENT_KEY_STATUS = "STATUS";
constexpr const char *FORM_RENDER_SERVICE_STATUS_ALTER = "FORM_RENDER_SERVICE_STATUS_ALTER";
const std::map<FormEventName, std::string> EVENT_NAME_MAP = {
    {FormEventName::ADD_FORM, "ADD_FORM"},
    {FormEventName::REQUEST_FORM, "REQUEST_FORM"},
    {FormEventName::DELETE_FORM, "DELETE_FORM"},
    {FormEventName::CASTTEMP_FORM, "CASTTEMP_FORM"},
    {FormEventName::ACQUIREFORMSTATE_FORM, "ACQUIREFORMSTATE_FORM"},
    {FormEventName::MESSAGE_EVENT_FORM, "MESSAGE_EVENT_FORM"},
    {FormEventName::ROUTE_EVENT_FORM, "ROUTE_EVENT_FORM"},
    {FormEventName::BACKGROUND_EVENT_FORM, "BACKGROUND_EVENT_FORM"},
    {FormEventName::RELEASE_FORM, "RELEASE_FORM"},
    {FormEventName::DELETE_INVALID_FORM, "DELETE_INVALID_FORM"},
    {FormEventName::SET_NEXT_REFRESH_TIME_FORM, "SET_NEXT_REFRESH_TIME_FORM"},
    {FormEventName::FORM_RENDER_BLOCK, "FORM_RENDER_BLOCK"},
    {FormEventName::INIT_FMS_FAILED, "INIT_FMS_FAILED"},
    {FormEventName::CALLEN_DB_FAILED, "CALLEN_DB_FAILED"},
    {FormEventName::ADD_FORM_FAILED, "ADD_FORM_FAILED"},
    {FormEventName::FIRST_ADD_FORM_DURATION, "FIRST_ADD_FORM_DURATION"},
    {FormEventName::FIRST_UPDATE_FORM_DURATION, "FIRST_UPDATE_FORM_DURATION"},
    {FormEventName::UPDATE_FORM_REFRESH_TIMES, "UPDATE_FORM_REFRESH_TIMES"},
    {FormEventName::PROXY_UPDATE_FORM, "PROXY_UPDATE_FORM"},
    {FormEventName::INVALID_PUBLISH_FORM_TO_HOST, "INVALID_PUBLISH_FORM_TO_HOST"},
    {FormEventName::UNBIND_FORM_APP, "UNBIND_FORM_APP"},
    {FormEventName::CONDITION_UPDATE_FORM, "CONDITION_UPDATE_FORM"},
    {FormEventName::LOAD_STAGE_FORM_CONFIG_INFO, "LOAD_STAGE_FORM_CONFIG_INFO"},
    {FormEventName::DELETE_FORM_FAILED, "DELETE_FORM_FAILED"},
    {FormEventName::UPDATE_FORM_FAILED, "UPDATE_FORM_FAILED"},
    {FormEventName::RECYCLE_RECOVER_FORM_FAILED, "RECYCLE_RECOVER_FORM_FAILED"},
    {FormEventName::REQUEST_PUBLIC_FORM, "REQUEST_PUBLIC_FORM"},
    {FormEventName::CONNECT_FORM_ABILITY_FAILED, "CONNECT_FORM_ABILITY_FAILED"},
    {FormEventName::FORM_NODE_ERROR, "FORM_NODE_ERROR"},
    {FormEventName::RELOAD_FORM_FAILED, "RELOAD_FORM_FAILED"},
    {FormEventName::FORM_STATUS_ERROR, "FORM_STATUS_ERROR"},
    {FormEventName::FORM_EVENT_QUEUE_OVER_LIMIT, "FORM_EVENT_QUEUE_OVER_LIMIT"},
};
}

void FormEventReport::SendFormEvent(const FormEventName &eventName, HiSysEventType type,
    const FormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == INVALIDEVENTNAME) {
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
            HiSysEventWrite(
                HiSysEvent::Domain::FORM_MANAGER,
                name,
                type,
                EVENT_KEY_DISTRIBUTED_FORM, eventInfo.distributedForm,
                EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(eventInfo.formDimension));
            break;
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
    if (name == INVALIDEVENTNAME) {
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
                EVENT_KEY_HOST_BUNDLE_NAME, eventInfo.hostBundleName,
                EVENT_KEY_DISTRIBUTED_FORM, eventInfo.distributedForm,
                EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(eventInfo.formDimension));
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
    if (name == INVALIDEVENTNAME) {
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
    if (name == INVALIDEVENTNAME) {
        HILOG_ERROR("invalid eventName");
        return;
    }
    switch (eventName) {
        case FormEventName::INIT_FMS_FAILED:
        case FormEventName::CALLEN_DB_FAILED:
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
    if (name == INVALIDEVENTNAME) {
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
            EVENT_KEY_OFFLOAD_RECOVER_REFRESH_TIMES, static_cast<int32_t>(eventInfo.offloadRecoverRefreshTimes),
            EVENT_KEY_DISABLE_FORM_REFRESH_TIMES, static_cast<int32_t>(eventInfo.disableFormRefreshTimes));
    }
}
void FormEventReport::SendFourthFormEvent(const FormEventName &eventName, HiSysEventType type,
    const NewFormEventInfo &eventInfo, const Want &want)
{
    std::string name = ConvertEventName(eventName);
    if (name == INVALIDEVENTNAME) {
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
                EVENT_KEY_ABILITY_NAME, want.GetStringParam(Constants::PARAM_ABILITY_NAME_KEY),
                EVENT_KEY_DISTRIBUTED_FORM, eventInfo.distributedForm);
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
    if (name == INVALIDEVENTNAME) {
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
    if (name == INVALIDEVENTNAME) {
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
    if (name == INVALIDEVENTNAME) {
        HILOG_ERROR("invalid eventName");
        return;
    }
    if (eventName == FormEventName::CONDITION_UPDATE_FORM) {
        HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER, name, type,
            EVENT_KEY_CONDITION_TYPE, static_cast<int32_t>(eventInfo.conditionType),
            EVENT_KEY_BUNDLE_FORMNAME, eventInfo.bundleAndFormName,
            EVENT_KEY_FORM_ID, eventInfo.formId,
            EVENT_KEY_DISTRIBUTED_FORM, eventInfo.distributedForm,
            EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(eventInfo.formDimension),
            EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName,
            EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
    }
}

void FormEventReport::SendLoadStageFormConfigInfoEvent(const FormEventName &eventName, HiSysEventType type,
    const NewFormEventInfo &eventInfo)
{
    std::string name = ConvertEventName(eventName);
    if (name == INVALIDEVENTNAME) {
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
    FormFileUtil::GetDirFiles(FORM_STORAGE_DIR_PATH, files);
    if (files.empty()) {
        HILOG_ERROR("files is empty, not report disk use info");
        return;
    }
    auto totalSize = FormFileUtil::GetFilesSize(files, filesSize);
    files.push_back(FORM_STORAGE_DIR_PATH);
    filesSize.emplace_back(totalSize);
    HiSysEventWrite(HiSysEvent::Domain::FILEMANAGEMENT, "USER_DATA_SIZE",
        HiSysEvent::EventType::STATISTIC,
        "COMPONENT_NAME", "form_fwk",
        "FILE_OR_FOLDER_PATH", files,
        "FILE_OR_FOLDER_SIZE", filesSize);
}

void FormEventReport::SendRequestPublicFormEvent(const std::string &callerBundleName, const std::string &formName,
    bool withSnapshot)
{
    HiSysEventWrite(
        HiSysEvent::Domain::FORM_MANAGER,
        "REQUEST_PUBLIC_FORM",
        HiSysEventType::STATISTIC,
        EVENT_KEY_BUNDLE_NAME, callerBundleName,
        EVENT_KEY_FORM_NAME, formName,
        EVENT_KEY_WITH_SNAPSHOT, withSnapshot);
}

void FormEventReport::SendFormFailedEvent(const FormEventName &eventName, int64_t formId, const std::string &bundleName,
    const std::string &formName, int32_t errorType, int32_t errorCode)
{
    std::string name = ConvertEventName(eventName);
    if (name == INVALIDEVENTNAME) {
        HILOG_ERROR("invalid eventName");
        return;
    }
    switch (eventName) {
        case FormEventName::ADD_FORM_FAILED:
        case FormEventName::DELETE_FORM_FAILED:
        case FormEventName::UPDATE_FORM_FAILED:
        case FormEventName::RECYCLE_RECOVER_FORM_FAILED:
        case FormEventName::CONNECT_FORM_ABILITY_FAILED:
        case FormEventName::FORM_NODE_ERROR:
        case FormEventName::RELOAD_FORM_FAILED:
        case FormEventName::FORM_STATUS_ERROR:
        case FormEventName::FORM_EVENT_QUEUE_OVER_LIMIT:
            HiSysEventWrite(
                HiSysEvent::Domain::FORM_MANAGER, FORM_ERROR,
                HiSysEventType::FAULT,
                EVENT_KEY_FORM_ID, formId,
                EVENT_KEY_BUNDLE_NAME, bundleName,
                EVENT_KEY_FORM_NAME, formName,
                EVENT_KEY_ERROR_NAME, name,
                EVENT_KEY_ERROR_TYPE, errorType,
                EVENT_KEY_ERROR_CODE, errorCode);
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
    return INVALIDEVENTNAME;
}

void FormEventReport::SendFRSStatusEvent(
    const std::vector<bool> &isLowMemoryList,
    const std::vector<uint8_t> &statusList,
    const std::vector<int32_t> &formCountList,
    const std::vector<int64_t> &occurrenceTimeList)
{
    HILOG_INFO("call");
    HiSysEventWrite(
        HiSysEvent::Domain::FORM_MANAGER,
        FORM_RENDER_SERVICE_STATUS_ALTER,
        HiSysEventType::STATISTIC,
        EVENT_KEY_OCCURRENCE_TIME, occurrenceTimeList,
        EVENT_KEY_FORM_COUNT, formCountList,
        EVENT_KEY_IS_LOW_MEMORY, isLowMemoryList,
        EVENT_KEY_STATUS, statusList);
}
} // namespace AppExecFwk
} // namespace OHOS
