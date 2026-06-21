/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include <unordered_map>

#include "form_file_util.h"
#include "form_hisysevent_wrapper.h"
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
constexpr const char *EVENT_KEY_URI = "URI";
constexpr const char *EVENT_KEY_ERROR_NAME = "ERROR_NAME";
constexpr const char *EVENT_KEY_ERROR_TYPE = "ERROR_TYPE";
constexpr const char *EVENT_KEY_ERROR_CODE = "ERROR_CODE";
constexpr const char *EVENT_KEY_SESSION_ID = "SESSION_ID";
constexpr const char *EVENT_KEY_BIND_DURATION = "BIND_DURATION";
constexpr const char *EVENT_KEY_GET_DURATION = "GET_DURATION";
constexpr const char *EVENT_KEY_FORM_NAME = "FORM_NAME";
constexpr const char *EVENT_KEY_FORM_DIMENSION = "FORM_DIMENSION";
constexpr const char *EVENT_KEY_FORM_LOCATION = "FORM_LOCATION";
constexpr const char *EVENT_KEY_NONTRANSPARENCY_RATE = "NONTRANSPARENCY_RATE";
constexpr const char *EVENT_KEY_APP_VERSION = "APP_VERSION";
constexpr const char *EVENT_KEY_ACQUIRE_DURATION = "ACQUIRE_DURATION";
constexpr const char *EVENT_KEY_DURATION = "DURATION";
constexpr const char *EVENT_KEY_DURATION_TYPE = "DURATION_TYPE";
constexpr const char *EVENT_KEY_DAILY_REFRESH_TIMES = "DAILY_REFRESH_TIMES";
constexpr const char *EVENT_KEY_ACTUAL_PROXY_REFRESH_TIMES = "ACTUAL_PROXY_REFRESH_TIMES";
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
constexpr const char *EVENT_KEY_IS_DISTRIBUTED_FORM = "IS_DISTRIBUTED_FORM";
constexpr const char *FORM_ERROR = "FORM_ERROR";
constexpr const char *EVENT_KEY_FUNC_TYPE = "FUNC_TYPE";
constexpr const char *INVALIDEVENTNAME = "INVALIDEVENTNAME";
constexpr const char *FORM_STORAGE_DIR_PATH = "/data/service/el1/public/database/form_storage";
constexpr const char *EVENT_KEY_FORM_COUNT = "FORM_COUNT";
constexpr const char *EVENT_KEY_IS_LOW_MEMORY = "IS_LOW_MEMORY";
constexpr const char *EVENT_KEY_OCCURRENCE_TIME = "OCCURRENCE_TIME";
constexpr const char *EVENT_KEY_STATUS = "STATUS";
constexpr const char *FORM_RENDER_SERVICE_STATUS_ALTER = "FORM_RENDER_SERVICE_STATUS_ALTER";
constexpr const char *ABNORMAL_FORM = "ABNORMAL_FORM";
static const std::unordered_map<FormEventName, const char*> EVENT_NAME_MAP = {
    {FormEventName::ADD_FORM, "ADD_FORM"},
    {FormEventName::ADD_DISTRIBUTED_FORM, "ADD_DISTRIBUTED_FORM"},
    {FormEventName::REQUEST_FORM, "REQUEST_FORM"},
    {FormEventName::DELETE_FORM, "DELETE_FORM"},
    {FormEventName::DELETE_DISTRIBUTED_FORM, "DELETE_DISTRIBUTED_FORM"},
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
    {FormEventName::FORM_DUE_CONTROL, "FORM_DUE_CONTROL"},
    {FormEventName::FORM_EXCEEDS_DISTRIBUTION, "FORM_EXCEEDS_DISTRIBUTION"},
};
}

void FormEventReport::SendDeleteInvalidFormEvent(const std::string &name, HiSysEventType type)
{
    FormHiSysEventWrapper::WriteEvent("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
}

void FormEventReport::SendAcquireFormStateEvent(const std::string &name, HiSysEventType type,
    const FormEventInfo &eventInfo)
{
    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
    builder.InsertParam(EVENT_KEY_MODULE_NAME, eventInfo.moduleName);
    builder.InsertParam(EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
    builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
}

void FormEventReport::SendMessageEventFormEvent(const std::string &name, HiSysEventType type,
    const FormEventInfo &eventInfo)
{
    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
    builder.InsertParam(EVENT_KEY_MODULE_NAME, eventInfo.moduleName);
    builder.InsertParam(EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
    builder.InsertParam(EVENT_KEY_HOST_BUNDLE_NAME, eventInfo.hostBundleName);
    builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
}

void FormEventReport::SendAddFormEventInner(const std::string &name, HiSysEventType type,
    const FormEventInfo &eventInfo)
{
    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
    builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
    builder.InsertParam(EVENT_KEY_MODULE_NAME, eventInfo.moduleName);
    builder.InsertParam(EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
    builder.InsertParam(EVENT_KEY_HOST_BUNDLE_NAME, eventInfo.hostBundleName);
    builder.InsertParam(EVENT_KEY_IS_DISTRIBUTED_FORM, eventInfo.isDistributedForm);
    builder.InsertParam(EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(eventInfo.formDimension));
    builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
}

void FormEventReport::SendRouteEventFormEvent(const std::string &name, HiSysEventType type,
    const FormEventInfo &eventInfo)
{
    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
    builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
    builder.InsertParam(EVENT_KEY_MODULE_NAME, eventInfo.moduleName);
    builder.InsertParam(EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
    builder.InsertParam(EVENT_KEY_HOST_BUNDLE_NAME, eventInfo.hostBundleName);
    builder.InsertParam(EVENT_KEY_URI, eventInfo.uri);
    builder.InsertParam(EVENT_KEY_FORM_LOCATION, eventInfo.formLocation);
    builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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
            SendDeleteInvalidFormEvent(name, type);
            break;
        case FormEventName::ACQUIREFORMSTATE_FORM:
            SendAcquireFormStateEvent(name, type, eventInfo);
            break;
        case FormEventName::MESSAGE_EVENT_FORM:
            SendMessageEventFormEvent(name, type, eventInfo);
            break;
        case FormEventName::ADD_FORM:
            SendAddFormEventInner(name, type, eventInfo);
            break;
        case FormEventName::ROUTE_EVENT_FORM:
            SendRouteEventFormEvent(name, type, eventInfo);
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

    FormHiSysEventBuilder builder;
    switch (eventName) {
        case FormEventName::REQUEST_FORM:
        case FormEventName::BACKGROUND_EVENT_FORM:
            builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
            builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
            builder.InsertParam(EVENT_KEY_MODULE_NAME, eventInfo.moduleName);
            builder.InsertParam(EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
            builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
            break;
        case FormEventName::DELETE_FORM:
            builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
            builder.InsertParam(EVENT_KEY_HOST_BUNDLE_NAME, eventInfo.hostBundleName);
            builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
            builder.InsertParam(EVENT_KEY_MODULE_NAME, eventInfo.moduleName);
            builder.InsertParam(EVENT_KEY_IS_DISTRIBUTED_FORM, eventInfo.isDistributedForm);
            builder.InsertParam(EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(eventInfo.formDimension));
            builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
            break;
        case FormEventName::CASTTEMP_FORM:
        case FormEventName::RELEASE_FORM:
        case FormEventName::SET_NEXT_REFRESH_TIME_FORM:
            builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
            builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
            break;
        case FormEventName::FORM_RENDER_BLOCK:
            builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
            builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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

    FormHiSysEventBuilder builder;
    switch (eventName) {
        case FormEventName::UNBIND_FORM_APP:
            builder.InsertParam(EVENT_KEY_TIMESTAMP, eventInfo.timeStamp);
            builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
            builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
            builder.InsertParam(EVENT_KEY_FORM_APP_PID, eventInfo.formAppPid);
            builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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
    FormHiSysEventBuilder builder;
    switch (eventName) {
        case FormEventName::INIT_FMS_FAILED:
        case FormEventName::CALLEN_DB_FAILED:
            builder.InsertParam(EVENT_KEY_ERROR_TYPE, errorType);
            builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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
        FormHiSysEventBuilder builder;
        builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
        builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
        builder.InsertParam(EVENT_KEY_MODULE_NAME, eventInfo.moduleName);
        builder.InsertParam(EVENT_KEY_FORM_NAME, eventInfo.formName);
        builder.InsertParam(EVENT_KEY_DAILY_REFRESH_TIMES, static_cast<int32_t>(eventInfo.dailyRefreshTimes));
        builder.InsertParam(EVENT_KEY_INVISIBLE_REFRESH_TIMES, static_cast<int32_t>(eventInfo.invisibleRefreshTimes));
        builder.InsertParam(EVENT_KEY_HF_REFRESH_BLOCK_TIMES, static_cast<int32_t>(eventInfo.hfRefreshBlockTimes));
        builder.InsertParam(EVENT_KEY_INVISIBLE_REFRESH_BLOCK_TIMES,
            static_cast<int32_t>(eventInfo.invisibleRefreshBlockTimes));
        builder.InsertParam(EVENT_KEY_HILOG_REFRESH_BLOCK_TIMES,
            static_cast<int32_t>(eventInfo.highLoadRefreshBlockTimes));
        builder.InsertParam(EVENT_KEY_ACTIVE_RECOVER_REFRESH_TIMES,
            static_cast<int32_t>(eventInfo.activeRecoverRefreshTimes));
        builder.InsertParam(EVENT_KEY_PASSIVER_RECOVER_REFRESH_TIMES,
            static_cast<int32_t>(eventInfo.passiveRecoverRefreshTimes));
        builder.InsertParam(EVENT_KEY_HF_RECOVER_REFRESH_TIMES,
            static_cast<int32_t>(eventInfo.hfRecoverRefreshTimes));
        builder.InsertParam(EVENT_KEY_OFFLOAD_RECOVER_REFRESH_TIMES,
            static_cast<int32_t>(eventInfo.offloadRecoverRefreshTimes));
        builder.InsertParam(EVENT_KEY_DISABLE_FORM_REFRESH_TIMES,
            static_cast<int32_t>(eventInfo.disableFormRefreshTimes));
        builder.InsertParam(EVENT_KEY_IS_DISTRIBUTED_FORM, eventInfo.isDistributedForm);
        builder.InsertParam(EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
        builder.InsertParam(EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(eventInfo.formDimension));
        builder.InsertParam(EVENT_KEY_FORM_LOCATION, static_cast<int8_t>(eventInfo.formLocation));
        builder.InsertParam(EVENT_KEY_ACTUAL_PROXY_REFRESH_TIMES,
            static_cast<int32_t>(eventInfo.actualProxyRefreshTimes));
        builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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
    FormHiSysEventBuilder builder;
    switch (eventName) {
        case FormEventName::PROXY_UPDATE_FORM:
            builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
            builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
            builder.InsertParam(EVENT_KEY_MODULE_NAME, want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY));
            builder.InsertParam(EVENT_KEY_FORM_NAME, want.GetStringParam(Constants::PARAM_FORM_NAME_KEY));
            builder.InsertParam(EVENT_KEY_FORM_DIMENSION,
                static_cast<int64_t>(want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0)));
            builder.InsertParam(EVENT_KEY_ABILITY_NAME, want.GetStringParam(Constants::PARAM_ABILITY_NAME_KEY));
            builder.InsertParam(EVENT_KEY_IS_DISTRIBUTED_FORM, eventInfo.isDistributedForm);
            builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
            break;
        case FormEventName::INVALID_PUBLISH_FORM_TO_HOST:
            builder.InsertParam(EVENT_KEY_CLIENT_BUNDLE_NAME,
                want.GetStringParam(AppExecFwk::Constants::PARAM_CALLER_BUNDLE_NAME_KEY));
            builder.InsertParam(EVENT_KEY_HOST_BUNDLE_NAME,
                want.GetStringParam(AppExecFwk::Constants::PARAM_FORM_HOST_BUNDLENAME_KEY));
            builder.InsertParam(EVENT_KEY_FORM_BUNDLE_NAME, want.GetElement().GetBundleName());
            builder.InsertParam(EVENT_KEY_MODULE_NAME, want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY));
            builder.InsertParam(EVENT_KEY_FORM_NAME, want.GetStringParam(Constants::PARAM_FORM_NAME_KEY));
            builder.InsertParam(EVENT_KEY_FORM_DIMENSION,
                static_cast<int64_t>(want.GetIntParam(AppExecFwk::Constants::PARAM_FORM_DIMENSION_KEY, 0)));
            builder.InsertParam(EVENT_KEY_ABILITY_NAME, want.GetElement().GetAbilityName());
            builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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
        FormHiSysEventBuilder builder;
        builder.InsertParam(EVENT_KEY_SESSION_ID, static_cast<int64_t>(eventInfo.sessionId));
        builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
        builder.InsertParam(EVENT_KEY_BIND_DURATION, static_cast<float>(eventInfo.bindDuration));
        builder.InsertParam(EVENT_KEY_GET_DURATION, static_cast<float>(eventInfo.getDuration));
        builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
        builder.InsertParam(EVENT_KEY_MODULE_NAME, eventInfo.moduleName);
        builder.InsertParam(EVENT_KEY_ABILITY_NAME, eventInfo.abilityName);
        builder.InsertParam(EVENT_KEY_FORM_NAME, eventInfo.formName);
        builder.InsertParam(EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(eventInfo.formDimension));
        builder.InsertParam(EVENT_KEY_ACQUIRE_DURATION, static_cast<float>(eventInfo.acquireDuration));
        builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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
        FormHiSysEventBuilder builder;
        builder.InsertParam(EVENT_KEY_SESSION_ID, static_cast<int64_t>(eventInfo.sessionId));
        builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
        builder.InsertParam(EVENT_KEY_DURATION, static_cast<float>(eventInfo.duration));
        builder.InsertParam(EVENT_KEY_DURATION_TYPE, eventInfo.durationType);
        builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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
        FormHiSysEventBuilder builder;
        builder.InsertParam(EVENT_KEY_CONDITION_TYPE, static_cast<int32_t>(eventInfo.conditionType));
        builder.InsertParam(EVENT_KEY_BUNDLE_FORMNAME, eventInfo.bundleAndFormName);
        builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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
        FormHiSysEventBuilder builder;
        builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
        builder.InsertParam(EVENT_KEY_FORM_NAME, eventInfo.formName);
        builder.InsertParam(EVENT_KEY_RENDERING_MODE, static_cast<int32_t>(eventInfo.renderingMode));
        builder.Write("FORM_MANAGER", name, static_cast<HiSysEventEventType>(type));
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

    FormHiSysEventBuilder builder;
    builder.InsertParam("COMPONENT_NAME", std::string("form_fwk"));
    builder.InsertParam("FILE_OR_FOLDER_PATH", files);
    builder.InsertParam("FILE_OR_FOLDER_SIZE", filesSize);
    builder.Write("FILEMANAGEMENT", "USER_DATA_SIZE", HISYSEVENT_STATISTIC);
}

void FormEventReport::SendRequestPublicFormEvent(const std::string &callerBundleName,
    const std::string &formName, RequestFormType funcType)
{
    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_BUNDLE_NAME, callerBundleName);
    builder.InsertParam(EVENT_KEY_FORM_NAME, formName);
    builder.InsertParam(EVENT_KEY_FUNC_TYPE, static_cast<int8_t>(funcType));
    builder.Write("FORM_MANAGER", "REQUEST_PUBLIC_FORM", HISYSEVENT_STATISTIC);
}

void FormEventReport::SendFormFailedEvent(const FormEventName &eventName, int64_t formId,
    const std::string &bundleName, const std::string &formName, int32_t errorType, int32_t errorCode)
{
    std::string name = ConvertEventName(eventName);
    if (name == INVALIDEVENTNAME) {
        HILOG_ERROR("invalid eventName");
        return;
    }
    FormHiSysEventBuilder builder;
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
        case FormEventName::FORM_DUE_CONTROL:
        case FormEventName::FORM_EXCEEDS_DISTRIBUTION:
        case FormEventName::CALLEN_DB_FAILED:
            builder.InsertParam(EVENT_KEY_FORM_ID, formId);
            builder.InsertParam(EVENT_KEY_BUNDLE_NAME, bundleName);
            builder.InsertParam(EVENT_KEY_FORM_NAME, formName);
            builder.InsertParam(EVENT_KEY_ERROR_NAME, name);
            builder.InsertParam(EVENT_KEY_ERROR_TYPE, errorType);
            builder.InsertParam(EVENT_KEY_ERROR_CODE, errorCode);
            builder.Write("FORM_MANAGER", FORM_ERROR, HISYSEVENT_FAULT);
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
    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_OCCURRENCE_TIME, occurrenceTimeList);
    builder.InsertParam(EVENT_KEY_FORM_COUNT, formCountList);
    builder.InsertParam(EVENT_KEY_IS_LOW_MEMORY, isLowMemoryList);
    builder.InsertParam(EVENT_KEY_STATUS, statusList);
    builder.Write("FORM_MANAGER", FORM_RENDER_SERVICE_STATUS_ALTER, HISYSEVENT_STATISTIC);
}

void FormEventReport::SendFormAbnormalEvent(const FormAbnormalReportParams &params)
{
    HILOG_DEBUG("call");

    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_BUNDLE_NAME, params.bundleNames);
    builder.InsertParam(EVENT_KEY_MODULE_NAME, params.moduleNames);
    builder.InsertParam(EVENT_KEY_ABILITY_NAME, params.abilityNames);
    builder.InsertParam(EVENT_KEY_FORM_NAME, params.formNames);
    builder.InsertParam(EVENT_KEY_FORM_DIMENSION, params.formDimensions);
    builder.InsertParam(EVENT_KEY_FORM_LOCATION, params.formLocations);
    builder.InsertParam(EVENT_KEY_APP_VERSION, params.appVersions);
    builder.InsertParam(EVENT_KEY_NONTRANSPARENCY_RATE, params.nonTransparencyRateList);
    builder.Write("FORM_MANAGER", ABNORMAL_FORM, HISYSEVENT_STATISTIC);
}

void FormEventReport::SendFormFwkUEEvent(const FormEventName &eventName, const FormEventInfo &eventInfo)
{
    const std::string name = ConvertEventName(eventName);
    if (name == INVALIDEVENTNAME) {
        HILOG_ERROR("invalid eventName");
        return;
    }

    FormHiSysEventBuilder builder;
    switch (eventName) {
        case FormEventName::ADD_DISTRIBUTED_FORM:
        case FormEventName::DELETE_DISTRIBUTED_FORM:
            builder.InsertParam(EVENT_KEY_FORM_ID, eventInfo.formId);
            builder.InsertParam(EVENT_KEY_BUNDLE_NAME, eventInfo.bundleName);
            builder.InsertParam(EVENT_KEY_MODULE_NAME, eventInfo.moduleName);
            builder.InsertParam(EVENT_KEY_FORM_DIMENSION, static_cast<int64_t>(eventInfo.formDimension));
            builder.InsertParam(EVENT_KEY_IS_DISTRIBUTED_FORM, eventInfo.isDistributedForm);
            builder.Write("FORM_FWK_UE", name, HISYSEVENT_BEHAVIOR);
            break;
        default:
            HILOG_ERROR("%{public}s is not UE event", name.c_str());
            break;
    }
}
} // namespace AppExecFwk
} // namespace OHOS