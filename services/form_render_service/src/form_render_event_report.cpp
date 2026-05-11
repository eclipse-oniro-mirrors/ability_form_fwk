/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "form_render_event_report.h"

#include <chrono>
#include <unordered_map>
#include "backtrace_local.h"
#include "fms_log_wrapper.h"
#include "form_hisysevent_wrapper.h"
#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static constexpr char DOMAIN_PERFORMANCE[] = "PERFORMANCE";
constexpr const char *EVENT_KEY_FORM_ID = "FORM_ID";
constexpr const char *EVENT_KEY_FORM_NAME = "FORM_NAME";
constexpr const char *EVENT_KEY_BUNDLE_NAME = "BUNDLE_NAME";
constexpr const char *EVENT_KEY_ERROR_NAME = "ERROR_NAME";
constexpr const char *EVENT_KEY_ERROR_MSG = "ERROR_MSG";
constexpr const char *EVENT_KEY_ERROR_TYPE = "ERROR_TYPE";
constexpr const char *EVENT_KEY_ERROR_CODE = "ERROR_CODE";
constexpr const char *EVENT_KEY_PROCESS_MEMORY = "PROCESS_MEMORY";
constexpr const char *EVENT_KEY_BUNDLE_MEMORY = "BUNDLE_MEMORY";
constexpr const char *EVENT_KEY_FORM_LOCATION = "FORM_LOCATION";
constexpr const char *INVALIDEVENTNAME = "INVALIDEVENTNAME";
constexpr int64_t RECYCLE_FORM_FAILED = 1;
constexpr int64_t WAIT_RELEASE_RENDERER_ERROR_CODE = 400;
constexpr int64_t WAIT_RELEASE_RENDERER_TIMEOUT = 2000;
static const std::unordered_map<FormEventName, const char *> EVENT_NAME_MAP = {
    {FormEventName::RELOAD_FORM_FAILED, "RELOAD_FORM_FAILED"},
    {FormEventName::RECYCLE_RECOVER_FORM_FAILED, "RECYCLE_RECOVER_FORM_FAILED"},
};
}

using namespace std;
using namespace std::chrono;

std::unordered_map<int64_t, int32_t> FormRenderEventReport::waitReleaseTimerMap_ = {};

void FormRenderEventReport::SendPerformanceEvent(SceneType sceneType, PerformanceEventInfo &eventInfo)
{
    FormHiSysEventBuilder builder;
    switch (sceneType) {
        case SceneType::CPU_SCENE_ENTRY:
            builder.InsertParam("PACKAGE_NAME", eventInfo.bundleName);
            builder.InsertParam("SCENE_ID", eventInfo.sceneId);
            builder.InsertParam("HAPPEN_TIME", eventInfo.timeStamp);
            builder.Write(DOMAIN_PERFORMANCE, "CPU_SCENE_ENTRY", HISYSEVENT_BEHAVIOR);
            break;
        default:
            break;
    }
}

void FormRenderEventReport::SendBlockFaultEvent(const std::string &bundleName, const std::string &errorName,
    const std::string &errorMsg)
{
    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_BUNDLE_NAME, bundleName);
    builder.InsertParam(EVENT_KEY_ERROR_NAME, errorName);
    builder.InsertParam(EVENT_KEY_ERROR_MSG, errorMsg);
    builder.Write("FORM_MANAGER", "FORM_BLOCK_CALLSTACK", HISYSEVENT_FAULT);
}

std::string FormRenderEventReport::ConvertEventName(const FormEventName &eventName)
{
    auto it = EVENT_NAME_MAP.find(eventName);
    if (it != EVENT_NAME_MAP.end()) {
        return it->second;
    }
    return INVALIDEVENTNAME;
}

void FormRenderEventReport::SendFormFailedEvent(const FormEventName &eventName, int64_t formId,
    const std::string &bundleName, const std::string &formName, int32_t errorType, int32_t errorCode)
{
    std::string name = ConvertEventName(eventName);
    if (name == INVALIDEVENTNAME) {
        HILOG_ERROR("invalid eventName");
        return;
    }

    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_FORM_ID, formId);
    builder.InsertParam(EVENT_KEY_BUNDLE_NAME, bundleName);
    builder.InsertParam(EVENT_KEY_FORM_NAME, formName);
    builder.InsertParam(EVENT_KEY_ERROR_NAME, name);
    builder.InsertParam(EVENT_KEY_ERROR_TYPE, errorType);
    builder.InsertParam(EVENT_KEY_ERROR_CODE, errorCode);
    builder.Write("FORM_MANAGER", "FORM_ERROR", HISYSEVENT_FAULT);
}

void FormRenderEventReport::StartReleaseTimeoutReportTimer(int64_t formId, const std::string &uid)
{
    FormRenderEventReport::StopReleaseTimeoutReportTimer(formId);
    auto timeoutCallback = [formId, uid](void *) {
        HILOG_ERROR("RecycleForm failed, wait form release timeout, formId:%{public}" PRId64, formId);
        std::string eventName = ConvertEventName(FormEventName::RECYCLE_RECOVER_FORM_FAILED);
        FormHiSysEventBuilder builder;
        builder.InsertParam(EVENT_KEY_FORM_ID, formId);
        builder.InsertParam(EVENT_KEY_BUNDLE_NAME, uid);
        builder.InsertParam(EVENT_KEY_FORM_NAME, std::string(""));
        builder.InsertParam(EVENT_KEY_ERROR_NAME, eventName);
        builder.InsertParam(EVENT_KEY_ERROR_TYPE, static_cast<int32_t>(RECYCLE_FORM_FAILED));
        builder.InsertParam(EVENT_KEY_ERROR_CODE, static_cast<int32_t>(WAIT_RELEASE_RENDERER_ERROR_CODE));
        builder.Write("FORM_MANAGER", "FORM_ERROR", HISYSEVENT_FAULT);
    };
    const std::string taskName = "FRS_WaitReleaseRenderer_" + std::to_string(formId);
    int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(taskName, WAIT_RELEASE_RENDERER_TIMEOUT,
        timeoutCallback, nullptr, HiviewDFX::XCOLLIE_FLAG_NOOP);
    HILOG_INFO("waiting form release, formId: %{public}" PRId64 ", timerId: %{public}d", formId, timerId);
    FormRenderEventReport::waitReleaseTimerMap_.emplace(formId, timerId);
}

void FormRenderEventReport::StopReleaseTimeoutReportTimer(int64_t formId)
{
    auto iter = FormRenderEventReport::waitReleaseTimerMap_.find(formId);
    if (iter != FormRenderEventReport::waitReleaseTimerMap_.end()) {
        int32_t timerId = iter->second;
        HILOG_INFO("form release completed, formId: %{public}" PRId64 "timerId: %{public}d", formId, timerId);
        HiviewDFX::XCollie::GetInstance().CancelTimer(timerId);
        FormRenderEventReport::waitReleaseTimerMap_.erase(iter);
    }
}

void FormRenderEventReport::SendRuntimeMemoryLeakEvent(const std::string &bundleName, uint64_t processMemory,
    uint64_t runtimeMemory, std::vector<std::string> &formName, std::vector<uint32_t> &formLocation)
{
    HILOG_INFO("runtime memory leak, bundleName: %{public}s processMemory: %{public}" PRIu64
        ", runtimeMemory: %{public}" PRIu64, bundleName.c_str(), processMemory, runtimeMemory);

    FormHiSysEventBuilder builder;
    builder.InsertParam(EVENT_KEY_BUNDLE_NAME, bundleName);
    builder.InsertParam(EVENT_KEY_PROCESS_MEMORY, processMemory);
    builder.InsertParam(EVENT_KEY_BUNDLE_MEMORY, runtimeMemory);
    builder.InsertParam(EVENT_KEY_FORM_NAME, formName);
    builder.InsertParam(EVENT_KEY_FORM_LOCATION, formLocation);
    builder.Write("FORM_MANAGER", "FORM_MEMORY_LEAK", HISYSEVENT_STATISTIC);
}
} // namespace AppExecFwk
} // namespace OHOS