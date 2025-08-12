/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <map>
#include "backtrace_local.h"
#include "fms_log_wrapper.h"
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
    constexpr int64_t RECYCLE_FORM_FAILED = 1;
    constexpr int64_t WAIT_RELEASE_RENDERER_ERROR_CODE = 400;
    constexpr int64_t WAIT_RELEASE_RENDERER_TIMEOUT = 2000;
}

using namespace std;
using namespace std::chrono;

std::unordered_map<int64_t, int32_t> FormRenderEventReport::waitReleaseTimerMap_ = {};

int64_t FormRenderEventReport::GetNowMillisecond()
{
    system_clock::time_point pointTime = system_clock::now();
    auto timeMilliseconds = chrono::duration_cast<chrono::milliseconds>(pointTime.time_since_epoch());
    return timeMilliseconds.count();
}

void FormRenderEventReport::SendPerformanceEvent(SceneType sceneType, PerformanceEventInfo &eventInfo)
{
    switch (sceneType) {
        case SceneType::CPU_SCENE_ENTRY:
            HiSysEventWrite(
                DOMAIN_PERFORMANCE,
                "CPU_SCENE_ENTRY",
                HiSysEventType::BEHAVIOR,
                "PACKAGE_NAME", eventInfo.bundleName,
                "SCENE_ID", eventInfo.sceneId,
                "HAPPEN_TIME", eventInfo.timeStamp);
            break;
        default:
            break;
    }
}

void FormRenderEventReport::SendBlockFaultEvent(const std::string &bundleName, const std::string &errorName,
    const std::string &errorMsg)
{
    HiSysEventWrite(
        HiSysEvent::Domain::FORM_MANAGER,
        "FORM_BLOCK_CALLSTACK",
        HiSysEvent::EventType::FAULT,
        EVENT_KEY_BUNDLE_NAME, bundleName,
        EVENT_KEY_ERROR_NAME, errorName,
        EVENT_KEY_ERROR_MSG, errorMsg);
}

	// After RecycleForm is executed, it will proceed to ReleaseRenderer.
// If ReleaseRenderer is not called within the timeout period, a card recycling failure will be reported.
void FormRenderEventReport::StartReleaseTimeoutReportTimer(int64_t formId, const std::string &uid)
{
    FormRenderEventReport::StopReleaseTimeoutReportTimer(formId);
    auto timeoutCallback = [formId, uid](void *) {
        HILOG_ERROR("RecycleForm failed, wait form release timeout, formId:%{public}" PRId64, formId);
        HiSysEventWrite(
            HiSysEvent::Domain::FORM_MANAGER, "FORM_ERROR",
            HiSysEvent::EventType::FAULT,
            EVENT_KEY_FORM_ID, formId,
            EVENT_KEY_BUNDLE_NAME, uid,
            EVENT_KEY_FORM_NAME, "",
            EVENT_KEY_ERROR_NAME, "RECYCLE_RECOVER_FORM_FAILED",
            EVENT_KEY_ERROR_TYPE, RECYCLE_FORM_FAILED,
            EVENT_KEY_ERROR_CODE, WAIT_RELEASE_RENDERER_ERROR_CODE);
    };
    const std::string taskName = "FRS_WaitReleaseRenderer_" + std::to_string(formId);
    int32_t timerId = HiviewDFX::XCollie::GetInstance().SetTimer(taskName, WAIT_RELEASE_RENDERER_TIMEOUT,
        timeoutCallback, nullptr, HiviewDFX::XCOLLIE_FLAG_NOOP);
    HILOG_INFO("waiting form release, formId: %{public}" PRId64 "timerId: %{public}d", formId, timerId);
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

    HiSysEventWrite(HiSysEvent::Domain::FORM_MANAGER,
        "FORM_MEMORY_LEAK",
        HiSysEvent::EventType::FAULT,
        EVENT_KEY_BUNDLE_NAME, bundleName,
        EVENT_KEY_PROCESS_MEMORY, processMemory,
        EVENT_KEY_BUNDLE_MEMORY, runtimeMemory,
        EVENT_KEY_FORM_NAME, formName,
        EVENT_KEY_FORM_LOCATION, formLocation);
}
} // namespace AppExecFwk
} // namespace OHOS
