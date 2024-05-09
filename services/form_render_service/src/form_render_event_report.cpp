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
#include "dfx_dump_catcher.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    static constexpr char DOMAIN_PERFORMANCE[] = "PERFORMANCE";
    constexpr const char *EVENT_KEY_FORM_BLOCK_CALLSTACK = "EVENT_KEY_FORM_BLOCK_CALLSTACK";
    constexpr const char *EVENT_KEY_FORM_BLOCK_APPNAME = "EVENT_KEY_FORM_BLOCK_APPNAME";
}

using namespace std;
using namespace std::chrono;

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

void FormRenderEventReport::SendBlockFaultEvent(pid_t processId, pid_t jsThreadId, std::string bundleName)
{
    OHOS::HiviewDFX::DfxDumpCatcher dumplog;
    std::string traceStr;
    bool ret = dumplog.DumpCatch(processId, jsThreadId, traceStr);
    if (ret) {
        HILOG_INFO("Print block form's process id %{public}d and thread %{public}d call stack %{public}s .",
            processId, jsThreadId, traceStr.c_str());
    }
    HiSysEventWrite(
        HiSysEvent::Domain::FORM_MANAGER,
        "FORM_RENDER_BLOCK",
        HiSysEvent::EventType::FAULT,
        EVENT_KEY_FORM_BLOCK_CALLSTACK, traceStr,
        EVENT_KEY_FORM_BLOCK_APPNAME, bundleName);
}

} // namespace AppExecFwk
} // namespace OHOS
