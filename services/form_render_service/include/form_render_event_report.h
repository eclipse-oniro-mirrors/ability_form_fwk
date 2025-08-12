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

#ifndef OHOS_FORM_FWK_FORM_RENDER_EVENT_REPORT_H
#define OHOS_FORM_FWK_FORM_RENDER_EVENT_REPORT_H

#include <string>

#include "hisysevent.h"

using HiSysEventType = OHOS::HiviewDFX::HiSysEvent::EventType;
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;

namespace OHOS {
namespace AppExecFwk {

struct PerformanceEventInfo {
    std::string bundleName;
    std::string sceneId;
    int64_t timeStamp = 0;
};

enum class SceneType {
    CPU_SCENE_ENTRY,
};

class FormRenderEventReport {
public:
    static int64_t GetNowMillisecond();
    static void SendPerformanceEvent(SceneType sceneType, PerformanceEventInfo &eventInfo);
    static void SendBlockFaultEvent(const std::string &bundleName, const std::string &errorName,
        const std::string &errorMsg);
    static void StartReleaseTimeoutReportTimer(int64_t formId, const std::string &uid);
    static void StopReleaseTimeoutReportTimer(int64_t formId);
    static void SendRuntimeMemoryLeakEvent(const std::string &bundleName, uint64_t processMemory,
        uint64_t runtimeMemory, std::vector<std::string> &formName, std::vector<uint32_t> &formLocation);

private:
    static std::unordered_map<int64_t, int32_t> waitReleaseTimerMap_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_EVENT_REPORT_H
