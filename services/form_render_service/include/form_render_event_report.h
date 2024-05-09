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
    static void SendBlockFaultEvent(pid_t processId, pid_t jsThreadId, std::string bundleName);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RENDER_EVENT_REPORT_H
