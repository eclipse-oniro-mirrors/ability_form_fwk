/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <random>
#include "form_event_hiappevent.h"
#include "form_ecological_rule_interface.h"
#ifdef NO_RUNTIME_EMULATOR
#include "app_event.h"
#include "app_event_processor_mgr.h"
#endif

namespace OHOS {
namespace AppExecFwk {
#ifdef NO_RUNTIME_EMULATOR
using namespace OHOS::HiviewDFX;
#endif
namespace {
constexpr int32_t TRIGGER_COND_TIMEOUT = 90;
constexpr int32_t TRIGGER_COND_ROW = 30;
constexpr int32_t EVENT_RESULT_SUCCESS = 0;
constexpr int32_t EVENT_RESULT_FAIL = 1;
const std::string SDK_NAME = "FormKit";
}

int64_t FormEventHiAppEvent::AddProcessor()
{
#ifdef NO_RUNTIME_EMULATOR
    HiAppEvent::ReportConfig config;
    config.name = "ha_app_event";
    config.appId = "com_hmos_sdk_ocg";
    config.routeInfo = "AUTO";
    config.triggerCond.timeout = TRIGGER_COND_TIMEOUT;
    config.triggerCond.row = TRIGGER_COND_ROW;
    config.eventConfigs.clear();
    {
        HiAppEvent::EventConfig event1;
        event1.domain = "api_diagnostic";
        event1.name = "api_exec_end";
        event1.isRealTime = false;
        config.eventConfigs.push_back(event1);
    }
    {
        HiAppEvent::EventConfig event2;
        event2.domain = "api_diagnostic";
        event2.name = "api_called_stat";
        event2.isRealTime = true;
        config.eventConfigs.push_back(event2);
    }
    {
        HiAppEvent::EventConfig event3;
        event3.domain = "api_diagnostic";
        event3.name = "api_called_stat_cnt";
        event3.isRealTime = true;
        config.eventConfigs.push_back(event3);
    }
    return HiAppEvent::AppEventProcessorMgr::AddProcessor(config);
#else
    return 0;
#endif
}

void FormEventHiAppEvent::WriteAppFormEndEvent(const int errCode, const time_t beginTime,
    const std::string &apiName, const PublishFormData &publishFormData, const int64_t processorId)
{
#ifdef NO_RUNTIME_EMULATOR
    if (processorId <= 0) {
        HILOG_ERROR("Not an APP process.");
        return;
    }
    std::random_device rd;
    std::string transId = "traceId_" + std::to_string(rd());
    HiAppEvent::Event event("api_diagnostic", "api_exec_end", HiAppEvent::BEHAVIOR);
    int32_t result = (errCode == ERR_OK) ? EVENT_RESULT_SUCCESS : EVENT_RESULT_FAIL;
    event.AddParam("trans_id", transId);
    event.AddParam("result", result);
    event.AddParam("error_code", errCode);
    event.AddParam("api_name", apiName);
    event.AddParam("sdk_name", SDK_NAME);
    event.AddParam("begin_time", beginTime);
    event.AddParam("end_time", time(nullptr));
    event.AddParam("bundle_name", publishFormData.bundleName);
    event.AddParam("ability_name", publishFormData.abilityName);
    event.AddParam("form_dimension", publishFormData.formDimension);
    event.AddParam("module_name", publishFormData.moduleName);
    event.AddParam("form_name", publishFormData.formName);
    Write(event);
#endif
}
} // namespace AppExecFwk
} // namespace OHOS