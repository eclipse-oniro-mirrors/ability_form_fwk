/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include <fuzzer/FuzzedDataProvider.h>

using namespace OHOS::AppExecFwk;
const std::vector<FormEventName> EVENT_NAME_LIST = {FormEventName::ADD_FORM, FormEventName::REQUEST_FORM,
    FormEventName::DELETE_FORM, FormEventName::CASTTEMP_FORM, FormEventName::ACQUIREFORMSTATE_FORM,
    FormEventName::MESSAGE_EVENT_FORM, FormEventName::ROUTE_EVENT_FORM, FormEventName::BACKGROUND_EVENT_FORM,
    FormEventName::RELEASE_FORM, FormEventName::DELETE_INVALID_FORM, FormEventName::SET_NEXT_REFRESH_TIME_FORM,
    FormEventName::FORM_RENDER_BLOCK, FormEventName::INIT_FMS_FAILED, FormEventName::CALLEN_DB_FAILED,
    FormEventName::ADD_FORM_FAILED, FormEventName::FIRST_ADD_FORM_DURATION,
    FormEventName::FIRST_UPDATE_FORM_DURATION, FormEventName::UPDATE_FORM_REFRESH_TIMES,
    FormEventName::PROXY_UPDATE_FORM, FormEventName::INVALID_PUBLISH_FORM_TO_HOST,
    FormEventName::LAUNCH_FORM_APP, FormEventName::CONDITION_UPDATE_FORM, FormEventName::UNBIND_FORM_APP,
    FormEventName::LOAD_STAGE_FORM_CONFIG_INFO, FormEventName::DELETE_FORM_FAILED,
    FormEventName::UPDATE_FORM_FAILED, FormEventName::RECYCLE_RECOVER_FORM_FAILED,
    FormEventName::REQUEST_PUBLIC_FORM, FormEventName::CONNECT_FORM_ABILITY_FAILED,
    FormEventName::RELOAD_FORM_FAILED, FormEventName::FORM_NODE_ERROR, FormEventName::FORM_STATUS_ERROR,
    FormEventName::FORM_EVENT_QUEUE_OVER_LIMIT};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    FormEventName eventName = EVENT_NAME_LIST[provider.ConsumeIntegralInRange<size_t>(0, EVENT_NAME_LIST.size() - 1)];
    FormEventInfo eventInfo;
    eventInfo.formId = provider.ConsumeIntegral<int64_t>();
    eventInfo.bundleName = provider.ConsumeRandomLengthString();
    eventInfo.moduleName = provider.ConsumeRandomLengthString();
    eventInfo.abilityName = provider.ConsumeRandomLengthString();
    FormEventReport::SendFormEvent(eventName, HiSysEventType::BEHAVIOR, eventInfo);
    FormEventReport::SendSecondFormEvent(eventName, HiSysEventType::BEHAVIOR, eventInfo);
    FormEventReport::SendThirdFormEvent(eventName, HiSysEventType::BEHAVIOR, eventInfo);
    int64_t errorType = provider.ConsumeIntegral<int64_t>();
    FormEventReport::SendFormFailedEvent(eventName, HiSysEventType::FAULT, errorType);
    NewFormEventInfo newEventInfo;
    newEventInfo.sessionId = provider.ConsumeIntegral<int64_t>();
    newEventInfo.formId = provider.ConsumeIntegral<int64_t>();
    newEventInfo.bundleName = provider.ConsumeRandomLengthString();
    newEventInfo.moduleName = provider.ConsumeRandomLengthString();
    newEventInfo.abilityName = provider.ConsumeRandomLengthString();
    newEventInfo.formName = provider.ConsumeRandomLengthString();
    newEventInfo.formDimension = provider.ConsumeIntegral<int64_t>();
    FormEventReport::SendFirstAddFormEvent(eventName, HiSysEventType::STATISTIC, newEventInfo);
    FormEventReport::SendFirstUpdateFormEvent(eventName, HiSysEventType::STATISTIC, newEventInfo);
    Want want;
    FormEventReport::SendFourthFormEvent(eventName, HiSysEventType::STATISTIC, newEventInfo, want);
    FormEventReport::SendConditonUpdateFormEvent(eventName, HiSysEventType::BEHAVIOR, newEventInfo);
    FormEventReport::SendFormRefreshCountEvent(eventName, HiSysEventType::STATISTIC, newEventInfo);
    FormEventReport::SendLoadStageFormConfigInfoEvent(eventName, HiSysEventType::BEHAVIOR, newEventInfo);
    FormEventReport::SendDiskUseEvent();
    std::string formName = provider.ConsumeRandomLengthString();
    int64_t formId = provider.ConsumeIntegral<int64_t>();
    std::string bundleName = provider.ConsumeRandomLengthString();
    int32_t errorCode = provider.ConsumeIntegral<int32_t>();
    FormEventReport::SendFormFailedEvent(eventName, formId, bundleName, formName, errorType, errorCode);
    std::vector<bool> isLowMemoryList;
    std::vector<uint8_t> statusList;
    std::vector<int32_t> formCountList;
    std::vector<int64_t> occurrenceTimeList;
    FormEventReport::SendFRSStatusEvent(isLowMemoryList, statusList, formCountList, occurrenceTimeList);
    return 0;
}