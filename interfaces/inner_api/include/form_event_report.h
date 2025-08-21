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

#ifndef OHOS_FORM_FWK_FORM_EVENT_REPORT_H
#define OHOS_FORM_FWK_FORM_EVENT_REPORT_H

#include <string>

#include "hisysevent.h"
#include "want.h"
#include "form_event_report_define.h"

using HiSysEventType = OHOS::HiviewDFX::HiSysEvent::EventType;
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;
using Want = OHOS::AAFwk::Want;

namespace OHOS {
namespace AppExecFwk {
class FormEventReport {
public:
    static void SendFormEvent(const FormEventName &eventName, HiSysEventType type, const FormEventInfo &eventInfo);
    static void SendSecondFormEvent(const FormEventName &eventName, HiSysEventType type,
        const FormEventInfo &eventInfo);
    static void SendThirdFormEvent(const FormEventName &eventName, HiSysEventType type,
        const FormEventInfo &eventInfo);
    static void SendFormFailedEvent(const FormEventName &eventName, HiSysEventType type, int64_t errorType);
    static void SendFirstAddFormEvent(const FormEventName &eventName, HiSysEventType type,
        const NewFormEventInfo &eventInfo);
    static void SendFirstUpdateFormEvent(const FormEventName &eventName, HiSysEventType type,
        const NewFormEventInfo &eventInfo);
    static void SendFourthFormEvent(const FormEventName &eventName, HiSysEventType type,
        const NewFormEventInfo &eventInfo, const Want &want);
    static void SendConditonUpdateFormEvent(const FormEventName &eventName, HiSysEventType type,
        const NewFormEventInfo &eventInfo);
    static void SendFormRefreshCountEvent(const FormEventName &eventName, HiSysEventType type,
        const NewFormEventInfo &eventInfo);
    static void SendLoadStageFormConfigInfoEvent(const FormEventName &eventName, HiSysEventType type,
        const NewFormEventInfo &eventInfo);
    static void SendDiskUseEvent();
    static void SendRequestPublicFormEvent(const std::string &callerBundleName, const std::string &formName,
        bool withSnapshot = false);
    static void SendFormFailedEvent(const FormEventName &eventName, int64_t formId, const std::string &bundleName,
        const std::string &formName, int32_t errorType, int32_t errorCode = 0);
    static void SendFRSStatusEvent(
        const std::vector<bool> &isLowMemoryList,
        const std::vector<uint8_t> &statusList,
        const std::vector<int32_t> &formCountList,
        const std::vector<int64_t> &occurrenceTimeList);
private:
    static std::string ConvertEventName(const FormEventName &eventName);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_EVENT_REPORT_H
