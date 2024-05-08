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

using HiSysEventType = OHOS::HiviewDFX::HiSysEvent::EventType;
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;

namespace OHOS {
namespace AppExecFwk {
struct FormEventInfo {
    int64_t formId = -1;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string hostBundleName = "";
    int32_t formAppPid = -1;
    int64_t timeStamp = 0;
};

enum class FormEventName {
    // form behavior event
    ADD_FORM,
    REQUEST_FORM,
    DELETE_FORM,
    CASTTEMP_FORM,
    ACQUIREFORMSTATE_FORM,
    MESSAGE_EVENT_FORM,
    ROUTE_EVENT_FORM,
    BACKGROUND_EVENT_FORM,
    RELEASE_FORM,
    DELETE_INVALID_FORM,
    SET_NEXT_REFRESH_TIME_FORM,
    FORM_RENDER_BLOCK,
    LAUNCH_FORM_APP,
    UNBIND_FORM_APP,
};

class FormEventReport {
public:
    static void SendFormEvent(const FormEventName &eventName, HiSysEventType type, const FormEventInfo &eventInfo);
    static void SendSecondFormEvent(const FormEventName &eventName, HiSysEventType type,
        const FormEventInfo &eventInfo);
    static void SendThirdFormEvent(const FormEventName &eventName, HiSysEventType type, const FormEventInfo &eventInfo);

private:
    static std::string ConvertEventName(const FormEventName &eventName);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_EVENT_REPORT_H
