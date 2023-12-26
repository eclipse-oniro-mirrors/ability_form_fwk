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

#ifndef OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_INTERFACE_H
#define OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_INTERFACE_H

#include <string>
#include "form_instance.h"
#include "iremote_broker.h"
#include "running_form_info.h"

namespace OHOS {
namespace AbilityRuntime {
class IJsFormStateObserver : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.IJsFormStateObserver");

    /**
     * @brief The form added.
     * @param bundleName The bundle name of the form host.
     */
    virtual int32_t OnAddForm(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo) = 0;

    /**
     * @brief The form removed.
     * @param bundleName The bundle name of the form host.
     */
    virtual int32_t OnRemoveForm(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo) = 0;

    /**
     * @brief The form click event.
     * @param bundleName BundleName of the form host.
     * @param formEventType The click event type.
     * @param runningFormInfo The running form info.
     */
    virtual int32_t OnFormClickEvent(const std::string &bundleName, const std::string &formEventType,
        const AppExecFwk::RunningFormInfo &runningFormInfo) = 0;

    virtual int32_t NotifyWhetherFormsVisible(const AppExecFwk::FormVisibilityType visibleType,
        const std::string &bundleName, std::vector<AppExecFwk::FormInstance> &runningFormInfos) = 0;

    enum class Message {
        FORM_STATE_OBSERVER_ON_ADD_FORM = 4302,
        FORM_STATE_OBSERVER_ON_REMOVE_FORM = 4303,
        FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE = 4304,
        FORM_STATE_OBSERVER_ON_FORM_CLICK = 4305
    };
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_INTERFACE_H