/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef FORM_EVENT_REGISTER_H
#define FORM_EVENT_REGISTER_H

#include <vector>

#include "app_lock_struct_definition.h"
#include "switch_state_listener.h"

namespace OHOS::AppExecFwk {

using namespace AppSecurityPrivacy::AppLock;
class SwitchStateListenerImpl final: public SwitchStateListener {
public:
    explicit SwitchStateListenerImpl(const std::function<void(const std::vector<SwitchState>&)>& callbackFuc)
    {
        this->callbackFunc = callbackFuc;
    }

    void OnSwitchStateChanged(const std::vector<SwitchState>& switchStates) override
    {
        if (this->callbackFunc != nullptr) {
            callbackFunc(switchStates);
        }
    }

private:
    std::function<void(const std::vector<SwitchState>&)> callbackFunc;
};


} // namespace OHOS::AppExecFwk

#endif // FORM_EVENT_REGISTER_H
