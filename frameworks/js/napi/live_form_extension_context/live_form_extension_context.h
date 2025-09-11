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

#ifndef OHOS_FORM_FWK_LIVE_FORM_EXTENSION_CONTEXT_H
#define OHOS_FORM_FWK_LIVE_FORM_EXTENSION_CONTEXT_H

#include "ui_extension_context.h"

#include "caller_callback.h"
#include "local_call_container.h"

namespace OHOS {
namespace AbilityRuntime {
class LiveFormExtensionContext : public UIExtensionContext {
public:
    LiveFormExtensionContext() = default;

    virtual ~LiveFormExtensionContext() = default;

    static const size_t CONTEXT_TYPE_ID;

    bool SetWindowBackgroundColor();

    ErrCode StartAbilityByFms(const AAFwk::Want &want, const std::string &formId);

    ErrCode StartAbilityByCall(const AAFwk::Want &want, const std::shared_ptr<CallerCallBack> &callback);

    ErrCode ReleaseCall(const std::shared_ptr<CallerCallBack> &callback);

    void ClearFailedCallConnection(const std::shared_ptr<CallerCallBack> &callback);

    std::shared_ptr<LocalCallContainer> GetLocalCallContainer()
    {
        return localCallContainer_;
    }

private:
    std::shared_ptr<LocalCallContainer> localCallContainer_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_LIVE_FORM_EXTENSION_CONTEXT_H