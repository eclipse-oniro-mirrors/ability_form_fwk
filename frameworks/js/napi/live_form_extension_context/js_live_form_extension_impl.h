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

#ifndef OHOS_FORM_FWK_JS_LIVE_FORM_EXTENSION_IMPL_H
#define OHOS_FORM_FWK_JS_LIVE_FORM_EXTENSION_IMPL_H

#include "js_ui_extension_base.h"
#include "live_form_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {

class LiveFormExtensionContext;

class JsLiveFormExtensionImpl : public JsUIExtensionBase {
public:
    explicit JsLiveFormExtensionImpl(const std::unique_ptr<Runtime> &runtime);
    ~JsLiveFormExtensionImpl() override = default;

    void SetContext(const std::shared_ptr<LiveFormExtensionContext> &context)
    {
        context_ = context;
        JsUIExtensionBase::SetContext(context);
    }

protected:
    void BindContext() override;

protected:
    std::shared_ptr<LiveFormExtensionContext> context_ = nullptr;

private:
    using JsUIExtensionBase::SetContext;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_JS_PHOTO_LIVEOR_EXTENSION_IMPL_H