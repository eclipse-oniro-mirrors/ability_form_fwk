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

#ifndef OHOS_FORM_FWK_ETS_LIVE_FORM_EXTENSION_IMPL_H
#define OHOS_FORM_FWK_ETS_LIVE_FORM_EXTENSION_IMPL_H

#include "ani.h"
#include "ets_ui_extension_base.h"
#include "live_form_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {

class LiveFormExtensionContext;

class EtsLiveFormExtensionImpl : public EtsUIExtensionBase {
public:
    explicit EtsLiveFormExtensionImpl(const std::unique_ptr<Runtime> &runtime);
    ~EtsLiveFormExtensionImpl() override = default;

    void SetContext(const std::shared_ptr<LiveFormExtensionContext> &context)
    {
        context_ = context;
        EtsUIExtensionBase::SetContext(context);
    }

    static void SetWindowBackgroundColor(ani_env *env, ani_object obj, ani_object callback);

protected:
    void BindContext() override;

protected:
    std::shared_ptr<LiveFormExtensionContext> context_ = nullptr;

private:
    void BindMethod(ani_env *env);
    bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result);
    static EtsLiveFormExtensionImpl* GetEtsEtsLiveForm(ani_env *env, ani_object obj);
    void OnSetWindowBackgroundColor(ani_env *env, ani_object callback);

    using EtsUIExtensionBase::SetContext;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_FORM_FWK_ETS_LIVE_FORM_EXTENSION_IMPL_H