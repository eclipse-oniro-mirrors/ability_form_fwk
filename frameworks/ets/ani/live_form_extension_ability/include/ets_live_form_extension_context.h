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

#ifndef OHOS_FORM_FWK_ETS_LIVE_FORM_EXTENSION_CONTEXT_H
#define OHOS_FORM_FWK_ETS_LIVE_FORM_EXTENSION_CONTEXT_H

#include "ani.h"
#include "live_form_extension_context.h"
#include "ets_ui_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsLiveFormExtensionContext final {
public:
    explicit EtsLiveFormExtensionContext(const std::shared_ptr<LiveFormExtensionContext> &context)
        : context_(context)
    {}
    virtual ~EtsLiveFormExtensionContext() = default;

    static ani_object CreateEtsLiveFormExtensionContext(ani_env *env,
        std::shared_ptr<LiveFormExtensionContext> context);
    static bool BindNativePtrCleaner(ani_env *env);
    static void Clean(ani_env *env, ani_object object);
    static void StartAbilityByLiveForm(ani_env *env, ani_object aniObj, ani_object aniWant,
        ani_string aniFormId, ani_object callback);
    static ani_long ConnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object connectOptionsObj);
    static void DisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_long connectId,
        ani_object callback);

private:
    static EtsLiveFormExtensionContext* GetEtsLiveFormExtensionContext(ani_env *env, ani_object obj);
    static bool CheckConnectionParam(ani_env *env, ani_object connectOptionsObj,
        sptr<EtsUIExtensionConnection>& connection, AAFwk::Want& want);
    void OnStartAbilityByLiveForm(ani_env *env, ani_object aniWant, ani_string aniFormId, ani_object callback);
    ani_long OnConnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object connectOptionsObj);
    void OnDisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj, ani_long connectId,
        ani_object callback);

    std::weak_ptr<LiveFormExtensionContext> context_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_FORM_FWK_ETS_LIVE_FORM_EXTENSION_CONTEXT_H