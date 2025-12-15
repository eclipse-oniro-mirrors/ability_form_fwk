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

#ifndef OHOS_ABILITY_RUNTIME_ETS_FORM_EDIT_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_ETS_FORM_EDIT_EXTENSION_CONTEXT_H

#include "ani.h"
#include "form_edit_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {

class EtsFormEditExtensionContext {
public:
    explicit EtsFormEditExtensionContext(const std::shared_ptr<FormEditExtensionContext> &context)
        : context_(context)
    {}
    virtual ~EtsFormEditExtensionContext() = default;

    static ani_object CreateEtsFormEditExtensionContext(ani_env *env,
        std::shared_ptr<FormEditExtensionContext> context);
    static bool BindNativePtrCleaner(ani_env *env);
    static void Clean(ani_env *env, ani_object object);
    static void StartSecondPage(ani_env *env, ani_object aniObj, ani_object aniWant, ani_object callback);
    static void StartUIAbility(ani_env *env, ani_object aniObj, ani_object aniWant, ani_object callback);

private:
    static EtsFormEditExtensionContext* GetEtsFormEditExtensionContext(ani_env *env, ani_object obj);
    bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result);
    void OnStartSecondPage(ani_env *env, ani_object aniWant, ani_object callback);
    void OnStartUIAbility(ani_env *env, ani_object aniWant, ani_object callback);

    std::weak_ptr<FormEditExtensionContext> context_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ETS_FORM_EDIT_EXTENSION_CONTEXT_H