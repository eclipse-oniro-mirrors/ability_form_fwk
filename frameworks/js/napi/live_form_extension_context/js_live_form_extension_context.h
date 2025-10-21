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

#ifndef OHOS_FORM_FWK_JS_LIVE_FORM_EXTENSION_CONTEXT_H
#define OHOS_FORM_FWK_JS_LIVE_FORM_EXTENSION_CONTEXT_H

#include "native_engine/native_engine.h"
#include "live_form_extension_context.h"
#include "js_ui_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
struct NapiCallbackInfo;
class JsLiveFormExtensionContext {
public:
    explicit JsLiveFormExtensionContext(const std::shared_ptr<LiveFormExtensionContext> &context)
        : context_(context)
    {}

    virtual ~JsLiveFormExtensionContext() = default;

    static void Finalizer(napi_env env, void *data, void *hint);

    static napi_value CreateJsLiveFormExtensionContext(napi_env env,
        std::shared_ptr<LiveFormExtensionContext> context);

    static napi_value SetWindowBackgroundColor(napi_env env, napi_callback_info info);

    static napi_value StartAbilityByLiveForm(napi_env env, napi_callback_info info);

    static napi_value ConnectAbility(napi_env env, napi_callback_info info);

    static napi_value DisconnectAbility(napi_env env, napi_callback_info info);

private:
    napi_value OnSetWindowBackgroundColor(napi_env env, NapiCallbackInfo &info);

    napi_value OnStartAbilityByLiveForm(napi_env env, NapiCallbackInfo &info);

    napi_value OnConnectAbility(napi_env env, NapiCallbackInfo &info);

    napi_value OnDisconnectAbility(napi_env env, NapiCallbackInfo &info);

    bool CheckConnectionParam(napi_env env, napi_value value,
        sptr<JSUIExtensionConnection> &connection, AAFwk::Want &want);

    bool CheckCallerIsSystemApp();

private:
    std::weak_ptr<LiveFormExtensionContext> context_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_JS_LIVE_FORM_EXTENSION_CONTEXT_H