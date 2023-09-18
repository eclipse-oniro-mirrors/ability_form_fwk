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

#ifndef OHOS_FORM_FWK_JS_FORM_AGENT_H
#define OHOS_FORM_FWK_JS_FORM_AGENT_H

#include "ability.h"
#include "form_provider_info.h"
#include "napi_form_util.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "nlohmann/json.hpp"
#include "want.h"
#include <vector>

namespace OHOS {
namespace AbilityRuntime {
struct RequestPublishFormCallbackInfo {
    Want want {};
    bool withFormBindingData = false;
    std::unique_ptr<OHOS::AppExecFwk::FormProviderData> formProviderData = nullptr;
    std::vector<AppExecFwk::FormDataProxy> formDataProxies;
};

struct AsyncIsRequestPublishFormSupportedCallbackInfo : AsyncCallbackInfoBase {
    bool result = false;

    explicit AsyncIsRequestPublishFormSupportedCallbackInfo(napi_env env) : AsyncCallbackInfoBase(env) {};
    ~AsyncIsRequestPublishFormSupportedCallbackInfo() override = default;
};

napi_value NAPI_RequestPublishForm(napi_env env, napi_callback_info info);

/**
 * @brief Check if the request to publish a form to the form host is supported.
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] info This is an opaque pointer that is used to represent a JavaScript value
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 *         which is true if the request of publishing form is supported and false otherwise
 */
napi_value NAPI_IsRequestPublishFormSupported(napi_env env, napi_callback_info info);

class JsFormAgent {
public:
    JsFormAgent() = default;
    ~JsFormAgent() = default;

    static void Finalizer(NativeEngine* engine, void* data, void* hint);

    static NativeValue* RequestPublishForm(NativeEngine *engine, NativeCallbackInfo *info);
private:
    NativeValue* OnRequestPublishForm(NativeEngine &engine, NativeCallbackInfo &info);
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif /* OHOS_FORM_FWK_JS_FORM_AGENT_H */
