/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "napi/native_api.h"

#include "hilog_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_node_api.h"
#include "napi_form_provider.h"

EXTERN_C_START
using namespace OHOS::AbilityRuntime;

static NativeValue* JsProviderInit(NativeEngine* engine, NativeValue* exports)
{
    HILOG_INFO("JsProviderInit is called");
    if (engine == nullptr || exports == nullptr) {
        HILOG_ERROR("Invalid input parameters");
        return nullptr;
    }

    NativeObject* object = ConvertNativeValueTo<NativeObject>(exports);
    if (object == nullptr) {
        HILOG_ERROR("object is nullptr");
        return nullptr;
    }

    std::unique_ptr<JsFormProvider> jsFormPorivder = std::make_unique<JsFormProvider>();
    object->SetNativePointer(jsFormPorivder.release(), JsFormProvider::Finalizer, nullptr);

    const char *moduleName = "JsFormProvider";
    BindNativeFunction(*engine, *object, "getFormsInfo", moduleName, JsFormProvider::GetFormsInfo);
    BindNativeFunction(*engine, *object, "setFormNextRefreshTime", moduleName, JsFormProvider::SetFormNextRefreshTime);
    BindNativeFunction(*engine, *object, "updateForm", moduleName, JsFormProvider::UpdateForm);
    return exports;
}

/**
 * @brief  For N-API modules registration
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] exports  An empty object via the exports parameter as a convenience
 *
 * @return The return value from Init is treated as the exports object for the module
 */
static napi_value Init(napi_env env, napi_value exports)
{
    HILOG_INFO("napi_module Init start...");
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("requestPublishForm", NAPI_RequestPublishForm),
        DECLARE_NAPI_FUNCTION("isRequestPublishFormSupported", NAPI_IsRequestPublishFormSupported),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));
    HILOG_INFO("napi_module Init end...");
    return reinterpret_cast<napi_value>(JsProviderInit(reinterpret_cast<NativeEngine*>(env),
        reinterpret_cast<NativeValue*>(exports)));
}

EXTERN_C_END

// Define a Node-API module.
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "application.formProvider",
    .nm_priv = nullptr,
    .reserved = {nullptr}
};

// Registers a Node-API module.
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}