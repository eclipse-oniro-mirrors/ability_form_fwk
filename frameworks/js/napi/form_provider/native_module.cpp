/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "fms_log_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_node_api.h"
#include "js_form_provider.h"

EXTERN_C_START
using namespace OHOS::AbilityRuntime;

static napi_value JsProviderInit(napi_env env, napi_value exports)
{
    HILOG_DEBUG("call");

    std::unique_ptr<JsFormProvider> jsFormProvider = std::make_unique<JsFormProvider>();
    napi_wrap(env, exports, jsFormProvider.release(), JsFormProvider::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsFormProvider";
    BindNativeFunction(env, exports, "getFormsInfo", moduleName, JsFormProvider::GetFormsInfo);
    BindNativeFunction(env, exports, "getPublishedFormInfos", moduleName, JsFormProvider::GetPublishedFormInfos);
    BindNativeFunction(env, exports, "getPublishedFormInfoById", moduleName, JsFormProvider::GetPublishedFormInfoById);
    BindNativeFunction(env, exports, "openFormManager", moduleName, JsFormProvider::OpenFormManager);
    BindNativeFunction(env, exports, "openFormManagerCrossBundle", moduleName,
        JsFormProvider::OpenFormManagerCrossBundle);
    BindNativeFunction(env, exports, "setFormNextRefreshTime", moduleName, JsFormProvider::SetFormNextRefreshTime);
    BindNativeFunction(env, exports, "updateForm", moduleName, JsFormProvider::UpdateForm);
    BindNativeFunction(env, exports, "requestPublishForm", moduleName, JsFormProvider::RequestPublishForm);
    BindNativeFunction(env, exports, "isRequestPublishFormSupported", moduleName,
        JsFormProvider::IsRequestPublishFormSupported);
    BindNativeFunction(env, exports, "openFormEditAbility", moduleName, JsFormProvider::OpenFormEditAbility);
    BindNativeFunction(env, exports, "closeFormEditAbility", moduleName, JsFormProvider::CloseFormEditAbility);
    BindNativeFunction(env, exports, "requestOverflow", moduleName, JsFormProvider::RequestOverflow);
    BindNativeFunction(env, exports, "cancelOverflow", moduleName, JsFormProvider::CancelOverflow);
    BindNativeFunction(env, exports, "activateSceneAnimation", moduleName, JsFormProvider::ActivateSceneAnimation);
    BindNativeFunction(env, exports, "deactivateSceneAnimation", moduleName, JsFormProvider::DeactivateSceneAnimation);
    BindNativeFunction(env, exports, "getFormRect", moduleName, JsFormProvider::GetFormRect);
    BindNativeFunction(env, exports, "getPublishedRunningFormInfos", moduleName,
        JsFormProvider::GetPublishedRunningFormInfos);
    BindNativeFunction(env, exports, "getPublishedRunningFormInfoById", moduleName,
        JsFormProvider::GetPublishedRunningFormInfoById);
    BindNativeFunction(env, exports, "reloadForms", moduleName, JsFormProvider::ReloadForms);
    BindNativeFunction(env, exports, "reloadAllForms", moduleName, JsFormProvider::ReloadAllForms);
    BindNativeFunction(env, exports, "onPublishFormCrossBundleControl", moduleName,
        JsFormProvider::RegisterPublishFormCrossBundleControl);
    BindNativeFunction(env, exports, "offPublishFormCrossBundleControl", moduleName,
        JsFormProvider::UnregisterPublishFormCrossBundleControl);
    return exports;
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
    return JsProviderInit(env, exports);
}

EXTERN_C_END

// Define a Node-API module.
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "app.form.formProvider",
    .nm_priv = nullptr,
    .reserved = { nullptr }
};

// Registers a Node-API module.
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}