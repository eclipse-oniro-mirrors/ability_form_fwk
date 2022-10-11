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

#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <unistd.h>

#include "hilog_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_node_api.h"
#include "napi_form_host.h"

EXTERN_C_START
using namespace OHOS::AbilityRuntime;

static NativeValue* NapiFormHostInit(NativeEngine *engine, NativeValue *exports)
{
    HILOG_DEBUG("NapiFormHostInit is called");
    if (engine == nullptr || exports == nullptr) {
        HILOG_ERROR("Invalid input parameters");
        return nullptr;
    }

    NativeObject *object = OHOS::AbilityRuntime::ConvertNativeValueTo<NativeObject>(exports);
    if (object == nullptr) {
        HILOG_ERROR("object is nullptr");
        return nullptr;
    }

    std::unique_ptr<NapiFormHost> napiFormHost = std::make_unique<NapiFormHost>();
    object->SetNativePointer(napiFormHost.release(), NapiFormHost::Finalizer, nullptr);

    const char *moduleName = "NapiFormHost";
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "shareForm", moduleName, NapiFormHost::ShareForm);
    OHOS::AbilityRuntime::BindNativeFunction(
        *engine, *object, "disableFormsUpdate", moduleName, NapiFormHost::DisableFormsUpdate);
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "isSystemReady", moduleName, NapiFormHost::IsSystemReady);
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "deleteForm", moduleName, NapiFormHost::DeleteForm);
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "releaseForm", moduleName, NapiFormHost::ReleaseForm);
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "requestForm", moduleName, NapiFormHost::RequestForm);
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "castTempForm", moduleName, NapiFormHost::CastTempForm);
    OHOS::AbilityRuntime::BindNativeFunction(
        *engine, *object, "getAllFormsInfo", moduleName, NapiFormHost::GetAllFormsInfo);
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "getFormsInfo", moduleName, NapiFormHost::GetFormsInfo);
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "enableFormsUpdate", moduleName,
        NapiFormHost::EnableFormsUpdate);
    OHOS::AbilityRuntime::BindNativeFunction(*engine, *object, "notifyFormsPrivacyProtected",
        moduleName, NapiFormHost::NotifyFormsPrivacyProtected);

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
        DECLARE_NAPI_FUNCTION("notifyVisibleForms", NAPI_NotifyVisibleForms),
        DECLARE_NAPI_FUNCTION("notifyInvisibleForms", NAPI_NotifyInvisibleForms),
        DECLARE_NAPI_FUNCTION("deleteInvalidForms", NAPI_DeleteInvalidForms),
        DECLARE_NAPI_FUNCTION("acquireFormState", NAPI_AcquireFormState),
        DECLARE_NAPI_FUNCTION("on", NAPI_RegisterFormUninstallObserver),
        DECLARE_NAPI_FUNCTION("off", NAPI_UnregisterFormUninstallObserver),
        DECLARE_NAPI_FUNCTION("notifyFormsVisible", NAPI_NotifyFormsVisible),
        DECLARE_NAPI_FUNCTION("notifyFormsEnableUpdate", NAPI_NotifyFormsEnableUpdate),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));
    HILOG_INFO("napi_module Init end...");

    return reinterpret_cast<napi_value>(NapiFormHostInit(reinterpret_cast<NativeEngine*>(env),
        reinterpret_cast<NativeValue*>(exports)));
}

EXTERN_C_END

// Define a Node-API module.
static napi_module _module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = Init,
    .nm_modname = "application.formHost",
    .nm_priv = ((void *)0),
    .reserved = {0}
};

// Registers a Node-API module.
extern "C" __attribute__((constructor)) void RegisterModule(void)
{
    napi_module_register(&_module);
}