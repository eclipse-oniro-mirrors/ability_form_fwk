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

#include "fms_log_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_node_api.h"
#include "napi_form_host.h"

EXTERN_C_START
using namespace OHOS::AbilityRuntime;

static napi_value NapiFormHostInit(napi_env env, napi_value exports)
{
    HILOG_DEBUG("NapiFormHostInit is called");
    if (env == nullptr || exports == nullptr) {
        HILOG_ERROR("Invalid input parameters");
        return nullptr;
    }

    std::unique_ptr<NapiFormHost> napiFormHost = std::make_unique<NapiFormHost>();
    napi_wrap(env, exports, napiFormHost.release(), NapiFormHost::Finalizer, nullptr, nullptr);

    const char *moduleName = "NapiFormHost";
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "shareForm", moduleName, NapiFormHost::ShareForm);
    OHOS::AbilityRuntime::BindNativeFunction(
        env, exports, "disableFormsUpdate", moduleName, NapiFormHost::DisableFormsUpdate);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "isSystemReady", moduleName, NapiFormHost::IsSystemReady);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "deleteForm", moduleName, NapiFormHost::DeleteForm);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "releaseForm", moduleName, NapiFormHost::ReleaseForm);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "requestForm", moduleName, NapiFormHost::RequestForm);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "castTempForm", moduleName, NapiFormHost::CastTempForm);
    OHOS::AbilityRuntime::BindNativeFunction(
        env, exports, "getAllFormsInfo", moduleName, NapiFormHost::GetAllFormsInfo);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "getFormsInfo", moduleName, NapiFormHost::GetFormsInfo);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "enableFormsUpdate", moduleName,
        NapiFormHost::EnableFormsUpdate);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "notifyFormsPrivacyProtected",
        moduleName, NapiFormHost::NotifyFormsPrivacyProtected);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "notifyVisibleForms",
        moduleName, NapiFormHost::NotifyVisibleForms);
    OHOS::AbilityRuntime::BindNativeFunction(env, exports, "notifyInvisibleForms",
        moduleName, NapiFormHost::NotifyInVisibleForms);
    OHOS::AbilityRuntime::BindNativeFunction(
        env, exports, "deleteInvalidForms", moduleName, NapiFormHost::DeleteInvalidForms);

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
        DECLARE_NAPI_FUNCTION("acquireFormState", NAPI_AcquireFormState),
        DECLARE_NAPI_FUNCTION("on", NAPI_RegisterFormUninstallObserver),
        DECLARE_NAPI_FUNCTION("off", NAPI_UnregisterFormUninstallObserver),
        DECLARE_NAPI_FUNCTION("notifyFormsVisible", NAPI_NotifyFormsVisible),
        DECLARE_NAPI_FUNCTION("notifyFormsEnableUpdate", NAPI_NotifyFormsEnableUpdate),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));
    HILOG_INFO("napi_module Init end...");

    return NapiFormHostInit(env, exports);
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