/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "form_binding_data.h"

#include "fms_log_wrapper.h"
#include "form_provider_data.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityRuntime {
#define ARGS_MAX_COUNT 10
namespace {
class FormBindingData {
public:
    explicit FormBindingData(const std::shared_ptr<AppExecFwk::FormProviderData>& formProviderData)
        : formProviderData_(formProviderData) {}
    ~FormBindingData() = default;

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        HILOG_INFO("FormBindingData::Finalizer is called");
        std::unique_ptr<FormBindingData>(static_cast<FormBindingData*>(data));
    }

    static napi_value CreateFormBindingData(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, FormBindingData, OnCreateFormBindingData);
    }
private:
    napi_value OnCreateFormBindingData(napi_env env, size_t argc, napi_value* argv);
    std::shared_ptr<AppExecFwk::FormProviderData> formProviderData_;
};

napi_value FormBindingData::OnCreateFormBindingData(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::string formDataStr;
    if (argc > 0) {
        napi_value nativeValue = nullptr;
        napi_valuetype type = napi_undefined;
        napi_typeof(env, argv[0], &type);
        if (type == napi_string) {
            HILOG_DEBUG("%{public}s called, param type is string.", __func__);
            nativeValue = argv[0];
        } else if (type == napi_object) {
            HILOG_DEBUG("%{public}s called, param type is object.", __func__);
            napi_value globalValue = nullptr;
            napi_get_global(env, &globalValue);
            napi_value jsonValue;
            napi_get_named_property(env, globalValue, "JSON", &jsonValue);

            napi_value stringifyValue = nullptr;
            napi_get_named_property(env, jsonValue, "stringify", &stringifyValue);
            napi_value funcArgv[1] = { argv[0] };
            napi_value transValue = nullptr;
            napi_call_function(env, jsonValue, stringifyValue, 1, funcArgv, &transValue);
            nativeValue = transValue;
        } else {
            HILOG_ERROR("%{public}s, param type not string or object", __func__);
            return CreateJsUndefined(env);
        }

        if (!ConvertFromJsValue(env, nativeValue, formDataStr)) {
            HILOG_ERROR("%{public}s, Parse formDataStr failed", __func__);
            return CreateJsUndefined(env);
        }
    }
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    formProviderData_->SetDataString(formDataStr);
    napi_set_named_property(env, objValue, "data", CreateJsValue(env, formDataStr));
    HILOG_DEBUG("%{public}s called:%{private}s", __func__, formDataStr.c_str());
    return objValue;
}
}

napi_value FormBindingDataInit(napi_env env, napi_value exportObj)
{
    HILOG_INFO("%{public}s called.", __func__);

    auto formProviderData = std::make_shared<AppExecFwk::FormProviderData>();
    auto formBindingData = std::make_unique<FormBindingData>(formProviderData);
    napi_wrap(env, exportObj, formBindingData.release(), FormBindingData::Finalizer, nullptr, nullptr);

    const char *moduleName = "FormBindingData";
    BindNativeFunction(env, exportObj, "createFormBindingData", moduleName, FormBindingData::CreateFormBindingData);

    HILOG_INFO("%{public}s called end.", __func__);
    return exportObj;
}
} // namespace AbilityRuntime
} // namespace OHOS
