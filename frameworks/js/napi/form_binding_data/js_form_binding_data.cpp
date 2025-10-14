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
#include "js_form_binding_data.h"

#include "fms_log_wrapper.h"
#include "form_provider_data.h"
#include "js_runtime_utils.h"
#include "napi_form_util.h"

namespace OHOS {
namespace AbilityRuntime {
#define ARGS_MAX_COUNT 10
namespace {
class JsFormBindingData {
public:
    JsFormBindingData() = default;
    ~JsFormBindingData() = default;

    static void Finalizer(napi_env env, void* data, void* hint)
    {
        HILOG_INFO("call");
        std::unique_ptr<JsFormBindingData>(static_cast<JsFormBindingData*>(data));
    }

    static napi_value CreateFormBindingData(napi_env env, napi_callback_info info)
    {
        GET_CB_INFO_AND_CALL(env, info, JsFormBindingData, OnCreateFormBindingData);
    }
private:
    napi_value OnCreateFormBindingData(napi_env env, size_t argc, napi_value* argv);
};

napi_value JsFormBindingData::OnCreateFormBindingData(napi_env env, size_t argc, napi_value* argv)
{
    std::string formDataStr;
    if (argc > 0) {
        napi_value nativeValue = nullptr;
        napi_valuetype type = napi_undefined;
        napi_typeof(env, argv[0], &type);
        if (type == napi_string) {
            nativeValue = argv[0];
        } else if (type == napi_object) {
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
        }
        ConvertFromJsValue(env, nativeValue, formDataStr);
    }
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    napi_set_named_property(env, objValue, "data", CreateJsValue(env, formDataStr));
    return objValue;
}
}

napi_value JsFormBindingDataInit(napi_env env, napi_value exportObj)
{
    HILOG_DEBUG("call");

    auto formBindingData = std::make_unique<JsFormBindingData>();
    napi_wrap(env, exportObj, formBindingData.release(), JsFormBindingData::Finalizer, nullptr, nullptr);

    const char *moduleName = "JsFormBindingData";
    BindNativeFunction(env, exportObj, "createFormBindingData", moduleName, JsFormBindingData::CreateFormBindingData);

    HILOG_INFO("end");
    return exportObj;
}
} // namespace AbilityRuntime
} // namespace OHOS
