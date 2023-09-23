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

#include "js_form_info_util.h"

#include "fms_log_wrapper.h"
#include "js_runtime_utils.h"
#include "napi_form_util.h"

namespace OHOS {
namespace AbilityRuntime {
EXTERN_C_START

bool ConvertFormInfoFilter(napi_env env, napi_value value, AppExecFwk::FormInfoFilter &formInfoFilter)
{
    napi_valuetype type = napi_undefined;
    napi_typeof(env, value, &type);
    if (type != napi_object) {
        HILOG_ERROR("%{public}s, an object is expected, but an argument of different type is passed in.", __func__);
        return false;
    }

    napi_value nativeDataValue = nullptr;
    napi_get_named_property(env, value, "moduleName", &nativeDataValue);
    napi_valuetype nativeDataValueType = napi_undefined;
    napi_typeof(env, nativeDataValue, &nativeDataValueType);
    if (nativeDataValue == nullptr || (nativeDataValueType != napi_undefined &&
        !ConvertFromJsValue(env, nativeDataValue, formInfoFilter.moduleName))) {
        HILOG_ERROR("%{public}s called, convert nativeDataValue failed.", __func__);
        return false;
    }
    HILOG_INFO("%{public}s called, module name is %{public}s.", __func__, formInfoFilter.moduleName.c_str());

    return true;
}

napi_value CreateJsFormInfo(napi_env env, const AppExecFwk::FormInfo &formInfo)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    ParseFormInfoIntoNapi(env, formInfo, objValue);
    return objValue;
}

napi_value CreateJsFormInfoArray(napi_env env, const std::vector<AppExecFwk::FormInfo> &formInfos)
{
    napi_value arrayValue = nullptr;
    napi_create_array_with_length(env, formInfos.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto &formInfo : formInfos) {
        napi_set_element(env, arrayValue, index++, CreateJsFormInfo(env, formInfo));
    }
    return arrayValue;
}
} // namespace AppExecFwk
} // namespace OHOS
EXTERN_C_END