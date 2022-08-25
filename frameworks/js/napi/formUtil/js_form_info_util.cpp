/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "hilog_wrapper.h"
#include "js_runtime_utils.h"
#include "napi_form_util.h"

namespace OHOS {
namespace AbilityRuntime {
EXTERN_C_START

bool ConvertFormInfoFilter(NativeEngine &engine, NativeValue* jsValue, AppExecFwk::FormInfoFilter &formInfoFilter)
{
    if (jsValue->TypeOf() != NATIVE_OBJECT) {
        HILOG_ERROR("%{public}s, an object is expected, but an argument of different type is passed in.", __func__);
        return false;
    }

    NativeObject* nativeObject = ConvertNativeValueTo<NativeObject>(jsValue);
    if (nativeObject == nullptr) {
        HILOG_ERROR("%{public}s called, nativeObject is nullptr.", __func__);
        return false;
    }
    NativeValue* nativeDataValue = nativeObject->GetProperty("moduleName");
    if (nativeDataValue == nullptr || (nativeDataValue->TypeOf() != NATIVE_UNDEFINED &&
        !ConvertFromJsValue(engine, nativeDataValue, formInfoFilter.moduleName))) {
        HILOG_ERROR("%{public}s called, convert nativeDataValue failed.", __func__);
        return false;
    }
    HILOG_INFO("%{public}s called, module name is %{public}s.", __func__, formInfoFilter.moduleName.c_str());

    return true;
}

NativeValue* CreateJsFormInfo(NativeEngine &engine, const AppExecFwk::FormInfo &formInfo)
{
    NativeValue* objValue = engine.CreateObject();
    napi_value napiValue = reinterpret_cast<napi_value>(objValue);
    ParseFormInfoIntoNapi(reinterpret_cast<napi_env>(&engine), formInfo, napiValue);
    return objValue;
}

NativeValue* CreateJsFormInfoArray(NativeEngine &engine, const std::vector<AppExecFwk::FormInfo> &formInfos)
{
    NativeValue* arrayValue = engine.CreateArray(formInfos.size());
    NativeArray* array = ConvertNativeValueTo<NativeArray>(arrayValue);
    uint32_t index = 0;
    for (const auto &formInfo : formInfos) {
        array->SetElement(index++, CreateJsFormInfo(engine, formInfo));
    }
    return arrayValue;
}
} // namespace AppExecFwk
} // namespace OHOS
EXTERN_C_END