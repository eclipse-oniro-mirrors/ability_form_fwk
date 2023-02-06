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

#include "js_form_provider.h"

#include <cinttypes>
#include <vector>

#include "form_mgr_errors.h"
#include "form_mgr.h"
#include "js_form_info_util.h"
#include "js_runtime_utils.h"
#include "hilog_wrapper.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_form_util.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
namespace {
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;

bool ConvertFormInfoFilterThrow(NativeEngine &engine, NativeValue *jsValue, AppExecFwk::FormInfoFilter &formInfoFilter)
{
    if (jsValue->TypeOf() != NATIVE_OBJECT) {
        HILOG_ERROR("%{public}s, an object is expected, but an argument of different type is passed in.", __func__);
        NapiFormUtil::ThrowParamTypeError(engine, "filter", "formInfo.FormInfoFilter");
        return false;
    }

    NativeObject *nativeObject = ConvertNativeValueTo<NativeObject>(jsValue);
    if (nativeObject == nullptr) {
        HILOG_ERROR("%{public}s called, nativeObject is nullptr.", __func__);
        NapiFormUtil::ThrowParamError(engine, "Failed to convert FormInfoFilter.");
        return false;
    }
    NativeValue *nativeDataValue = nativeObject->GetProperty("moduleName");
    if (nativeDataValue == nullptr || (nativeDataValue->TypeOf() != NATIVE_UNDEFINED &&
                                       !ConvertFromJsValue(engine, nativeDataValue, formInfoFilter.moduleName))) {
        HILOG_ERROR("%{public}s called, convert nativeDataValue failed.", __func__);
        NapiFormUtil::ThrowParamError(engine, "Failed to convert FormInfoFilter.");
        return false;
    }
    HILOG_INFO("%{public}s called, module name is %{public}s.", __func__, formInfoFilter.moduleName.c_str());

    return true;
}
}

static std::string GetStringByProp(napi_env env, napi_value value, const std::string &prop)
{
    std::string result;
    bool propExist = false;
    napi_value propValue = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_has_named_property(env, value, prop.c_str(), &propExist);
    if (!propExist) {
        HILOG_ERROR("%{public}s, prop[%{public}s] not exist.", __func__, prop.c_str());
        return result;
    }
    napi_get_named_property(env, value, prop.c_str(), &propValue);
    if (propValue == nullptr) {
        HILOG_ERROR("%{public}s, prop[%{public}s] get failed.", __func__, prop.c_str());
        return result;
    }
    napi_typeof(env, propValue, &valueType);
    if (valueType != napi_string) {
        HILOG_ERROR("%{public}s, prop[%{public}s] is not napi_string.", __func__, prop.c_str());
        return result;
    }
    size_t size = 0;
    if (napi_get_value_string_utf8(env, propValue, nullptr, 0, &size) != napi_ok) {
        HILOG_ERROR("%{public}s, prop[%{public}s] get size failed.", __func__, prop.c_str());
        return result;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, propValue, result.data(), (size + 1), &size) != napi_ok) {
        HILOG_ERROR("%{public}s, prop[%{public}s] get value failed.", __func__, prop.c_str());
        return "";
    }
    return result;
}

void JsFormProvider::Finalizer(NativeEngine *engine, void *data, void *hint)
{
    HILOG_INFO("JsFormProvider::Finalizer is called");
    std::unique_ptr<JsFormProvider>(static_cast<JsFormProvider *>(data));
}

NativeValue *JsFormProvider::GetFormsInfo(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsFormProvider *me = CheckParamsAndGetThis<JsFormProvider>(engine, info);
    return (me != nullptr) ? me->OnGetFormsInfo(*engine, *info) : nullptr;
}

NativeValue *JsFormProvider::OnGetFormsInfo(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (info.argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "0, 1 or 2");
        return engine.CreateUndefined();
    }

    size_t convertArgc = 0;
    FormInfoFilter formInfoFilter;
    if (info.argc > 0 && info.argv[0]->TypeOf() != NATIVE_FUNCTION) {
        if (!ConvertFormInfoFilterThrow(engine, info.argv[0], formInfoFilter)) {
            HILOG_ERROR("%{public}s, convert form info filter failed.", __func__);
            return engine.CreateUndefined();
        }
        convertArgc++;
    }

    AsyncTask::CompleteCallback complete =
        [formInfoFilter](NativeEngine &engine, AsyncTask &task, int32_t status) {
            std::vector<FormInfo> formInfos;
            auto ret = FormMgr::GetInstance().GetFormsInfo(formInfoFilter, formInfos);
            if (ret != ERR_OK) {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
                return;
            }
            task.ResolveWithNoError(engine, CreateJsFormInfoArray(engine, formInfos));
        };

    NativeValue *lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsFormProvider::OnGetFormsInfo",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue *JsFormProvider::SetFormNextRefreshTime(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsFormProvider *me = CheckParamsAndGetThis<JsFormProvider>(engine, info);
    return (me != nullptr) ? me->OnSetFormNextRefreshTime(*engine, *info) : nullptr;
}

NativeValue *JsFormProvider::OnSetFormNextRefreshTime(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (info.argc < ARGS_SIZE_TWO || info.argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("wrong number of arguments.");
        NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "2 or 3");
        return engine.CreateUndefined();
    }
    if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
        HILOG_ERROR("formId is not napi_string.");
        NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
        return engine.CreateUndefined();
    }
    int64_t formId = 0;
    std::string strFormId;
    bool confirm = ConvertFromJsValue(engine, info.argv[PARAM0], strFormId);
    if (!confirm) {
        HILOG_ERROR("ConvertFromJsValue failed.");
        NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
        return engine.CreateUndefined();
    }
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert form string failed.");
        NapiFormUtil::ThrowParamError(engine, "Failed to convert formId.");
        return engine.CreateUndefined();
    }
    if (info.argv[PARAM1]->TypeOf() != NATIVE_NUMBER) {
        NapiFormUtil::ThrowParamTypeError(engine, "minute", "number");
        return engine.CreateUndefined();
    }
    int32_t time;
    bool res = ConvertFromJsValue(engine, info.argv[PARAM1], time);
    if (!res) {
        HILOG_ERROR("ConvertFromJsValue failed.");
        NapiFormUtil::ThrowParamTypeError(engine, "minute", "number");
        return engine.CreateUndefined();
    }
    AsyncTask::CompleteCallback complete = [formId, time](NativeEngine &engine, AsyncTask &task, int32_t status) {
        int32_t ret = FormMgr::GetInstance().SetNextRefreshTime(formId, time);
        if (ret != ERR_OK) {
            task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            return;
        }
        task.ResolveWithNoError(engine, engine.CreateUndefined());
    };
    NativeValue *lastParam = (info.argc == ARGS_SIZE_THREE) ? info.argv[PARAM2] : nullptr;
    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsFormProvider::OnSetFormNextRefreshTime",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue *JsFormProvider::UpdateForm(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsFormProvider *me = CheckParamsAndGetThis<JsFormProvider>(engine, info);
    return (me != nullptr) ? me->OnUpdateForm(*engine, *info) : nullptr;
}

NativeValue *JsFormProvider::OnUpdateForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    auto env = reinterpret_cast<napi_env>(&engine);
    if (info.argc < ARGS_SIZE_TWO || info.argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("wrong number of arguments.");
        NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "2 or 3");
        return engine.CreateUndefined();
    }
    if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
        HILOG_ERROR("formId is not napi_string.");
        NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
        return engine.CreateUndefined();
    }
    int64_t formId = 0;
    std::string strFormId;
    bool confirm = ConvertFromJsValue(engine, info.argv[PARAM0], strFormId);
    if (!confirm) {
        HILOG_ERROR("ConvertFromJsValue failed.");
        NapiFormUtil::ThrowParamTypeError(engine, "formId", "string");
        return engine.CreateUndefined();
    }
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert form string failed.");
        NapiFormUtil::ThrowParamError(engine, "Failed to convert formId.");
        return engine.CreateUndefined();
    }
    if (info.argv[PARAM1]->TypeOf() != NATIVE_OBJECT) {
        HILOG_ERROR("formBindingData is not napi_object.");
        NapiFormUtil::ThrowParamTypeError(engine, "formBindingData", "formBindingData.FormBindingData");
        return engine.CreateUndefined();
    }
    auto formProviderData = std::make_shared<OHOS::AppExecFwk::FormProviderData>();
    auto arg1 = reinterpret_cast<napi_value>(info.argv[PARAM1]);
    std::string formDataStr = GetStringByProp(env, arg1, "data");
    formProviderData->SetDataString(formDataStr);
    formProviderData->ParseImagesData();
    AsyncTask::CompleteCallback complete =
        [formId, data = formProviderData](NativeEngine &engine, AsyncTask &task, int32_t status) {
            int32_t ret = FormMgr::GetInstance().UpdateForm(formId, *data);
            if (ret != ERR_OK) {
                task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
                return;
            }
            task.ResolveWithNoError(engine, engine.CreateUndefined());
        };
    NativeValue *lastParam = (info.argc == ARGS_SIZE_THREE) ? info.argv[PARAM2] : nullptr;
    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsFormProvider::OnUpdateForm",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue *JsFormProvider::IsRequestPublishFormSupported(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsFormProvider *me = CheckParamsAndGetThis<JsFormProvider>(engine, info);
    return (me != nullptr) ? me->OnIsRequestPublishFormSupported(*engine, *info) : nullptr;
}

NativeValue *JsFormProvider::OnIsRequestPublishFormSupported(NativeEngine &engine, const NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (info.argc > ARGS_SIZE_ONE) {
        HILOG_ERROR("wrong number of arguments.");
        NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "0 or 1");
        return engine.CreateUndefined();
    }

    AsyncTask::CompleteCallback complete = [](NativeEngine &engine, AsyncTask &task, int32_t status) {
        bool value = FormMgr::GetInstance().IsRequestPublishFormSupported();
        task.ResolveWithNoError(engine, engine.CreateBoolean(value));
    };
    NativeValue *lastParam = (info.argc == ARGS_SIZE_ONE) ? info.argv[PARAM0] : nullptr;
    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsFormProvider::OnIsRequestPublishFormSupported",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue *JsFormProvider::RequestPublishForm(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsFormProvider *me = CheckParamsAndGetThis<JsFormProvider>(engine, info);
    return (me != nullptr) ? me->OnRequestPublishForm(*engine, *info) : nullptr;
}

NativeValue *JsFormProvider::OnRequestPublishForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    auto env = reinterpret_cast<napi_env>(&engine);
    if (info.argc < ARGS_SIZE_ONE || info.argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("wrong number of arguments.");
        NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1, 2 or 3");
        return engine.CreateUndefined();
    }

    auto asyncCallbackInfo = std::make_shared<RequestPublishFormCallbackInfo>();
    decltype(info.argc) convertArgc = 0;
    if (info.argv[PARAM0]->TypeOf() != NATIVE_OBJECT) {
        HILOG_ERROR("formId is not napi_object.");
        NapiFormUtil::ThrowParamTypeError(engine, "want", "Want");
        return engine.CreateUndefined();
    }
    if (!AppExecFwk::UnwrapWant(env, reinterpret_cast<napi_value>(info.argv[PARAM0]), asyncCallbackInfo->want)) {
        HILOG_ERROR("Failed to convert want.");
        NapiFormUtil::ThrowParamError(engine, "Failed to convert want.");
        return engine.CreateUndefined();
    }
    convertArgc++;

    if (info.argc > ARGS_SIZE_ONE) {
        asyncCallbackInfo->withFormBindingData = true;
        if (info.argv[PARAM1]->TypeOf() != NATIVE_OBJECT) {
            HILOG_ERROR("formBindingData is not napi_object.");
            NapiFormUtil::ThrowParamTypeError(engine, "formBindingData", "formBindingData.FormBindingData");
            return engine.CreateUndefined();
        }
        auto formProviderData = std::make_unique<FormProviderData>();
        auto arg1 = reinterpret_cast<napi_value>(info.argv[PARAM1]);
        std::string formDataStr = GetStringByProp(env, arg1, "data");
        formProviderData->SetDataString(formDataStr);
        formProviderData->ParseImagesData();
        asyncCallbackInfo->formProviderData = std::move(formProviderData);
        convertArgc++;
    }

    AsyncTask::CompleteCallback complete = [asyncCallbackInfo](NativeEngine &engine, AsyncTask &task, int32_t status) {
        int64_t formId = 0;
        ErrCode ret = FormMgr::GetInstance().RequestPublishForm(asyncCallbackInfo->want,
            asyncCallbackInfo->withFormBindingData, asyncCallbackInfo->formProviderData, formId);
        if (ret != ERR_OK) {
            task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            return;
        }
        std::string formIdStr = std::to_string(formId);
        task.ResolveWithNoError(engine, engine.CreateString(formIdStr.c_str(), formIdStr.size()));
    };
    NativeValue *lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsFormProvider::OnRequestPublishForm",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
