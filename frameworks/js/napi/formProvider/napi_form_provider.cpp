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

#include "napi_form_provider.h"

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
    constexpr size_t ARGS_SIZE_ZERO = 0;
    constexpr size_t ARGS_SIZE_ONE = 1;
    constexpr size_t ARGS_SIZE_TWO = 2;
    constexpr size_t ARGS_SIZE_THREE = 3;
    constexpr int REF_COUNT = 1;
    constexpr int CALLBACK_FLG = 1;
    constexpr int PROMISE_FLG = 2;
    const std::string MODULE_NAME = "moduleName";
}

napi_value ExecuteAsyncCallbackWork(napi_env env, AsyncCallbackInfoBase* asyncCallbackInfo)
{
    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr, nullptr};
        // store return-message to callbackValues[0].
        InnerCreateCallbackRetMsg(env, ERR_APPEXECFWK_FORM_COMMON_CODE, callbackValues);
        napi_value callback;
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_value callResult;
        // call.
        napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
        napi_delete_reference(env, asyncCallbackInfo->callback);
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        asyncCallbackInfo = nullptr;
    }
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    return result;
}

void ExecuteAsyncPromiseWork(napi_env env, AsyncCallbackInfoBase* asyncCallbackInfo)
{
    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        napi_value error;
        InnerCreatePromiseRetMsg(env, ERR_APPEXECFWK_FORM_COMMON_CODE, &error);
        napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, error);
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        asyncCallbackInfo = nullptr;
    }
}

static std::string GetStringByProp(napi_env env, napi_value value, const std::string& prop)
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

static void InnerRequestPublishForm(napi_env env, AsyncRequestPublishFormCallbackInfo *const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    if (FormMgr::GetRecoverStatus() == Constants::IN_RECOVERING) {
        HILOG_ERROR("%{public}s error, form is in recover status, can't do action on form.", __func__);
        asyncCallbackInfo->result = ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR;
        return;
    }

    ErrCode errCode = FormMgr::GetInstance().RequestPublishForm(asyncCallbackInfo->want,
        asyncCallbackInfo->withFormBindingData, asyncCallbackInfo->formProviderData, asyncCallbackInfo->formId);
    if (errCode != ERR_OK) {
        HILOG_ERROR("Failed to RequestPublishForm, error code is %{public}d.", errCode);
    }
    asyncCallbackInfo->result = errCode;
    HILOG_DEBUG("%{public}s, end", __func__);
}

static ErrCode RequestPublishFormParse(napi_env env, napi_value *argv,
                                       AsyncRequestPublishFormCallbackInfo *asyncCallbackInfo)
{
    bool parseResult = UnwrapWant(env, argv[0], asyncCallbackInfo->want);
    if (!parseResult) {
        HILOG_ERROR("%{public}s, failed to parse want.", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (asyncCallbackInfo->withFormBindingData) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[1], &valueType);
        if (valueType != napi_object) {
            HILOG_ERROR("%{public}s, wrong type for argv[1].", __func__);
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        auto formProviderData = std::make_unique<FormProviderData>();
        std::string formDataStr = GetStringByProp(env, argv[1], "data");
        formProviderData->SetDataString(formDataStr);
        formProviderData->ParseImagesData();
        asyncCallbackInfo->formProviderData = std::move(formProviderData);
    }

    return ERR_OK;
}

static napi_value RequestPublishFormCallback(napi_env env, napi_value *argv, bool withFormBindingData)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);

    int32_t callbackIdx = 1;
    if (withFormBindingData) {
        callbackIdx++;
    }
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[callbackIdx], &valueType));
    if (valueType != napi_function) {
        HILOG_ERROR("The arguments[1] type of requestPublishForm is incorrect, expected type is function.");
        return nullptr;
    }

    auto *asyncCallbackInfo = new (std::nothrow) AsyncRequestPublishFormCallbackInfo {
        .env = env,
        .withFormBindingData = withFormBindingData,
    };
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr");
        return nullptr;
    }

    ErrCode errCode = RequestPublishFormParse(env, argv, asyncCallbackInfo);
    if (errCode != ERR_OK) {
        delete asyncCallbackInfo;
        return RetErrMsg(InitErrMsg(env, errCode, CALLBACK_FLG, argv[callbackIdx]));
    }
    napi_create_reference(env, argv[callbackIdx], REF_COUNT, &asyncCallbackInfo->callback);

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncRequestPublishFormCallbackInfo *) data;
            InnerRequestPublishForm(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncRequestPublishFormCallbackInfo *) data;

            if (asyncCallbackInfo->callback != nullptr) {
                napi_value callback;
                napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr, nullptr};
                InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, callbackValues);
                if (asyncCallbackInfo->result == ERR_OK) {
                    std::string strFormId = std::to_string(asyncCallbackInfo->formId);
                    napi_value formId;
                    napi_create_string_utf8(env, strFormId.c_str(), strFormId.length(), &formId);
                    callbackValues[1] = formId;
                }

                napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                napi_value callResult;
                napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
                napi_delete_reference(env, asyncCallbackInfo->callback);
            }

            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

static napi_value RequestPublishFormPromise(napi_env env, napi_value *argv, bool withFormBindingData)
{
    HILOG_INFO("%{public}s, promise.", __func__);
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    auto *asyncCallbackInfo = new (std::nothrow) AsyncRequestPublishFormCallbackInfo {
        .env = env,
        .deferred = deferred,
        .withFormBindingData = withFormBindingData,
    };
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr");
        return nullptr;
    }

    ErrCode errCode = RequestPublishFormParse(env, argv, asyncCallbackInfo);
    if (errCode != ERR_OK) {
        delete asyncCallbackInfo;
        return RetErrMsg(InitErrMsg(env, errCode, PROMISE_FLG, nullptr));
    }

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise running", __func__);
            auto *asyncCallbackInfo = (AsyncRequestPublishFormCallbackInfo *) data;
            if (asyncCallbackInfo) {
                InnerRequestPublishForm(env, asyncCallbackInfo);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncRequestPublishFormCallbackInfo *) data;
            napi_value result;
            if (asyncCallbackInfo) {
                if (asyncCallbackInfo->result == ERR_OK) {
                    std::string strFormId = std::to_string(asyncCallbackInfo->formId);
                    napi_create_string_utf8(env, strFormId.c_str(), strFormId.length(), &result);
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            }
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: requestPinForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_RequestPublishForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);
    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr, nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    if (argc < ARGS_SIZE_TWO) {
        // promise, no form binding data
        return RequestPublishFormPromise(env, argv, false);
    } else if (argc > ARGS_SIZE_TWO) {
        // callback, with form binding data
        return RequestPublishFormCallback(env, argv, true);
    } else {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        if (valueType == napi_function) {
            // callback, no form binding data
            return RequestPublishFormCallback(env, argv, false);
        } else {
            // promise, with form binding data
            return RequestPublishFormPromise(env, argv, true);
        }
    }
}

static void InnerIsRequestPublishFormSupported(napi_env env,
    AsyncIsRequestPublishFormSupportedCallbackInfo *asyncCallbackInfo)
{
    HILOG_INFO("InnerIsRequestPublishFormSupported called");
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("InnerIsRequestPublishFormSupported data is a nullptr");
        return;
    }
    bool value = FormMgr::GetInstance().IsRequestPublishFormSupported();
    asyncCallbackInfo->result = value;
}

// callback version of NAPI_IsRequestPublishFormSupported
static napi_value IsRequestPublishFormSupportedCallback(napi_env env, napi_value argv,
    AsyncIsRequestPublishFormSupportedCallbackInfo *asyncCallbackInfo)
{
    HILOG_INFO("%{public}s starts.", __func__);
    // Check the type of the argv, expect to be a callback function.
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv, &valueType));
    if (valueType != napi_function) {
        HILOG_ERROR("IsRequestPublishFormSupportedCallback callback is not a function");
        return nullptr;
    }
    // store callback function that user passed in.
    napi_create_reference(env, argv, REF_COUNT, &asyncCallbackInfo->callback);
    // create resource name as Identifier to provide diagnostic information.
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            // entry to the core of this functionality.
            auto *asyncCallbackInfo = static_cast<AsyncIsRequestPublishFormSupportedCallbackInfo *>(data);
            InnerIsRequestPublishFormSupported(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("IsRequestPublishFormSupportedCallback callback completed");
            if (data == nullptr) {
                HILOG_ERROR("IsRequestPublishFormSupportedCallback data is a nullptr");
                return;
            }
            AsyncIsRequestPublishFormSupportedCallbackInfo *asyncCallbackInfo =
                static_cast<AsyncIsRequestPublishFormSupportedCallbackInfo *>(data);

            // call user provided callback function.
            if (asyncCallbackInfo->callback != nullptr) {
                napi_value callbackValues[ARGS_SIZE_TWO] = {0};
                napi_value callback;
                // store return-message to callbackValues[0].
                InnerCreateCallbackRetMsg(env, ERR_OK, callbackValues);
                // store result
                napi_value result;
                napi_get_boolean(env, asyncCallbackInfo->result, &result);
                callbackValues[1] = result;
                napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                napi_value callResult;
                // call.
                napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
                napi_delete_reference(env, asyncCallbackInfo->callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    return ExecuteAsyncCallbackWork(env, asyncCallbackInfo);
}

static napi_value IsRequestPublishFormSupportedPromise(napi_env env,
    AsyncIsRequestPublishFormSupportedCallbackInfo *asyncCallbackInfo)
{
    HILOG_INFO("%{public}s calls.", __func__);
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;
    // create resource name as Identifier to provide diagnostic information.
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            auto *asyncCallbackInfo = static_cast<AsyncIsRequestPublishFormSupportedCallbackInfo *>(data);
            InnerIsRequestPublishFormSupported(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("IsRequestPublishFormSupportedPromise completed");
            if (data == nullptr) {
                HILOG_ERROR("IsRequestPublishFormSupportedPromise data is a nullptr");
                return;
            }
            AsyncIsRequestPublishFormSupportedCallbackInfo *asyncCallbackInfo =
                static_cast<AsyncIsRequestPublishFormSupportedCallbackInfo *>(data);
            napi_value result;
            napi_get_boolean(env, asyncCallbackInfo->result, &result);
            napi_resolve_deferred(
                asyncCallbackInfo->env,
                asyncCallbackInfo->deferred,
                result);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    ExecuteAsyncPromiseWork(env, asyncCallbackInfo);
    return promise;
}

napi_value NAPI_IsRequestPublishFormSupported(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s starts.", __func__);
    // Check the number of the arguments.
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_ONE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }

    auto *asyncCallbackInfo = new (std::nothrow) AsyncIsRequestPublishFormSupportedCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr");
        return nullptr;
    }
    // callback
    if (argc == ARGS_SIZE_ONE) {
        return IsRequestPublishFormSupportedCallback(env, argv[ARGS_SIZE_ZERO], asyncCallbackInfo);
    }
    return IsRequestPublishFormSupportedPromise(env, asyncCallbackInfo);
}

void JsFormProvider::Finalizer(NativeEngine* engine, void* data, void* hint)
{
    HILOG_INFO("JsFormProvider::Finalizer is called");
    std::unique_ptr<JsFormProvider>(static_cast<JsFormProvider*>(data));
}

NativeValue* JsFormProvider::GetFormsInfo(NativeEngine* engine, NativeCallbackInfo* info)
{
    JsFormProvider* me = CheckParamsAndGetThis<JsFormProvider>(engine, info);
    return (me != nullptr) ? me->OnGetFormsInfo(*engine, *info) : nullptr;
}

NativeValue* JsFormProvider::OnGetFormsInfo(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_INFO("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    if (info.argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        errCode = ERR_ADD_INVALID_PARAM;
    }

    size_t convertArgc = 0;
    FormInfoFilter formInfoFilter;
    if (info.argc > 0 && info.argv[0]->TypeOf() != NATIVE_FUNCTION) {
        if (!ConvertFormInfoFilter(engine, info.argv[0], formInfoFilter)) {
            HILOG_ERROR("%{public}s, convert form info filter failed.", __func__);
            errCode = ERR_ADD_INVALID_PARAM;
        }
        convertArgc++;
    }

    AsyncTask::CompleteCallback complete =
        [formInfoFilter, errCode](NativeEngine &engine, AsyncTask &task, int32_t status) {
            if (errCode != ERR_OK) {
                task.Reject(engine, CreateJsError(engine, errCode, QueryRetMsg(errCode)));
                return;
            }

            std::vector<FormInfo> formInfos;
            auto ret = FormMgr::GetInstance().GetFormsInfo(formInfoFilter, formInfos);
            if (ret == ERR_OK) {
                task.Resolve(engine, CreateJsFormInfoArray(engine, formInfos));
            } else {
                auto retCode = QueryRetCode(ret);
                task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            }
        };

    NativeValue* lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
    NativeValue* result = nullptr;
    AsyncTask::Schedule("JsFormProvider::OnGetFormsInfo",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}
NativeValue* JsFormProvider::SetFormNextRefreshTime(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsFormProvider *me = CheckParamsAndGetThis<JsFormProvider>(engine, info);
    return (me != nullptr) ? me->OnSetFormNextRefreshTime(*engine, *info) : nullptr;
}

NativeValue* JsFormProvider::OnSetFormNextRefreshTime(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    if (info.argc < ARGS_SIZE_TWO || info.argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("wrong number of arguments.");
        return engine.CreateNull();
    }
    if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
        HILOG_ERROR("formId is not napi_string.");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    int64_t formId = 0;
    std::string strFormId;
    bool confirm = ConvertFromJsValue(engine, info.argv[PARAM0], strFormId);
    if (!confirm) {
        HILOG_ERROR("ConvertFromJsValue failed.");
        errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
    }
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert form string failed.");
        errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
    }
    if (info.argv[PARAM1]->TypeOf() != NATIVE_NUMBER) {
        errCode = ERR_APPEXECFWK_FORM_REFRESH_TIME_NUM_ERR;
    }
    int32_t time;
    bool res = ConvertFromJsValue(engine, info.argv[PARAM1], time);
    if (!res) {
        HILOG_ERROR("ConvertFromJsValue failed.");
        errCode = ERR_APPEXECFWK_FORM_REFRESH_TIME_NUM_ERR;
    }
    AsyncTask::CompleteCallback complete =
        [errCode, formId, time](NativeEngine &engine, AsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            auto retCode = QueryRetCode(errCode);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        int32_t ret = FormMgr::GetInstance().SetNextRefreshTime(formId, time);
        if (ret != ERR_OK) {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        task.Resolve(engine, CreateJsValue(engine, ret));
    };
    NativeValue *lastParam = (info.argc == ARGS_SIZE_THREE) ? info.argv[PARAM2] : nullptr;
    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsFormProvider::OnSetFormNextRefreshTime",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* JsFormProvider::UpdateForm(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsFormProvider *me = CheckParamsAndGetThis<JsFormProvider>(engine, info);
    return (me != nullptr) ? me->OnUpdateForm(*engine, *info) : nullptr;
}

NativeValue* JsFormProvider::OnUpdateForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    auto env = reinterpret_cast<napi_env>(&engine);
    if (info.argc < ARGS_SIZE_TWO || info.argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("wrong number of arguments.");
        return engine.CreateNull();
    }
    if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
        HILOG_ERROR("formId is not napi_string.");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }
    int64_t formId = 0;
    std::string strFormId;
    bool confirm = ConvertFromJsValue(engine, info.argv[PARAM0], strFormId);
    if (!confirm) {
        HILOG_ERROR("ConvertFromJsValue failed.");
        errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
    }
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert form string failed.");
        errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
    }
    if (info.argv[PARAM1]->TypeOf() != NATIVE_OBJECT) {
        HILOG_ERROR("formBindingData is not napi_object.");
        errCode = ERR_APPEXECFWK_FORM_INVALID_PROVIDER_DATA;
    }
    auto formProviderData = std::make_shared<OHOS::AppExecFwk::FormProviderData>();
    auto arg1 = reinterpret_cast<napi_value>(info.argv[PARAM1]);
    std::string formDataStr = GetStringByProp(env, arg1, "data");
    formProviderData->SetDataString(formDataStr);
    formProviderData->ParseImagesData();
    AsyncTask::CompleteCallback complete =
        [errCode, formId, data = formProviderData](NativeEngine &engine, AsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            auto retCode = QueryRetCode(errCode);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        int32_t ret = FormMgr::GetInstance().UpdateForm(formId, *data);
        if (ret != ERR_OK) {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        task.Resolve(engine, CreateJsValue(engine, ret));
    };
    NativeValue *lastParam = (info.argc == ARGS_SIZE_THREE) ? info.argv[PARAM2] : nullptr;
    NativeValue *result = nullptr;
    AsyncTask::Schedule("JsFormProvider::OnUpdateForm",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
