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

#include "napi_form_provider.h"

#include <cinttypes>
#include <vector>

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_mgr.h"
#include "js_runtime_utils.h"
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
    const std::string IS_FORM_AGENT = "isFormAgent";
}

napi_value ExecuteAsyncCallbackWork(napi_env env, AsyncCallbackInfoBase* asyncCallbackInfo)
{
    if (napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default) != napi_ok) {
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
    if (napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default) != napi_ok) {
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

    asyncCallbackInfo->want.SetParam(IS_FORM_AGENT, false);
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

static void FormCallbackCreateAsyncWork(napi_env env, AsyncRequestPublishFormCallbackInfo *asyncCallbackInfo)
{
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("running");
            auto *asyncCallbackInfo = (AsyncRequestPublishFormCallbackInfo *) data;
            InnerRequestPublishForm(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("complete");
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
}

static napi_value RequestPublishFormCallback(napi_env env, napi_value *argv, bool withFormBindingData)
{
    HILOG_INFO("asyncCallback.");

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

    FormCallbackCreateAsyncWork(env, asyncCallbackInfo);
    napi_status status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default);
    if (status != napi_ok) {
        HILOG_ERROR("async work failed!");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        napi_delete_reference(env, asyncCallbackInfo->callback);
        delete asyncCallbackInfo;
        return nullptr;
    }
    return NapiGetResult(env, 1);
}

static void FormPromiseCreateAsyncWork(napi_env env, AsyncRequestPublishFormCallbackInfo *asyncCallbackInfo)
{
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("running");
            auto *asyncCallbackInfo = (AsyncRequestPublishFormCallbackInfo *) data;
            if (asyncCallbackInfo) {
                InnerRequestPublishForm(env, asyncCallbackInfo);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("complete");
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
}

static napi_value RequestPublishFormPromise(napi_env env, napi_value *argv, bool withFormBindingData)
{
    HILOG_INFO("promise");
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
    
    FormPromiseCreateAsyncWork(env, asyncCallbackInfo);
    napi_status status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default);
    if (status != napi_ok) {
        HILOG_ERROR("async work failed!");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        return nullptr;
    }
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
    HILOG_INFO("call");
    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr, nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("argc = [%{public}zu]", argc);

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

static void CheckFormArgv(napi_env env, size_t argc, napi_value* argv, int32_t *errCode, int64_t *formId)
{
    HILOG_INFO("asyncCallback");

    napi_valuetype paramZeroType = napi_undefined;
    napi_typeof(env, argv[PARAM0], &paramZeroType);
    if (paramZeroType != napi_string) {
        HILOG_ERROR("formId is not napi_string.");
        *errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    }

    std::string strFormId;
    bool confirm = ConvertFromJsValue(env, argv[PARAM0], strFormId);
    if (!confirm) {
        HILOG_ERROR("ConvertFromJsValue failed.");
        *errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
    }
    if (!ConvertStringToInt64(strFormId, *formId)) {
        HILOG_ERROR("convert form string failed.");
        *errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
    }
}

void JsFormProvider::Finalizer(napi_env env, void* data, void* hint)
{
    HILOG_INFO("Finalizer is called");
    std::unique_ptr<JsFormProvider>(static_cast<JsFormProvider*>(data));
}

napi_value JsFormProvider::GetFormsInfo(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnGetFormsInfo);
}

napi_value JsFormProvider::OnGetFormsInfo(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_INFO("call");
    int32_t errCode = ERR_OK;
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        errCode = ERR_ADD_INVALID_PARAM;
    }

    size_t convertArgc = 0;
    FormInfoFilter formInfoFilter;
    napi_valuetype type = napi_undefined;
    napi_typeof(env, argv[0], &type);
    if (argc > 0 && type != napi_function) {
        if (!ConvertFormInfoFilter(env, argv[0], formInfoFilter)) {
            HILOG_ERROR("%{public}s, convert form info filter failed.", __func__);
            errCode = ERR_ADD_INVALID_PARAM;
        }
        convertArgc++;
    }

    NapiAsyncTask::CompleteCallback complete =
        [formInfoFilter, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
            if (errCode != ERR_OK) {
                task.Reject(env, CreateJsError(env, errCode, QueryRetMsg(errCode)));
                return;
            }

            std::vector<FormInfo> formInfos;
            auto ret = FormMgr::GetInstance().GetFormsInfo(formInfoFilter, formInfos);
            if (ret == ERR_OK) {
                task.Resolve(env, CreateFormInfos(env, formInfos));
            } else {
                NapiFormUtil::RejectCurrentTask(env, task, ret);
            }
        };

    napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnGetFormsInfo",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}
napi_value JsFormProvider::SetFormNextRefreshTime(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnSetFormNextRefreshTime);
}

napi_value JsFormProvider::OnSetFormNextRefreshTime(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (argc < ARGS_SIZE_TWO || argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("wrong number of arguments.");
        napi_value jsNull = nullptr;
        NAPI_CALL(env, napi_get_null(env, &jsNull));
        return jsNull;
    }
    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    CheckFormArgv(env, argc, argv, &errCode, &formId);

    napi_valuetype paramOneType = napi_undefined;
    napi_typeof(env, argv[PARAM1], &paramOneType);
    if (paramOneType != napi_number) {
        errCode = ERR_APPEXECFWK_FORM_REFRESH_TIME_NUM_ERR;
    }
    int32_t time;
    bool res = ConvertFromJsValue(env, argv[PARAM1], time);
    if (!res) {
        HILOG_ERROR("ConvertFromJsValue failed.");
        errCode = ERR_APPEXECFWK_FORM_REFRESH_TIME_NUM_ERR;
    }
    NapiAsyncTask::CompleteCallback complete =
        [errCode, formId, time](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        int32_t ret = FormMgr::GetInstance().SetNextRefreshTime(formId, time);
        if (ret != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
            return;
        }
        task.Resolve(env, CreateJsValue(env, ret));
    };
    napi_value lastParam = (argc == ARGS_SIZE_THREE) ? argv[PARAM2] : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnSetFormNextRefreshTime",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::UpdateForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnUpdateForm);
}

napi_value JsFormProvider::OnUpdateForm(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (argc < ARGS_SIZE_TWO || argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("wrong number of arguments.");
        napi_value jsNull = nullptr;
        NAPI_CALL(env, napi_get_null(env, &jsNull));
        return jsNull;
    }
    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    CheckFormArgv(env, argc, argv, &errCode, &formId);

    napi_valuetype paramOneType = napi_undefined;
    napi_typeof(env, argv[PARAM1], &paramOneType);
    if (paramOneType != napi_object) {
        HILOG_ERROR("formBindingData is not napi_object.");
        errCode = ERR_APPEXECFWK_FORM_INVALID_PROVIDER_DATA;
    }
    auto formProviderData = std::make_shared<OHOS::AppExecFwk::FormProviderData>();
    std::string formDataStr = GetStringByProp(env, argv[PARAM1], "data");
    formProviderData->SetDataString(formDataStr);
    formProviderData->ParseImagesData();
    NapiAsyncTask::CompleteCallback complete =
        [errCode, formId, data = formProviderData](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        int32_t ret = FormMgr::GetInstance().UpdateForm(formId, *data);
        if (ret != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
            return;
        }
        task.Resolve(env, CreateJsValue(env, ret));
    };
    napi_value lastParam = (argc == ARGS_SIZE_THREE) ? argv[PARAM2] : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnUpdateForm",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormProvider::IsRequestPublishFormSupported(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormProvider, OnIsRequestPublishFormSupported);
}

napi_value JsFormProvider::OnIsRequestPublishFormSupported(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (argc > ARGS_SIZE_ONE) {
        HILOG_ERROR("wrong number of arguments.");
        napi_value jsNull = nullptr;
        NAPI_CALL(env, napi_get_null(env, &jsNull));
        return jsNull;
    }
    struct OnIsRequestPublishFormSupported {
        bool result;
    };
    std::shared_ptr<OnIsRequestPublishFormSupported> onIsRequestPublishFormSupported =
        std::make_shared<OnIsRequestPublishFormSupported>();
    auto execute = [data = onIsRequestPublishFormSupported] () {
        if (data == nullptr) {
            HILOG_ERROR("onIsRequestPublishFormSupported is nullptr.");
            return;
        }
        data->result = FormMgr::GetInstance().IsRequestPublishFormSupported();
    };
    NapiAsyncTask::CompleteCallback complete = [data = onIsRequestPublishFormSupported](
            napi_env env, NapiAsyncTask &task, int32_t status) {
        auto retMsg = QueryRetMsg(ERR_OK);
        task.ResolveWithCustomize(env, CreateJsError(env, ERR_OK, retMsg),
            CreateJsValue(env, data->result));
    };
    napi_value lastParam = (argc <= ARGS_SIZE_ZERO) ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormProvider::OnIsRequestPublishFormSupported",
        env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
    return result;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
