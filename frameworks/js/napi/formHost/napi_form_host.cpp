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

#include "napi_form_host.h"

#include <cinttypes>
#include <regex>
#include <uv.h>
#include <vector>

#include "form_info.h"
#include "form_callback_interface.h"
#include "form_host_client.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "hilog_wrapper.h"
#include "napi_form_util.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "runtime.h"

using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace {
    constexpr size_t ARGS_SIZE_ZERO = 0;
    constexpr size_t ARGS_SIZE_ONE = 1;
    constexpr size_t ARGS_SIZE_TWO = 2;
    constexpr size_t ARGS_SIZE_THREE = 3;
    constexpr int REF_COUNT = 1;
    constexpr int CALLBACK_FLG = 1;
    constexpr int PROMISE_FLG = 2;
    // NANOSECONDS mean 10^9 nano second
    constexpr int64_t NANOSECONDS = 1000000000;
    // MICROSECONDS mean 10^6 millias second
    constexpr int64_t MICROSECONDS = 1000000;
}

/**
 * @brief Get a C++ string value from Node-API
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] value This is an opaque pointer that is used to represent a JavaScript value
 *
 * @return Return a C++ string
 */
static std::string GetStringFromNAPI(napi_env env, napi_value value)
{
    std::string result;
    size_t size = 0;

    if (napi_get_value_string_utf8(env, value, nullptr, 0, &size) != napi_ok) {
        HILOG_ERROR("%{public}s, can not get string size", __func__);
        return "";
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + 1), &size) != napi_ok) {
        HILOG_ERROR("%{public}s, can not get string value", __func__);
        return "";
    }
    return result;
}

static napi_value GetFormIds(napi_env env, napi_value value, ErrCode &errCode, std::vector<int64_t> &formIds)
{
    errCode = ERR_INVALID_VALUE;

    bool isArray;
    NAPI_CALL(env, napi_is_array(env, value, &isArray));
    if (!isArray) {
        errCode = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR;
        return nullptr;
    }

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, value, &arrayLength));

    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, value, i, &napiFormId);

        // Check the value type of the arguments
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
            return nullptr;
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
            return nullptr;
        }

        formIds.push_back(formIdValue);
    }

    errCode = ERR_OK;
    return nullptr;
}

/**
 * @brief  Call native kit function: DeleteForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerDelForm(napi_env env, AsyncDelFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->result = FormMgr::GetInstance().DeleteForm(asyncCallbackInfo->formId,
        FormHostClient::GetInstance());
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: deleteForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_DeleteForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[0]);
    int64_t formId;
    HILOG_ERROR("%{public}s, form id ", strFormId.c_str());
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    AsyncDelFormCallbackInfo *asyncCallbackInfo = new
        AsyncDelFormCallbackInfo {
            .env = env,
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formId = 0,
            .result = 0,
        };
    asyncCallbackInfo->formId = formId;

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of deleteForm is incorrect, "
            "expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
                AsyncDelFormCallbackInfo *asyncCallbackInfo = (AsyncDelFormCallbackInfo *)data;
                InnerDelForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncDelFormCallbackInfo *asyncCallbackInfo = (AsyncDelFormCallbackInfo *)data;
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result[ARGS_SIZE_TWO] = {0};
                    InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncDelFormCallbackInfo *asyncCallbackInfo = (AsyncDelFormCallbackInfo *)data;
                InnerDelForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);
                AsyncDelFormCallbackInfo *asyncCallbackInfo = (AsyncDelFormCallbackInfo *)data;

                napi_value result;
                InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: ReleaseForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerReleaseForm(napi_env env, AsyncReleaseFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->result = FormMgr::GetInstance().ReleaseForm(
        asyncCallbackInfo->formId, FormHostClient::GetInstance(), asyncCallbackInfo->isReleaseCache);
    HILOG_DEBUG("%{public}s end", __func__);
}

// NAPI_ReleaseForm InnerReleaseForm callback execute
napi_async_execute_callback NAPI_ReleaseFormAsyncExecute = [](napi_env env, void *data) {
    HILOG_INFO("NAPI_ReleaseForm InnerReleaseForm execute callback");
    AsyncReleaseFormCallbackInfo *asyncCallbackInfo =
    (AsyncReleaseFormCallbackInfo *)data;
    InnerReleaseForm(env, asyncCallbackInfo);
};

// NAPI_ReleaseForm callback complete
napi_async_complete_callback NAPI_ReleaseFormAsyncComplete = [](napi_env env, napi_status status, void *data) {
    HILOG_INFO("NAPI_ReleaseForm compeleted callback");
    AsyncReleaseFormCallbackInfo *asyncCallbackInfo =
    (AsyncReleaseFormCallbackInfo *)data;

    if (asyncCallbackInfo->callback != nullptr) {
        napi_value result[ARGS_SIZE_TWO] = {0};
        InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, result);
        napi_value callback;
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_value callResult;
        napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, result, &callResult);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
};

// NAPI_ReleaseForm promise Complete
napi_async_complete_callback NAPI_ReleaseFormPromiseComplete = [](napi_env env, napi_status status, void *data) {
    HILOG_INFO("%{public}s, promise complete", __func__);
    AsyncReleaseFormCallbackInfo *asyncCallbackInfo = (AsyncReleaseFormCallbackInfo *)data;

    napi_value result;
    InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
    if (asyncCallbackInfo->result == ERR_OK) {
        napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
    } else {
        napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
};

// ReleaseForm callback
napi_value ReleaseFormCallback(napi_env env, AsyncReleaseFormCallbackInfo *asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        NAPI_ReleaseFormAsyncExecute,
        NAPI_ReleaseFormAsyncComplete,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

// ReleaseForm promise
napi_value ReleaseFormPromise(napi_env env, AsyncReleaseFormCallbackInfo *asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        NAPI_ReleaseFormAsyncExecute,
        NAPI_ReleaseFormPromiseComplete,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: releaseForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_ReleaseForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < ARGS_SIZE_ONE || argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    if (argc == ARGS_SIZE_THREE) {
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ONE], &valueType));
        if (valueType != napi_boolean) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[ARGS_SIZE_TWO],
                    .code = ERR_APPEXECFWK_FORM_RELEASE_FLG_ERR,
                    .type = CALLBACK_FLG
                };
            return RetErrMsg(asyncErrorInfo);
        }
    } else if (argc == ARGS_SIZE_TWO) {
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ONE], &valueType));
        if (valueType != napi_function && valueType != napi_boolean) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[ARGS_SIZE_ONE],
                    .code = ERR_APPEXECFWK_FORM_RELEASE_FLG_ERR,
                    .type = PROMISE_FLG
                };
            return RetErrMsg(asyncErrorInfo);
        }
    }

    valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ZERO], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[ARGS_SIZE_TWO],
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0
            };

        if (argc == ARGS_SIZE_ONE) {
            asyncErrorInfo->type = PROMISE_FLG;
        } else if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
            asyncErrorInfo->callbackValue = argv[ARGS_SIZE_TWO];
        } else {
            valueType = napi_undefined;
            NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
            if (valueType == napi_function) {
                asyncErrorInfo->type = CALLBACK_FLG;
                asyncErrorInfo->callbackValue = argv[1];
            } else if (valueType == napi_boolean) {
                asyncErrorInfo->type = PROMISE_FLG;
            } else {
                NAPI_ASSERT(env, valueType == napi_function || valueType == napi_boolean,
                    "The arguments[2] type of releaseForm is incorrect,expected type is function or boolean.");
            }
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[ARGS_SIZE_ZERO]);
    int64_t formId;
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[ARGS_SIZE_TWO],
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0
            };

        if (argc == ARGS_SIZE_ONE) {
            asyncErrorInfo->type = PROMISE_FLG;
        } else if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
            asyncErrorInfo->callbackValue = argv[ARGS_SIZE_TWO];
        } else {
            valueType = napi_undefined;
            NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
            if (valueType == napi_function) {
                asyncErrorInfo->type = CALLBACK_FLG;
                asyncErrorInfo->callbackValue = argv[1];
            } else if (valueType == napi_boolean) {
                asyncErrorInfo->type = PROMISE_FLG;
            } else {
                NAPI_ASSERT(env, valueType == napi_function || valueType == napi_boolean,
                    "The arguments[2] type of releaseForm is incorrect,expected type is function or boolean.");
            }
        }
        return RetErrMsg(asyncErrorInfo);
    }

    AsyncReleaseFormCallbackInfo *asyncCallbackInfo = new
    AsyncReleaseFormCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formId = formId,
        .isReleaseCache = false,
        .result = 0,
    };

    if (argc == ARGS_SIZE_ONE) { // release promise, one argv
        return ReleaseFormPromise(env, asyncCallbackInfo);
    } else if (argc == ARGS_SIZE_THREE) { // release callback, three argv
        HILOG_INFO("%{public}s, asyncCallback.", __func__);
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_boolean, "The arguments[1] type of releaseForm is incorrect, "
            "expected type is boolean.");

        napi_get_value_bool(env, argv[1], &asyncCallbackInfo->isReleaseCache);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[2] type of releaseForm is incorrect, "
            "expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
        ReleaseFormCallback(env, asyncCallbackInfo);
    } else {
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        if (valueType == napi_function) { // release callback, two argv
            napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
            ReleaseFormCallback(env, asyncCallbackInfo);
        } else if (valueType == napi_boolean) { // release promise, two argv
            napi_get_value_bool(env, argv[1], &asyncCallbackInfo->isReleaseCache);
            return ReleaseFormPromise(env, asyncCallbackInfo);
        } else {
            NAPI_ASSERT(env, valueType == napi_function || valueType == napi_boolean,
                "The arguments[2] type of releaseForm is incorrect,expected type is function or boolean.");
        }
    }
    return NapiGetResult(env, 1);
}

/**
 * @brief  Call native kit function: RequestForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerRequestForm(napi_env env, AsyncRequestFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    Want want;
    asyncCallbackInfo->result = FormMgr::GetInstance().RequestForm(asyncCallbackInfo->formId,
        FormHostClient::GetInstance(), want);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: requestForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_RequestForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[0]);
    int64_t formId;
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    AsyncRequestFormCallbackInfo *asyncCallbackInfo = new
    AsyncRequestFormCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formId = formId,
        .result = 0,
    };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of requestForm is incorrect, "
            "expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
                AsyncRequestFormCallbackInfo *asyncCallbackInfo = (AsyncRequestFormCallbackInfo *)data;
                InnerRequestForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncRequestFormCallbackInfo *asyncCallbackInfo = (AsyncRequestFormCallbackInfo *)data;
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result[ARGS_SIZE_TWO] = {0};
                    InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncRequestFormCallbackInfo *asyncCallbackInfo = (AsyncRequestFormCallbackInfo *)data;
                InnerRequestForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);
                AsyncRequestFormCallbackInfo *asyncCallbackInfo = (AsyncRequestFormCallbackInfo *)data;

                napi_value result;
                InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: CastTempForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerCastTempForm(napi_env env, AsyncCastTempFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->result = FormMgr::GetInstance().CastTempForm(asyncCallbackInfo->formId,
        FormHostClient::GetInstance());
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: castTempForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_CastTempForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[0]);
    int64_t formId;
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    AsyncCastTempFormCallbackInfo *asyncCallbackInfo = new
    AsyncCastTempFormCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formId = formId,
        .result = 0,
    };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of castTempForm is incorrect, "
            "expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
                AsyncCastTempFormCallbackInfo *asyncCallbackInfo = (AsyncCastTempFormCallbackInfo *)data;
                InnerCastTempForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncCastTempFormCallbackInfo *asyncCallbackInfo = (AsyncCastTempFormCallbackInfo *)data;
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result[ARGS_SIZE_TWO] = {0};
                    InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncCastTempFormCallbackInfo *asyncCallbackInfo = (AsyncCastTempFormCallbackInfo *)data;
                InnerCastTempForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);
                AsyncCastTempFormCallbackInfo *asyncCallbackInfo = (AsyncCastTempFormCallbackInfo *)data;

                napi_value result;
                InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: NotifyVisibleForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerNotifyVisibleForms(napi_env env, AsyncNotifyVisibleFormsCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->result = FormMgr::GetInstance().NotifyWhetherVisibleForms(asyncCallbackInfo->formIds,
        FormHostClient::GetInstance(), Constants::FORM_VISIBLE);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: notifyVisibleForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_NotifyVisibleForms(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    bool isArray;
    NAPI_CALL(env, napi_is_array(env, argv[0], &isArray));
    if (!isArray) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR,
                .type = 0
            };
        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &arrayLength));
    if (arrayLength == 0) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR,
                .type = 0
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::vector<int64_t> formIds;
    formIds.clear();
    napi_valuetype valueType;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[1],
                    .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                    .type = 0
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[1],
                    .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                    .type = 0
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        formIds.push_back(formIdValue);
    }

    AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo = new
        AsyncNotifyVisibleFormsCallbackInfo {
            .env = env,
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formIds = formIds,
            .result = 1,
        };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of notifyVisibleForms is incorrect,"
            "expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyVisibleFormsCallbackInfo *)data;

                InnerNotifyVisibleForms(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyVisibleFormsCallbackInfo *)data;

                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result[ARGS_SIZE_TWO] = {0};
                    InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);

                AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyVisibleFormsCallbackInfo *)data;

                InnerNotifyVisibleForms(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyVisibleFormsCallbackInfo *)data;

                napi_value result;
                InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: NotifyInvisibleForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerNotifyInvisibleForms(napi_env env, AsyncNotifyInvisibleFormsCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->result = FormMgr::GetInstance().NotifyWhetherVisibleForms(asyncCallbackInfo->formIds,
        FormHostClient::GetInstance(), Constants::FORM_INVISIBLE);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: notifyInvisibleForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_NotifyInvisibleForms(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    bool isArray;
    NAPI_CALL(env, napi_is_array(env, argv[0], &isArray));
    if (!isArray) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR,
                .type = 0
            };
        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &arrayLength));
    if (arrayLength == 0) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR,
                .type = 0,
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::vector<int64_t> formIds;
    formIds.clear();
    napi_valuetype valueType;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[1],
                    .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                    .type = 0,
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[1],
                    .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                    .type = 0,
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        formIds.push_back(formIdValue);
    }

    AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo = new
        AsyncNotifyInvisibleFormsCallbackInfo {
            .env = env,
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formIds = formIds,
            .result = 1,
        };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of notifyInvisibleForms is incorrect,"
            "expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyInvisibleFormsCallbackInfo *)data;

                InnerNotifyInvisibleForms(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyInvisibleFormsCallbackInfo *)data;

                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result[ARGS_SIZE_TWO] = {0};
                    InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);

                AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyInvisibleFormsCallbackInfo *)data;

                InnerNotifyInvisibleForms(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyInvisibleFormsCallbackInfo *)data;

                napi_value result;
                InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: EnableUpdateForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerEnableFormsUpdate(napi_env env, AsyncEnableUpdateFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->result = FormMgr::GetInstance().LifecycleUpdate(asyncCallbackInfo->formIds,
        FormHostClient::GetInstance(), true);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: enableFormsUpdate
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_EnableFormsUpdate(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    bool isArray;
    NAPI_CALL(env, napi_is_array(env, argv[0], &isArray));
    if (!isArray) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR,
                .type = 0
            };
        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &arrayLength));
    if (arrayLength == 0) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR,
                .type = 0,
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::vector<int64_t> formIds;
    formIds.clear();
    napi_valuetype valueType;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[1],
                    .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                    .type = 0,
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[1],
                    .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                    .type = 0
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        formIds.push_back(formIdValue);
    }

    AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo = new
    AsyncEnableUpdateFormCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formIds = formIds,
        .result = 0,
    };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of enableFormsUpdate "
            "is incorrect, expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncEnableUpdateFormCallbackInfo *)data;

                InnerEnableFormsUpdate(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncEnableUpdateFormCallbackInfo *)data;

                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result[ARGS_SIZE_TWO] = {0};
                    InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncEnableUpdateFormCallbackInfo *)data;

                InnerEnableFormsUpdate(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncEnableUpdateFormCallbackInfo *)data;

                napi_value result;
                InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: DisableUpdateForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerDisableFormsUpdate(napi_env env, AsyncDisableUpdateFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    asyncCallbackInfo->result = FormMgr::GetInstance().LifecycleUpdate(asyncCallbackInfo->formIds,
        FormHostClient::GetInstance(), false);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: disableFormsUpdate
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_DisableFormsUpdate(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    bool isArray;
    NAPI_CALL(env, napi_is_array(env, argv[0], &isArray));
    if (!isArray) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR,
                .type = 0
            };
        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &arrayLength));
    if (arrayLength == 0) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR,
                .type = 0
            };
        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::vector<int64_t> formIds;
    formIds.clear();
    napi_valuetype valueType;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[1],
                    .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                    .type = 0,
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .callbackValue = argv[1],
                    .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                    .type = 0
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        formIds.push_back(formIdValue);
    }

    AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo = new
        AsyncDisableUpdateFormCallbackInfo {
            .env = env,
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formIds = formIds,
            .result = 0,
        };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of disableFormsUpdate "
            "is incorrect, expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncDisableUpdateFormCallbackInfo *)data;

                InnerDisableFormsUpdate(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncDisableUpdateFormCallbackInfo *)data;

                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result[ARGS_SIZE_TWO] = {0};
                    InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);

                AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncDisableUpdateFormCallbackInfo *)data;

                InnerDisableFormsUpdate(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncDisableUpdateFormCallbackInfo *)data;

                napi_value result;
                InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: CheckFMSReady
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerCheckFMSReady(napi_env env, AsyncCheckFMSReadyCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->isFMSReady = FormMgr::GetInstance().CheckFMSReady() ? 0 : 1;
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: checkFMSReady
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_CheckFMSReady(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_ONE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo = new
    AsyncCheckFMSReadyCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .isFMSReady = false,
    };

    if (argc == ARGS_SIZE_ONE) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        napi_valuetype valueType;
        NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[0] type of checkFMSReady is incorrect, "
            "expected type is function.");

        napi_create_reference(env, argv[0], REF_COUNT, &asyncCallbackInfo->callback);
        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo =
                (AsyncCheckFMSReadyCallbackInfo *)data;

                InnerCheckFMSReady(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo =
                    (AsyncCheckFMSReadyCallbackInfo *)data;

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value callbackValues[ARGS_SIZE_TWO] = {0};
                    InnerCreateCallbackRetMsg(env, asyncCallbackInfo->isFMSReady, callbackValues);

                    napi_value undefined;
                    napi_get_undefined(env, &undefined);

                    napi_value callback;
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);

                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);

                AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo =
                    (AsyncCheckFMSReadyCallbackInfo *)data;

                InnerCheckFMSReady(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo =
                (AsyncCheckFMSReadyCallbackInfo *)data;

                napi_value result;
                InnerCreatePromiseRetMsg(env, asyncCallbackInfo->isFMSReady, &result);
                if (asyncCallbackInfo->isFMSReady == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(
                        asyncCallbackInfo->env,
                        asyncCallbackInfo->deferred,
                        result);
                }

                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

static void InnerDeleteInvalidForms(napi_env env, AsyncDeleteInvalidFormsCallbackInfo *const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    ErrCode ret = FormMgr::GetInstance().DeleteInvalidForms(asyncCallbackInfo->formIds,
        FormHostClient::GetInstance(), asyncCallbackInfo->numFormsDeleted);
    asyncCallbackInfo->result = ret;
    if (ret != ERR_OK) {
        asyncCallbackInfo->numFormsDeleted = 0;
    }
    HILOG_DEBUG("%{public}s, end", __func__);
}

napi_value DeleteInvalidFormsCallback(napi_env env, AsyncDeleteInvalidFormsCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncDeleteInvalidFormsCallbackInfo *) data;
            InnerDeleteInvalidForms(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncDeleteInvalidFormsCallbackInfo *) data;

            if (asyncCallbackInfo->callback != nullptr) {
                napi_value callback;
                napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr, nullptr};
                InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, callbackValues);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_create_int32(env, asyncCallbackInfo->numFormsDeleted, &callbackValues[1]);
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

napi_value DeleteInvalidFormsPromise(napi_env env, AsyncDeleteInvalidFormsCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncDeleteInvalidFormsCallbackInfo *) data;
            InnerDeleteInvalidForms(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncDeleteInvalidFormsCallbackInfo *) data;
            if (asyncCallbackInfo->result != ERR_OK) {
                napi_value result;
                InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
                napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            } else {
                napi_value result;
                napi_create_int32(env, asyncCallbackInfo->numFormsDeleted, &result);
                napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: deleteInvalidForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_DeleteInvalidForms(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }

    int32_t callbackType = (argc == ARGS_SIZE_TWO) ? CALLBACK_FLG : PROMISE_FLG;
    bool isArray;
    NAPI_CALL(env, napi_is_array(env, argv[0], &isArray));
    if (!isArray) {
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR, callbackType, argv[1]));
    }

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &arrayLength));

    std::vector<int64_t> formIds;
    formIds.clear();
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_INVALID_FORM_ID, callbackType, argv[1]));
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR, callbackType, argv[1]));
        }

        formIds.push_back(formIdValue);
    }

    auto *asyncCallbackInfo = new AsyncDeleteInvalidFormsCallbackInfo {
        .env = env,
        .formIds = formIds,
    };

    if (argc == ARGS_SIZE_TWO) {
        // Check the value type of the arguments
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of args[1] is incorrect, expected type is function.");
        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
        return DeleteInvalidFormsCallback(env, asyncCallbackInfo);
    } else {
        return DeleteInvalidFormsPromise(env, asyncCallbackInfo);
    }
}

napi_value ParseFormStateInfo(napi_env env, FormStateInfo &stateInfo)
{
    napi_value formStateInfoObject = nullptr;
    napi_create_object(env, &formStateInfoObject);
    napi_value jsValue = WrapWant(env, stateInfo.want);
    SetPropertyValueByPropertyName(env, formStateInfoObject, "want", jsValue);
    napi_value formState = nullptr;
    napi_create_int32(env, (int32_t) stateInfo.state, &formState);
    SetPropertyValueByPropertyName(env, formStateInfoObject, "formState", formState);

    return formStateInfoObject;
}

void AcquireFormStateCallbackComplete(uv_work_t *work, int32_t status)
{
    HILOG_INFO("%{public}s, onAcquireFormState back", __func__);
    if (work == nullptr) {
        HILOG_ERROR("work == nullptr.");
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncAcquireFormStateCallbackInfo *>(work->data);
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr.");
        delete work;
        return;
    }
    napi_env env = asyncCallbackInfo->env;

    if (asyncCallbackInfo->callback != nullptr) {
        napi_value callback;
        napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr, nullptr};
        InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, callbackValues);
        if (asyncCallbackInfo->result == ERR_OK) {
            callbackValues[1] = ParseFormStateInfo(env, asyncCallbackInfo->stateInfo);
        }

        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_value callResult;
        napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }

    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
    delete work;
    work = nullptr;
    HILOG_INFO("%{public}s, onAcquireFormState back done", __func__);
}

void AcquireFormStatePromiseComplete(uv_work_t *work, int32_t status)
{
    HILOG_INFO("%{public}s, onAcquireFormState back", __func__);
    if (work == nullptr) {
        HILOG_ERROR("%{public}s, work == nullptr.", __func__);
        return;
    }
    auto *asyncCallbackInfo = static_cast<AsyncAcquireFormStateCallbackInfo *>(work->data);
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr.");
        delete work;
        return;
    }
    napi_env env = asyncCallbackInfo->env;

    if (asyncCallbackInfo->result != ERR_OK) {
        napi_value result;
        InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
        napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
    } else {
        napi_value result = ParseFormStateInfo(env, asyncCallbackInfo->stateInfo);
        napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
    }

    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
    delete work;
    work = nullptr;
    HILOG_INFO("%{public}s, onAcquireFormState back done", __func__);
}

namespace {
class FormStateCallbackClient : public FormStateCallbackInterface {
public:
    explicit FormStateCallbackClient(AsyncAcquireFormStateCallbackInfo *const asyncCallbackInfo)
    {
        asyncCallbackInfo_ = asyncCallbackInfo;
    }

    virtual ~FormStateCallbackClient() = default;

    void ProcessAcquireState(FormState state) override
    {
        if (asyncCallbackInfo_ == nullptr) {
            return;
        }
        asyncCallbackInfo_->stateInfo.state = state;

        uv_loop_s *loop = nullptr;
        napi_get_uv_event_loop(asyncCallbackInfo_->env, &loop);
        if (loop == nullptr) {
            HILOG_ERROR("%{public}s, loop == nullptr.", __func__);
            return;
        }

        auto *work = new (std::nothrow) uv_work_t;
        if (work == nullptr) {
            HILOG_ERROR("%{public}s, work == nullptr.", __func__);
            return;
        }
        work->data = asyncCallbackInfo_;

        int32_t result = 0;
        if (asyncCallbackInfo_->callbackType == CALLBACK_FLG) {
            result = uv_queue_work(loop, work, [](uv_work_t *work) {}, AcquireFormStateCallbackComplete);
        } else {
            result = uv_queue_work(loop, work, [](uv_work_t *work) {}, AcquireFormStatePromiseComplete);
        }
        // When uv_queue_work returns 0, asyncCallbackInfo_ and work will be freed in the callback function.
        if (result != 0) {
            delete asyncCallbackInfo_;
            asyncCallbackInfo_ = nullptr;
            delete work;
            work = nullptr;
        }
    }

private:
    AsyncAcquireFormStateCallbackInfo *asyncCallbackInfo_ = nullptr;
};

class FormUninstallCallbackClient {
public:
    explicit FormUninstallCallbackClient(napi_env env, napi_ref callbackRef)
    {
        env_ = env;
        callbackRef_ = callbackRef;
    }

    virtual ~FormUninstallCallbackClient()
    {
        napi_delete_reference(env_, callbackRef_);
    }

    void ProcessFormUninstall(const int64_t formId)
    {
        std::string formIdString = std::to_string(formId);
        napi_value callbackValues;
        napi_create_string_utf8(env_, formIdString.c_str(), NAPI_AUTO_LENGTH, &callbackValues);
        napi_value callResult;
        napi_value myCallback = nullptr;
        napi_get_reference_value(env_, callbackRef_, &myCallback);
        if (myCallback != nullptr) {
            napi_call_function(env_, nullptr, myCallback, ARGS_SIZE_ONE, &callbackValues, &callResult);
        }
    }

    bool IsStrictEqual(napi_value callback)
    {
        bool isEqual = false;
        napi_value myCallback = nullptr;
        napi_get_reference_value(env_, callbackRef_, &myCallback);
        napi_strict_equals(env_, myCallback, callback, &isEqual);
        HILOG_INFO("isStrictEqual: %{public}d", isEqual);
        return isEqual;
    }

private:
    napi_ref callbackRef_ {};
    napi_env env_;
};

std::map<napi_ref, std::shared_ptr<FormUninstallCallbackClient>> g_formUninstallCallbackMap {};
std::mutex formUninstallCallbackMapMutex_;

void FormUninstallCallback(const std::vector<int64_t> &formIds)
{
    std::lock_guard<std::mutex> lock(formUninstallCallbackMapMutex_);
    for (auto &iter : g_formUninstallCallbackMap) {
        for (int64_t formId : formIds) {
            iter.second->ProcessFormUninstall(formId);
        }
    }
}

bool AddFormUninstallCallback(napi_env env, napi_value callback)
{
    std::lock_guard<std::mutex> lock(formUninstallCallbackMapMutex_);
    for (auto &iter : g_formUninstallCallbackMap) {
        if (iter.second->IsStrictEqual(callback)) {
            HILOG_ERROR("found equal callback");
            return false;
        }
    }

    napi_ref callbackRef;
    napi_create_reference(env, callback, REF_COUNT, &callbackRef);
    std::shared_ptr<FormUninstallCallbackClient> callbackClient = std::make_shared<FormUninstallCallbackClient>(env,
        callbackRef);

    auto ret = g_formUninstallCallbackMap.emplace(callbackRef, callbackClient);
    if (!ret.second) {
        HILOG_ERROR("failed to emplace callback");
        return false;
    }
    return true;
}

bool DelFormUninstallCallback(napi_value callback)
{
    int32_t count = 0;
    std::lock_guard<std::mutex> lock(formUninstallCallbackMapMutex_);
    for (auto iter = g_formUninstallCallbackMap.begin(); iter != g_formUninstallCallbackMap.end();) {
        if (iter->second->IsStrictEqual(callback)) {
            HILOG_INFO("found equal callback");
            iter = g_formUninstallCallbackMap.erase(iter);
            count++;
        } else {
            iter++;
        }
    }
    HILOG_INFO("%{public}d form uninstall callback deleted.", count);
    return true;
}

bool ClearFormUninstallCallback()
{
    std::lock_guard<std::mutex> lock(formUninstallCallbackMapMutex_);
    g_formUninstallCallbackMap.clear();
    return true;
}
}

static void InnerAcquireFormState(napi_env env, AsyncAcquireFormStateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    std::shared_ptr<FormStateCallbackInterface> formStateCallback = std::make_shared<FormStateCallbackClient>(
        asyncCallbackInfo);
    FormHostClient::GetInstance()->AddFormState(formStateCallback, asyncCallbackInfo->want);

    asyncCallbackInfo->result = FormMgr::GetInstance().AcquireFormState(asyncCallbackInfo->want,
        FormHostClient::GetInstance(), asyncCallbackInfo->stateInfo);
    HILOG_DEBUG("%{public}s, end", __func__);
}

napi_value AcquireFormStateCallback(napi_env env, AsyncAcquireFormStateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncAcquireFormStateCallbackInfo *) data;
            InnerAcquireFormState(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncAcquireFormStateCallbackInfo *) data;
            // asyncCallbackInfo will be freed in OnAcquireState, so save the member variable asyncWork.
            napi_async_work asyncWork = asyncCallbackInfo->asyncWork;
            // When the result is not ERR_OK, OnAcquireState will be called here,
            // else OnAcquireState will be called after the form state is acquired.
            if (asyncCallbackInfo->result != ERR_OK) {
                FormHostClient::GetInstance()->OnAcquireState(FormState::UNKNOWN, asyncCallbackInfo->want);
            }
            napi_delete_async_work(env, asyncWork);
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

napi_value AcquireFormStatePromise(napi_env env, AsyncAcquireFormStateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncAcquireFormStateCallbackInfo *) data;
            InnerAcquireFormState(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncAcquireFormStateCallbackInfo *) data;
            // asyncCallbackInfo will be freed in OnAcquireState, so save the member variable asyncWork.
            napi_async_work asyncWork = asyncCallbackInfo->asyncWork;
            // When the result is not ERR_OK, OnAcquireState will be called here,
            // else OnAcquireState will be called after the form state is acquired.
            if (asyncCallbackInfo->result != ERR_OK) {
                FormHostClient::GetInstance()->OnAcquireState(FormState::UNKNOWN, asyncCallbackInfo->want);
            }
            napi_delete_async_work(env, asyncWork);
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: acquireFormState
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_AcquireFormState(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    int32_t callbackType = (argc == ARGS_SIZE_TWO) ? CALLBACK_FLG : PROMISE_FLG;
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_object) {
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_INVALID_PARAM, callbackType, argv[1]));
    }

    auto *asyncCallbackInfo = new AsyncAcquireFormStateCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .want = {},
        .stateInfo = {},
        .callbackType = callbackType,
        .result = ERR_OK,
    };

    bool parseResult = UnwrapWant(env, argv[0], asyncCallbackInfo->want);
    if (!parseResult) {
        HILOG_ERROR("%{public}s, failed to parse want.", __func__);
        delete asyncCallbackInfo;
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_INVALID_PARAM, callbackType, argv[1]));
    }

    if (argc == ARGS_SIZE_TWO) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function,
            "The arguments[1] type of acquireFormState is incorrect, expected type is function.");
        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
        return AcquireFormStateCallback(env, asyncCallbackInfo);
    } else {
        return AcquireFormStatePromise(env, asyncCallbackInfo);
    }
}

/**
 * @brief  The implementation of Node-API interface: on
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_RegisterFormUninstallObserver(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        HILOG_ERROR("The type of args[0] is incorrect, expected type is string.");
        return nullptr;
    }
    std::string type;
    if (!UnwrapStringFromJS2(env, argv[0], type)) {
        HILOG_ERROR("failed to get args[0].");
        return nullptr;
    }

    if (type != "formUninstall") {
        HILOG_ERROR("args[0] should be formUninstall.");
        return nullptr;
    }

    valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
    if (valueType != napi_function) {
        HILOG_ERROR("The type of args[1] is incorrect, expected type is function.");
        return nullptr;
    }

    FormHostClient::GetInstance()->RegisterUninstallCallback(FormUninstallCallback);
    AddFormUninstallCallback(env, argv[1]);
    return nullptr;
}

/**
 * @brief  The implementation of Node-API interface: off
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_UnregisterFormUninstallObserver(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        HILOG_ERROR("The type of args[0] is incorrect, expected type is string.");
        return nullptr;
    }
    std::string type;
    if (!UnwrapStringFromJS2(env, argv[0], type)) {
        HILOG_ERROR("failed to get args[0].");
        return nullptr;
    }

    if (type != "formUninstall") {
        HILOG_ERROR("args[0] should be formUninstall.");
        return nullptr;
    }

    if (argc == ARGS_SIZE_TWO) {
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        if (valueType != napi_function) {
            HILOG_ERROR("The type of args[1] is incorrect, expected type is function.");
            return nullptr;
        }
        DelFormUninstallCallback(argv[1]);
        return nullptr;
    } else {
        ClearFormUninstallCallback();
        return nullptr;
    }
}

static void InnerNotifyFormsVisible(napi_env env, AsyncNotifyFormsVisibleCallbackInfo *const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    asyncCallbackInfo->result = FormMgr::GetInstance().NotifyFormsVisible(asyncCallbackInfo->formIds,
        asyncCallbackInfo->isVisible, FormHostClient::GetInstance());
    HILOG_DEBUG("%{public}s, end", __func__);
}

napi_value NotifyFormsVisibleCallback(napi_env env, AsyncNotifyFormsVisibleCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsVisibleCallbackInfo *) data;
            InnerNotifyFormsVisible(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsVisibleCallbackInfo *) data;

            if (asyncCallbackInfo->callback != nullptr) {
                napi_value callback;
                napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr, nullptr};
                InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, callbackValues);

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

napi_value NotifyFormsVisiblePromise(napi_env env, AsyncNotifyFormsVisibleCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsVisibleCallbackInfo *) data;
            InnerNotifyFormsVisible(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsVisibleCallbackInfo *) data;
            napi_value result;
            InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
            if (asyncCallbackInfo->result == ERR_OK) {
                napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            } else {
                napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: notifyFormsVisible
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_NotifyFormsVisible(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr, nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE || argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }

    int32_t callbackType = (argc == ARGS_SIZE_THREE) ? CALLBACK_FLG : PROMISE_FLG;

    ErrCode errCode;
    std::vector<int64_t> formIds {};
    GetFormIds(env, argv[0], errCode, formIds);
    if (errCode != ERR_OK) {
        return RetErrMsg(InitErrMsg(env, errCode, callbackType, argv[ARGS_SIZE_TWO]));
    }

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
    if (valueType != napi_boolean) {
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_INVALID_PARAM, callbackType, argv[ARGS_SIZE_TWO]));
    }

    auto *asyncCallbackInfo = new AsyncNotifyFormsVisibleCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formIds = formIds,
        .isVisible = false,
    };
    napi_get_value_bool(env, argv[1], &asyncCallbackInfo->isVisible);

    if (argc == ARGS_SIZE_THREE) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of arg 2 is incorrect, expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
        return NotifyFormsVisibleCallback(env, asyncCallbackInfo);
    } else {
        return NotifyFormsVisiblePromise(env, asyncCallbackInfo);
    }
}

static void InnerNotifyFormsEnableUpdate(napi_env env,
                                         AsyncNotifyFormsEnableUpdateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    asyncCallbackInfo->result = FormMgr::GetInstance().NotifyFormsEnableUpdate(asyncCallbackInfo->formIds,
        asyncCallbackInfo->isEnableUpdate, FormHostClient::GetInstance());
    HILOG_DEBUG("%{public}s, end", __func__);
}

napi_value NotifyFormsEnableUpdateCallback(napi_env env,
                                           AsyncNotifyFormsEnableUpdateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsEnableUpdateCallbackInfo *) data;
            InnerNotifyFormsEnableUpdate(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsEnableUpdateCallbackInfo *) data;

            if (asyncCallbackInfo->callback != nullptr) {
                napi_value callback;
                napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr, nullptr};
                InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, callbackValues);

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

napi_value NotifyFormsEnableUpdatePromise(napi_env env,
                                          AsyncNotifyFormsEnableUpdateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsEnableUpdateCallbackInfo *) data;
            InnerNotifyFormsEnableUpdate(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsEnableUpdateCallbackInfo *) data;
            napi_value result;
            InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
            if (asyncCallbackInfo->result == ERR_OK) {
                napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            } else {
                napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: notifyFormsEnableUpdate
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_NotifyFormsEnableUpdate(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr, nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE || argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }

    int32_t callbackType = (argc == ARGS_SIZE_THREE) ? CALLBACK_FLG : PROMISE_FLG;

    ErrCode errCode;
    std::vector<int64_t> formIds {};
    GetFormIds(env, argv[0], errCode, formIds);
    if (errCode != ERR_OK) {
        return RetErrMsg(InitErrMsg(env, errCode, callbackType, argv[ARGS_SIZE_TWO]));
    }

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
    if (valueType != napi_boolean) {
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_INVALID_PARAM, callbackType, argv[ARGS_SIZE_TWO]));
    }

    auto *asyncCallbackInfo = new AsyncNotifyFormsEnableUpdateCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formIds = formIds,
        .isEnableUpdate = false,
    };
    napi_get_value_bool(env, argv[1], &asyncCallbackInfo->isEnableUpdate);

    if (argc == ARGS_SIZE_THREE) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of arg 2 is incorrect, expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
        return NotifyFormsEnableUpdateCallback(env, asyncCallbackInfo);
    } else {
        return NotifyFormsEnableUpdatePromise(env, asyncCallbackInfo);
    }
}

/**
 * @brief  Call native kit function: GetAllFormsInfo
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerGetAllFormsInfo(napi_env env, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->result = FormMgr::GetInstance().GetAllFormsInfo(asyncCallbackInfo->formInfos);
    HILOG_DEBUG("%{public}s, end", __func__);
}

// NAPI_GetAllFormsInfo callback execute
napi_async_execute_callback NAPI_GetAllFormsInfoAsyncExecute = [](napi_env env, void *data) {
    HILOG_INFO("NAPI_GetAllFormsInfo execute callback");
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = (AsyncGetFormsInfoCallbackInfo *)data;
    InnerGetAllFormsInfo(env, asyncCallbackInfo);
};

// NAPI_GetFormsInfo callback complete
napi_async_complete_callback NAPI_GetFormsInfoAsyncComplete = [](napi_env env, napi_status status, void *data) {
    HILOG_INFO("NAPI_GetFormsInfo compeleted callback");
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = (AsyncGetFormsInfoCallbackInfo *)data;
    napi_value arrayFormInfos;
    napi_create_array(env, &arrayFormInfos);
    if (asyncCallbackInfo->result == ERR_OK) {
        int iFormInfoCount = 0;
        for (auto formInfo : asyncCallbackInfo->formInfos) {
            napi_value formInfoObject = nullptr;
            napi_create_object(env, &formInfoObject);
            ParseFormInfoIntoNapi(env, formInfo, formInfoObject);
            napi_set_element(env, arrayFormInfos, iFormInfoCount, formInfoObject);
            ++iFormInfoCount;
        }
    }
    if (asyncCallbackInfo->callback != nullptr) {
        napi_value callbackValues[ARGS_SIZE_TWO] = {0};
        napi_value callback;
        ErrCode errCode = asyncCallbackInfo->result;
        InnerCreateCallbackRetMsg(env, errCode, callbackValues);
        if (errCode == ERR_OK) {
            callbackValues[1] = arrayFormInfos;
        }
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_value callResult;
        napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
};

// NAPI_GetFormsInfo promise Complete
napi_async_complete_callback NAPI_GetFormsInfoPromiseComplete = [](napi_env env, napi_status status, void *data) {
    HILOG_INFO("%{public}s, promise complete", __func__);
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = (AsyncGetFormsInfoCallbackInfo *)data;
    if (asyncCallbackInfo->result == ERR_OK) {
        napi_value arrayFormInfos;
        napi_create_array(env, &arrayFormInfos);
        int iFormInfoCount = 0;
        for (auto formInfo : asyncCallbackInfo->formInfos) {
            napi_value formInfoObject = nullptr;
            napi_create_object(env, &formInfoObject);
            ParseFormInfoIntoNapi(env, formInfo, formInfoObject);
            napi_set_element(env, arrayFormInfos, iFormInfoCount, formInfoObject);
            ++iFormInfoCount;
        }
        napi_resolve_deferred(
            asyncCallbackInfo->env,
            asyncCallbackInfo->deferred,
            arrayFormInfos);
    } else {
        napi_value getFormsInfoResult;
        InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &getFormsInfoResult);

        napi_reject_deferred(
            asyncCallbackInfo->env,
            asyncCallbackInfo->deferred,
            getFormsInfoResult);
    }

    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
};

/**
 * @brief  The implementation of Node-API interface: getAllFormsInfo
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_GetAllFormsInfo(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_ONE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = new
    AsyncGetFormsInfoCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formInfos = std::vector<OHOS::AppExecFwk::FormInfo>(),
        .bundleName = "",
        .moduleName = "",
        .result = 0,
    };

    if (argc == ARGS_SIZE_ONE) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        napi_valuetype valueType;
        NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[0] type of getAllFormsInfo is incorrect, "
            "expected type is function.");

        napi_create_reference(env, argv[0], REF_COUNT, &asyncCallbackInfo->callback);
        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            NAPI_GetAllFormsInfoAsyncExecute,
            NAPI_GetFormsInfoAsyncComplete,
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            NAPI_GetAllFormsInfoAsyncExecute,
            NAPI_GetFormsInfoPromiseComplete,
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: GetFormsInfoByApp
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerGetFormsInfoByApp(napi_env env, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->result = FormMgr::GetInstance().GetFormsInfoByApp(
        asyncCallbackInfo->bundleName,
        asyncCallbackInfo->formInfos);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  Call native kit function: GetFormsInfoByModule
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerGetFormsInfoByModule(napi_env env, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    asyncCallbackInfo->result = FormMgr::GetInstance().GetFormsInfoByModule(
        asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName,
        asyncCallbackInfo->formInfos);
    HILOG_DEBUG("%{public}s, end", __func__);
}

// NAPI_GetFormsInfo byModule callback execute
auto NAPI_GetFormsInfoByModuleAsyncExecute = [](napi_env env, void *data) {
    HILOG_INFO("NAPI_GetFormsInfo byModule execute callback");
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo =
        (AsyncGetFormsInfoCallbackInfo *)data;
    InnerGetFormsInfoByModule(env, asyncCallbackInfo);
};

// NAPI_GetFormsInfo byApp callback execute
auto NAPI_GetFormsInfoByAppAsyncExecute = [](napi_env env, void *data) {
    HILOG_INFO("NAPI_GetFormsInfo byApp execute callback");
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo =
        (AsyncGetFormsInfoCallbackInfo *)data;
    InnerGetFormsInfoByApp(env, asyncCallbackInfo);
};

// GetFormsInfo callback
napi_value GetFormsInfoCallback(napi_env env, AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo, bool isByApp)
{
    HILOG_INFO("%{public}s, callback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        isByApp ? NAPI_GetFormsInfoByAppAsyncExecute :
        NAPI_GetFormsInfoByModuleAsyncExecute,
        NAPI_GetFormsInfoAsyncComplete,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

// GetFormsInfo promise
napi_value GetFormsInfoPromise(napi_env env, AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo, bool isByApp)
{
    HILOG_INFO("%{public}s, promise.", __func__);
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        isByApp ? NAPI_GetFormsInfoByAppAsyncExecute : NAPI_GetFormsInfoByModuleAsyncExecute,
        NAPI_GetFormsInfoPromiseComplete,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

// GetFormsInfo THREE ARGV
napi_value GetFormsInfoThreeArgv(napi_env env, napi_value *argv, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s.", __func__);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ONE], &valueType));
    std::string moduleNameInfo = GetStringFromNAPI(env, argv[ARGS_SIZE_ONE]);
    HILOG_INFO("%{public}s, moduleNameInfo=%{public}s.", __func__, moduleNameInfo.c_str());
    asyncCallbackInfo->moduleName = moduleNameInfo;

    // Check the value type of the arguments
    valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
    NAPI_ASSERT(env, valueType == napi_function, "The arguments[2] type of getFormsInfo is incorrect, "
        "expected type is function.");
    napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
    return GetFormsInfoCallback(env, asyncCallbackInfo, false);
}

// GetFormsInfo TWO ARGV
napi_value GetFormsInfoTwoArgv(napi_env env, napi_value *argv, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s.", __func__);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ONE], &valueType));

    // GetFormsInfoByModule promise
    if (valueType == napi_string) {
        std::string moduleNameInfo = GetStringFromNAPI(env, argv[ARGS_SIZE_ONE]);
        HILOG_INFO("%{public}s, moduleNameInfo=%{public}s.", __func__, moduleNameInfo.c_str());
        asyncCallbackInfo->moduleName = moduleNameInfo;
        return GetFormsInfoPromise(env, asyncCallbackInfo, false);
    } else if (valueType == napi_function) { // GetFormsInfoByApp callback
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ONE], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of getFormsInfo is incorrect, "
            "expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_ONE], REF_COUNT, &asyncCallbackInfo->callback);
        return GetFormsInfoCallback(env, asyncCallbackInfo, true);
    } else {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .callbackValue = argv[1],
                .code = ERR_APPEXECFWK_FORM_INVALID_MODULENAME,
                .type = PROMISE_FLG
            };
        return RetErrMsg(asyncErrorInfo);
    }
}

/**
 * @brief  The implementation of Node-API interface: getFormsInfo
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_GetFormsInfo(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ZERO], &valueType));
    std::string bundleNameInfo = GetStringFromNAPI(env, argv[ARGS_SIZE_ZERO]);
    HILOG_INFO("%{public}s, bundleName=%{public}s.", __func__, bundleNameInfo.c_str());

    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = new
    AsyncGetFormsInfoCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formInfos = std::vector<OHOS::AppExecFwk::FormInfo>(),
        .bundleName = bundleNameInfo,
        .moduleName = "",
        .result = 0,
    };

    if (argc == ARGS_SIZE_THREE) { // GetFormsInfoByModule callback
        HILOG_INFO("%{public}s, ARGS_SIZE_THREE.", __func__);
        return GetFormsInfoThreeArgv(env, argv, asyncCallbackInfo);
    } else if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, ARGS_SIZE_TWO.", __func__);
        return GetFormsInfoTwoArgv(env, argv, asyncCallbackInfo);
    } else if (argc == ARGS_SIZE_ONE) { // GetFormsInfoByApp promise
        return GetFormsInfoPromise(env, asyncCallbackInfo, true);
    }
    return NapiGetResult(env, 1);
}

int64_t SystemTimeMillis() noexcept
{
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<int64_t>(((t.tv_sec) * NANOSECONDS + t.tv_nsec) / MICROSECONDS);
}

class ShareFormCallBackClient : public ShareFormCallBack,
                                public std::enable_shared_from_this<ShareFormCallBackClient> {
public:
    explicit ShareFormCallBackClient(ShareFormTask &&task) : task_(std::move(task))
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~ShareFormCallBackClient() = default;

    void ProcessShareFormResponse(int32_t result) override
    {
        if (handler_) {
            handler_->PostSyncTask([client = shared_from_this(), result] () {
                client->task_(result);
            });
        }
    }

private:
    ShareFormTask task_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
};

void JsFormHost::Finalizer(NativeEngine* engine, void* data, void* hint)
{
    HILOG_INFO("JsFormHost::Finalizer is called");
    std::unique_ptr<JsFormHost>(static_cast<JsFormHost*>(data));
}

NativeValue* JsFormHost::ShareForm(NativeEngine* engine, NativeCallbackInfo* info)
{
    JsFormHost* me = OHOS::AbilityRuntime::CheckParamsAndGetThis<JsFormHost>(engine, info);
    return (me != nullptr) ? me->OnShareForm(*engine, *info) : nullptr;
}

NativeValue* JsFormHost::OnShareForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_INFO("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    if (info.argc > ARGS_SIZE_THREE || info.argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        errCode = ERR_ADD_INVALID_PARAM;
    }

    std::string strFormId =
        ::GetStringFromNAPI(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(info.argv[0]));
    std::string remoteDeviceId =
        ::GetStringFromNAPI(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(info.argv[1]));
    // The promise form has only two parameters
    decltype(info.argc) unwrapArgc = 2;

    int64_t formId;
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("%{public}s, convert string formId to int64 failed.", __func__);
        errCode = ERR_COMMON;
    }
    if (formId == 0 || remoteDeviceId.empty()) {
        errCode = ERR_COMMON;
    }

    NativeValue* lastParam = (info.argc <= unwrapArgc) ? nullptr : info.argv[unwrapArgc];
    NativeValue* result = nullptr;

    std::unique_ptr<AbilityRuntime::AsyncTask> uasyncTask =
        AbilityRuntime::CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, nullptr, &result);
    std::shared_ptr<AbilityRuntime::AsyncTask> asyncTask = std::move(uasyncTask);

    ShareFormTask task = [&engine, asyncTask](int32_t code) {
        HILOG_INFO("%{public}s, task complete code: %{public}d", __func__, code);
        if (code == ERR_OK) {
            asyncTask->Resolve(engine, engine.CreateUndefined());
        } else {
            auto retCode = QueryRetCode(code);
            auto retMsg = QueryRetMsg(retCode);
            asyncTask->Reject(engine, AbilityRuntime::CreateJsError(engine, retCode, retMsg));
        }
    };

    if (errCode != ERR_OK) {
        asyncTask->Reject(engine, AbilityRuntime::CreateJsError(engine, errCode, "Invalidate params."));
    } else {
        InnerShareForm(engine, asyncTask, std::move(task), formId, remoteDeviceId);
    }

    return result;
}

void JsFormHost::InnerShareForm(
    NativeEngine &engine,
    const std::shared_ptr<AbilityRuntime::AsyncTask> &asyncTask,
    ShareFormTask &&task,
    int64_t formId,
    const std::string &remoteDeviceId)
{
    auto shareFormCallback = std::make_shared<ShareFormCallBackClient>(std::move(task));
    int64_t requestCode = SystemTimeMillis();
    FormHostClient::GetInstance()->AddShareFormCallback(shareFormCallback, requestCode);

    ErrCode ret = FormMgr::GetInstance().ShareForm(
        formId, remoteDeviceId, FormHostClient::GetInstance(), requestCode);
    if (ret != ERR_OK) {
        HILOG_INFO("%{public}s, share form failed.", __func__);
        auto retCode = QueryRetCode(ret);
        auto retMsg = QueryRetMsg(retCode);
        asyncTask->Reject(engine, AbilityRuntime::CreateJsError(engine, retCode, retMsg));
        FormHostClient::GetInstance()->RemoveShareFormCallback(requestCode);
    }
}
