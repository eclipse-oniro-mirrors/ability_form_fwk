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
#include <typeinfo>
#include <uv.h>
#include <vector>
#include <iostream>
#include <string>

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

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace {
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
    std::unique_ptr<AsyncNotifyVisibleFormsCallbackInfo> callbackPtr {asyncCallbackInfo};

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
        callbackPtr.release();
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
        callbackPtr.release();
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
    std::unique_ptr<AsyncNotifyInvisibleFormsCallbackInfo> callbackPtr {asyncCallbackInfo};

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
        callbackPtr.release();
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
        callbackPtr.release();
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

    auto *asyncCallbackInfo = new (std::nothrow) AsyncDeleteInvalidFormsCallbackInfo {.env = env, .formIds = formIds, };
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr.");
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_COMMON_CODE, callbackType, argv[1]));
    }
    std::unique_ptr<AsyncDeleteInvalidFormsCallbackInfo> callbackPtr {asyncCallbackInfo};

    napi_value result;
    if (argc == ARGS_SIZE_TWO) {
        // Check the value type of the arguments
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of args[1] is incorrect, expected type is function.");
        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
        result = DeleteInvalidFormsCallback(env, asyncCallbackInfo);
    } else {
        result = DeleteInvalidFormsPromise(env, asyncCallbackInfo);
    }
    callbackPtr.release();
    return result;
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

class FormUninstallCallbackClient : public std::enable_shared_from_this<FormUninstallCallbackClient>
{
public:
    FormUninstallCallbackClient(napi_env env, napi_ref callbackRef) : callbackRef_(callbackRef), env_(env)
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~FormUninstallCallbackClient()
    {
        napi_delete_reference(env_, callbackRef_);
    }

    void ProcessFormUninstall(const int64_t formId)
    {
        if (handler_ == nullptr) {
            HILOG_INFO("handler is nullptr");
            return;
        }
        handler_->PostSyncTask([thisWeakPtr = weak_from_this(), formId]() {
            auto sharedThis = thisWeakPtr.lock();
            if (sharedThis == nullptr) {
                HILOG_ERROR("sharedThis is nullptr.");
                return;
            }
            HILOG_DEBUG("task complete formId: form: %{public}" PRId64 ".", formId);
            std::string formIdString = std::to_string(formId);
            napi_value callbackValues;
            napi_create_string_utf8(sharedThis->env_, formIdString.c_str(), NAPI_AUTO_LENGTH, &callbackValues);
            napi_value callResult;
            napi_value myCallback = nullptr;
            napi_get_reference_value(sharedThis->env_, sharedThis->callbackRef_, &myCallback);
            if (myCallback != nullptr) {
                napi_call_function(sharedThis->env_, nullptr, myCallback, ARGS_SIZE_ONE, &callbackValues, &callResult);
            }
        });
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
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
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

    auto *asyncCallbackInfo = new (std::nothrow) AsyncAcquireFormStateCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .want = {},
        .stateInfo = {},
        .callbackType = callbackType,
        .result = ERR_OK,
    };
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr.");
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_COMMON_CODE, callbackType, argv[1]));
    }
    std::unique_ptr<AsyncAcquireFormStateCallbackInfo> callbackPtr {asyncCallbackInfo};

    bool parseResult = UnwrapWant(env, argv[0], asyncCallbackInfo->want);
    if (!parseResult) {
        HILOG_ERROR("%{public}s, failed to parse want.", __func__);
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_INVALID_PARAM, callbackType, argv[1]));
    }

    napi_value result;
    if (argc == ARGS_SIZE_TWO) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function,
            "The arguments[1] type of acquireFormState is incorrect, expected type is function.");
        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
        result = AcquireFormStateCallback(env, asyncCallbackInfo);
    } else {
        result = AcquireFormStatePromise(env, asyncCallbackInfo);
    }
    callbackPtr.release();
    return result;
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

    auto *asyncCallbackInfo = new (std::nothrow) AsyncNotifyFormsVisibleCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formIds = formIds,
        .isVisible = false,
    };
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr.");
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_COMMON_CODE, callbackType, argv[1]));
    }
    std::unique_ptr<AsyncNotifyFormsVisibleCallbackInfo> callbackPtr {asyncCallbackInfo};

    napi_get_value_bool(env, argv[1], &asyncCallbackInfo->isVisible);

    napi_value result;
    if (argc == ARGS_SIZE_THREE) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of arg 2 is incorrect, expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
        result = NotifyFormsVisibleCallback(env, asyncCallbackInfo);
    } else {
        result = NotifyFormsVisiblePromise(env, asyncCallbackInfo);
    }

    callbackPtr.release();
    return result;
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

    auto *asyncCallbackInfo = new (std::nothrow) AsyncNotifyFormsEnableUpdateCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formIds = formIds,
        .isEnableUpdate = false,
    };
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr.");
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_COMMON_CODE, callbackType, argv[1]));
    }
    std::unique_ptr<AsyncNotifyFormsEnableUpdateCallbackInfo> callbackPtr {asyncCallbackInfo};

    napi_get_value_bool(env, argv[1], &asyncCallbackInfo->isEnableUpdate);

    napi_value result;
    if (argc == ARGS_SIZE_THREE) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of arg 2 is incorrect, expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
        result = NotifyFormsEnableUpdateCallback(env, asyncCallbackInfo);
    } else {
        result = NotifyFormsEnableUpdatePromise(env, asyncCallbackInfo);
    }
    callbackPtr.release();
    return result;
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

void NapiFormHost::Finalizer(NativeEngine *engine, void *data, void *hint)
{
    HILOG_DEBUG("NapiFormHost::Finalizer is called");
    std::unique_ptr<NapiFormHost>(static_cast<NapiFormHost*>(data));
}

NativeValue* NapiFormHost::ShareForm(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnShareForm(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::DisableFormsUpdate(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnDisableFormsUpdate(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::IsSystemReady(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnIsSystemReady(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::GetAllFormsInfo(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnGetAllFormsInfo(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::GetFormsInfo(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnGetFormsInfo(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::DeleteForm(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnDeleteForm(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::ReleaseForm(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnReleaseForm(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::RequestForm(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnRequestForm(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::CastTempForm(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnCastTempForm(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::EnableFormsUpdate(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost *me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnEnableFormsUpdate(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::OnShareForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    if (info.argc > ARGS_SIZE_THREE || info.argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("wrong number of arguments.");
        errCode = ERR_ADD_INVALID_PARAM;
    }

    std::string strFormId =
        GetStringFromNAPI(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(info.argv[0]));
    std::string remoteDeviceId =
        GetStringFromNAPI(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(info.argv[1]));
    // The promise form has only two parameters
    decltype(info.argc) unwrapArgc = 2;

    int64_t formId = 0;
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert string formId to int64 failed.");
        errCode = ERR_COMMON;
    }
    if (formId == 0 || remoteDeviceId.empty()) {
        errCode = ERR_COMMON;
    }

    NativeValue *lastParam = (info.argc <= unwrapArgc) ? nullptr : info.argv[unwrapArgc];
    NativeValue *result = nullptr;

    std::unique_ptr<AbilityRuntime::AsyncTask> uasyncTask =
        AbilityRuntime::CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, nullptr, &result);
    std::shared_ptr<AbilityRuntime::AsyncTask> asyncTask = std::move(uasyncTask);

    ShareFormTask task = [&engine, asyncTask](int32_t code) {
        HILOG_DEBUG("task complete code: %{public}d", code);
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

NativeValue* NapiFormHost::OnDisableFormsUpdate(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
        HILOG_ERROR("wrong number of arguments!");
        return engine.CreateUndefined();
    }

    if (!(info.argv[PARAM0]->IsArray())) {
        HILOG_ERROR("input params is not array!");
        errCode = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR;
    }
    std::vector<string> strFormIdList;
    if (!GetStringsValue(engine, info.argv[PARAM0], strFormIdList)) {
        HILOG_ERROR("conversion string failed!");
        errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
    }
    if (strFormIdList.empty()) {
        HILOG_ERROR("formId list is empty!");
        errCode = ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR;
    }
    std::vector<int64_t> iFormIds;
    for (size_t i = 0; i < strFormIdList.size(); i++) {
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormIdList[i], formIdValue)) {
            HILOG_ERROR("conversion int failed!");
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        } else {
            iFormIds.push_back(formIdValue);
        }
    }

    auto complete = [formIds = iFormIds, errCode](NativeEngine &engine, AsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            auto code = QueryRetCode(errCode);
            task.Reject(engine, CreateJsError(engine, code, QueryRetMsg(code)));
            return;
        }
        auto ret = FormMgr::GetInstance().LifecycleUpdate(formIds, FormHostClient::GetInstance(), false);
        if (ret != ERR_OK) {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        task.Resolve(engine, CreateJsValue(engine, ret));
    };

    auto callback = (info.argc == ARGS_ONE) ? nullptr : info.argv[PARAM1];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("NapiFormHost::OnDisableFormsUpdate",
        engine, CreateAsyncTaskWithLastParam(engine, callback, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* NapiFormHost::OnIsSystemReady(NativeEngine &engine, const NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (info.argc > ARGS_ONE || info.argc < ARGS_ZERO) {
        HILOG_ERROR("wrong number of arguments.");
        return engine.CreateUndefined();
    }

    auto complete = [](NativeEngine &engine, AsyncTask &task, int32_t status) {
        // Use original logic.
        // Use the error code to return whether the function executed successfully.
        auto ret = FormMgr::GetInstance().CheckFMSReady() ? 0 : 1;
        if (ret == ERR_OK) {
            task.Resolve(engine, engine.CreateUndefined());
        } else {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
        }
    };

    auto callback = (info.argc == ARGS_ZERO) ? nullptr : info.argv[PARAM0];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("NapiFormHost::OnIsSystemReady",
        engine, CreateAsyncTaskWithLastParam(engine, callback, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* NapiFormHost::OnGetAllFormsInfo(NativeEngine &engine, const NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (info.argc > ARGS_ONE || info.argc < ARGS_ZERO) {
        HILOG_ERROR("wrong number of arguments!");
        return engine.CreateUndefined();
    }

    auto complete = [](NativeEngine &engine, AsyncTask &task, int32_t status) {
        std::vector<FormInfo> formInfos;
        auto ret = FormMgr::GetInstance().GetAllFormsInfo(formInfos);
        if (ret != ERR_OK) {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        task.Resolve(engine, CreateFormInfos(engine, formInfos));
    };

    auto callback = (info.argc == ARGS_ZERO) ? nullptr : info.argv[PARAM0];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("NapiFormHost::OnGetAllFormsInfo",
        engine, CreateAsyncTaskWithLastParam(engine, callback, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* NapiFormHost::OnGetFormsInfo(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    if (info.argc > ARGS_THREE || info.argc < ARGS_ONE) {
        HILOG_ERROR("wrong number of arguments!");
        return engine.CreateUndefined();
    }

    std::string bName("");
    if (!ConvertFromJsValue(engine, info.argv[PARAM0], bName)) {
        HILOG_ERROR("conversion failed!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME;
    }

    std::string mName("");
    bool bParam = false;
    bool flagCall = UnwrapGetFormsInfoParams(engine, info, mName, bParam);
    auto complete = [bName, mName, bParam, errCode](NativeEngine &engine, AsyncTask &task, int32_t status) {
        std::string bundleName(bName);
        std::string moduleName(mName);
        std::vector<FormInfo> formInfos;
        if (errCode != ERR_OK) {
            auto retCode = QueryRetCode(errCode);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        int ret = ERR_OK;
        if (!bParam) {
            ret = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
        } else {
            ret = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
        }

        if (ret != ERR_OK) {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        task.Resolve(engine, CreateFormInfos(engine, formInfos));
    };

    NativeValue *result = nullptr;
    auto callback = flagCall ? ((info.argc == ARGS_TWO) ? info.argv[PARAM1] : info.argv[PARAM2]) : nullptr;
    AsyncTask::Schedule("NapiFormHost::OnGetFormsInfo",
        engine, CreateAsyncTaskWithLastParam(engine, callback, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* NapiFormHost::OnDeleteForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
        HILOG_ERROR("OnDeleteForm wrong number of arguments.");
        return engine.CreateUndefined();
    }
    if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
        HILOG_ERROR("input params is not string!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    } else {
        std::string strFormId;
        if (!ConvertFromJsValue(engine, info.argv[PARAM0], strFormId)) {
            HILOG_ERROR("conversion failed!");
            return engine.CreateUndefined();
        }
        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("OnDeleteForm convert string formId to int64 failed.");
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        }
    }
    AsyncTask::CompleteCallback complete = [formId, errCode](NativeEngine &engine, AsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            auto retCode = QueryRetCode(errCode);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        auto ret = FormMgr::GetInstance().DeleteForm(formId, FormHostClient::GetInstance());
        if (ret == ERR_OK) {
            auto result = QueryRetCode(ret);
            task.Resolve(engine, CreateJsValue(engine, result));
        } else {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
        }
    };

    NativeValue* lastParam = (info.argc == ARGS_ONE) ? nullptr : info.argv[PARAM1];
    NativeValue* result = nullptr;
    AsyncTask::Schedule("NapiFormHost::OnDeleteForm",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* NapiFormHost::OnReleaseForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    bool isReleaseCache = false;
    if (info.argc > ARGS_THREE || info.argc < ARGS_ONE) {
        HILOG_ERROR("OnReleaseForm wrong number of arguments.");
        return engine.CreateUndefined();
    }
    if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
        HILOG_ERROR("input params is not string!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    } else {
        std::string strFormId;
        if (!ConvertFromJsValue(engine, info.argv[PARAM0], strFormId)) {
            HILOG_ERROR("conversion failed!");
            return engine.CreateUndefined();
        }
        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("OnReleaseForm convert string formId to int64 failed.");
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        } else if ((info.argc == ARGS_TWO || info.argc == ARGS_THREE) &&
            info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
            if (info.argv[PARAM1]->TypeOf() == NATIVE_BOOLEAN) {
                if (!ConvertFromJsValue(engine, info.argv[PARAM1], isReleaseCache)) {
                    HILOG_ERROR("conversion bool failed!");
                    return engine.CreateUndefined();
                }
            } else {
                HILOG_ERROR("promise second param type is illegal");
                errCode = ERR_APPEXECFWK_FORM_RELEASE_FLG_ERR;
            }
        }
    }

    AsyncTask::CompleteCallback complete = [formId, errCode, isReleaseCache]
        (NativeEngine &engine, AsyncTask &task, int32_t status) {
            auto ret = ERR_COMMON;
            if (errCode != ERR_OK) {
                auto retCode = QueryRetCode(errCode);
                task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
                return ;
            }
            ret = FormMgr::GetInstance().ReleaseForm(formId, FormHostClient::GetInstance(), isReleaseCache);
            if (ret == ERR_OK) {
                auto result = QueryRetCode(ret);
                task.Resolve(engine, CreateJsValue(engine, result));
            } else {
                auto retCode = QueryRetCode(ret);
                task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
                return;
            }
    };

    NativeValue* lastParam = (info.argc == ARGS_ONE) ? nullptr :
        (info.argc == ARGS_TWO && info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) ? nullptr :
        (info.argc == ARGS_THREE) ? info.argv[PARAM2] : info.argv[PARAM1];
    NativeValue* result = nullptr;
    AsyncTask::Schedule("NapiFormHost::OnReleaseForm",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* NapiFormHost::OnRequestForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return engine.CreateUndefined();
    }
    if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
        HILOG_ERROR("input params is not string!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    } else {
        std::string strFormId;
        if (!ConvertFromJsValue(engine, info.argv[PARAM0], strFormId)) {
            HILOG_ERROR("conversion failed!");
            return engine.CreateUndefined();
        }
        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("%{public}s, convert string formId to int64 failed.", __func__);
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        }
    }
    AsyncTask::CompleteCallback complete = [formId, errCode](NativeEngine &engine, AsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            auto retCode = QueryRetCode(errCode);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        Want want;
        auto ret = FormMgr::GetInstance().RequestForm(formId, FormHostClient::GetInstance(), want);
        if (ret == ERR_OK) {
            auto result = QueryRetCode(ret);
            task.Resolve(engine, CreateJsValue(engine, result));
        } else {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
        }
    };

    NativeValue* lastParam = (info.argc == ARGS_ONE) ? nullptr : info.argv[PARAM1];
    NativeValue* result = nullptr;
    AsyncTask::Schedule("NapiFormHost::OnRequestForm",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* NapiFormHost::OnCastTempForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    if (info.argc > ARGS_TWO || info.argc < ARGS_ONE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return engine.CreateUndefined();
    }
    if (info.argv[PARAM0]->TypeOf() != NATIVE_STRING) {
        HILOG_ERROR("input params is not string!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    } else {
        std::string strFormId;
        if (!ConvertFromJsValue(engine, info.argv[PARAM0], strFormId)) {
            HILOG_ERROR("conversion failed!");
            return engine.CreateUndefined();
        }
        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("%{public}s, convert string formId to int64 failed.", __func__);
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        }
    }
    AsyncTask::CompleteCallback complete = [formId, errCode](NativeEngine &engine, AsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            auto retCode = QueryRetCode(errCode);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            return;
        }
        auto ret = FormMgr::GetInstance().CastTempForm(formId, FormHostClient::GetInstance());
        if (ret == ERR_OK) {
            auto result = QueryRetCode(ret);
            task.Resolve(engine, CreateJsValue(engine, result));
        } else {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
        }
    };

    NativeValue* lastParam = (info.argc == ARGS_ONE) ? nullptr : info.argv[PARAM1];
    NativeValue* result = nullptr;
    AsyncTask::Schedule("NapiFormHost::OnCastTempForm",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}

NativeValue* NapiFormHost::OnEnableFormsUpdate(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);

    int32_t errCode = ERR_OK;
    std::vector<int64_t> iFormIds;
    if (info.argc > ARGS_TWO|| info.argc < ARGS_ONE) {
        HILOG_ERROR("wrong number of arguments!");
        return engine.CreateUndefined();
    }
    if (!(info.argv[PARAM0]->IsArray())) {
        HILOG_ERROR("input params0 is not array!");
        errCode = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR;
    } else {
        std::vector<string> strFormIdList;
        if (!GetStringsValue(engine, info.argv[PARAM0], strFormIdList)) {
            HILOG_ERROR("conversion string failed!");
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        }
        for (size_t i = 0; i < strFormIdList.size(); i++) {
            int64_t formIdValue;
            if (!ConvertStringToInt64(strFormIdList[i], formIdValue)) {
                HILOG_ERROR("conversion int failed!");
                errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
            } else {
                iFormIds.push_back(formIdValue);
            }
        }
    }
    auto complete = [iFormIds, errCode](NativeEngine &engine, AsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            auto code = QueryRetCode(errCode);
            task.Reject(engine, CreateJsError(engine, code, QueryRetMsg(code)));
            return;
        }
        auto ret = FormMgr::GetInstance().LifecycleUpdate(iFormIds, FormHostClient::GetInstance(), true);
        if (ret == ERR_OK) {
            auto result = QueryRetCode(ret);
            task.Resolve(engine, CreateJsValue(engine, result));
        } else {
            auto retCode = QueryRetCode(ret);
            task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
        }
    };

    auto callback = (info.argc == ARGS_ONE) ? nullptr : info.argv[PARAM1];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("NapiFormHost::OnEnableFormsUpdate",
        engine, CreateAsyncTaskWithLastParam(engine, callback, nullptr, std::move(complete), &result));
    return result;
}

bool NapiFormHost::GetStringsValue(NativeEngine &engine, NativeValue *object, std::vector<std::string> &strList)
{
    auto array = ConvertNativeValueTo<NativeArray>(object);
    if (array == nullptr) {
        HILOG_ERROR("input params error");
        return false;
    }

    for (uint32_t i = 0; i < array->GetLength(); i++) {
        std::string itemStr("");
        if ((array->GetElement(i))->TypeOf() != NATIVE_STRING) {
            HILOG_ERROR("GetElement is not string");
            return false;
        }
        if (!ConvertFromJsValue(engine, array->GetElement(i), itemStr)) {
            HILOG_ERROR("GetElement from to array [%{public}u] error", i);
            return false;
        }
        strList.push_back(itemStr);
    }

    return true;
}

bool NapiFormHost::UnwrapGetFormsInfoParams(
    NativeEngine &engine, NativeCallbackInfo &info, std::string &moduleName, bool &bParam)
{
    bool flagCall = true;
    if (info.argc == ARGS_ONE) {
        flagCall = false;
        bParam = false;
    } else if (info.argc == ARGS_TWO && info.argv[PARAM1]->TypeOf() != NATIVE_FUNCTION) {
        if (!ConvertFromJsValue(engine, info.argv[PARAM1], moduleName)) {
            HILOG_WARN("input params string error");
        }
        flagCall = false;
        bParam = true;
    } else if (info.argc == ARGS_TWO && info.argv[PARAM1]->TypeOf() == NATIVE_FUNCTION) {
        bParam = false;
    } else if (info.argc == ARGS_THREE) {
        if (!ConvertFromJsValue(engine, info.argv[PARAM1], moduleName)) {
            HILOG_WARN("input params string error");
        }
        bParam = true;
    }

    return flagCall;
}

void NapiFormHost::InnerShareForm(
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

NativeValue* NapiFormHost::NotifyFormsPrivacyProtected(NativeEngine *engine, NativeCallbackInfo *info)
{
    NapiFormHost* me = OHOS::AbilityRuntime::CheckParamsAndGetThis<NapiFormHost>(engine, info);
    return (me != nullptr) ? me->OnNotifyFormsPrivacyProtected(*engine, *info) : nullptr;
}

NativeValue* NapiFormHost::OnNotifyFormsPrivacyProtected(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_INFO("%{public}s is called", __func__);
    if (info.argc > ARGS_SIZE_THREE || info.argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }

    ErrCode errCode = ERR_OK;
    std::vector<int64_t> formIds {};
    GetFormIds(reinterpret_cast<napi_env>(&engine), reinterpret_cast<napi_value>(info.argv[0]),
        errCode, formIds);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get formIds faild, code is %{public}d", errCode);
        return nullptr;
    }

    // The promise form has only two parameters
    decltype(info.argc) unwrapArgc = 2;
    bool isProtected = false;

    if (!ConvertFromJsValue(engine, info.argv[1], isProtected)) {
        HILOG_ERROR("convert from Js value failed!");
        return nullptr;
    }

    AsyncTask::CompleteCallback complete =
        [formIds, isProtected, errCode](NativeEngine &engine, AsyncTask &task, int32_t status) {
            if (errCode != ERR_OK) {
                HILOG_ERROR("task reject, code is %{public}d", errCode);
                task.Reject(engine, CreateJsError(engine, errCode, QueryRetMsg(errCode)));
                return;
            }

            auto ret = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds,
                isProtected, FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.Resolve(engine, engine.CreateUndefined());
            } else {
                HILOG_ERROR("task reject, result code is %{public}d", ret);
                auto retCode = QueryRetCode(ret);
                task.Reject(engine, CreateJsError(engine, retCode, QueryRetMsg(retCode)));
            }
        };

    NativeValue *lastParam = (info.argc <= unwrapArgc) ? nullptr : info.argv[unwrapArgc];
    NativeValue *result = nullptr;
    AsyncTask::Schedule("NapiFormHost::OnNotifyFormsPrivacyProtected",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}
}  // namespace AbilityRuntime
}  // namespace OHOS