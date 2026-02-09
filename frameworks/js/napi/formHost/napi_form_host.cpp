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

#include "napi_form_host.h"

#include <cinttypes>
#include <regex>
#include <typeinfo>
#include <uv.h>
#include <vector>
#include <iostream>
#include <string>

#include "fms_log_wrapper.h"
#include "form_info.h"
#include "form_callback_interface.h"
#include "form_host_client.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
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

    struct OnDeleteInvalidFormsS {
        int result;
        int32_t numFormsDeleted = 0;
        std::vector<int64_t> iFormIds;
    };
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

napi_value ParseFormStateInfo(napi_env env, FormStateInfo &stateInfo)
{
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    if (scope == nullptr) {
        return nullptr;
    }
    napi_value formStateInfoObject = nullptr;
    napi_create_object(env, &formStateInfoObject);
    napi_value jsValue = WrapWant(env, stateInfo.want);
    SetPropertyValueByPropertyName(env, formStateInfoObject, "want", jsValue);
    napi_value formState = nullptr;
    napi_create_int32(env, (int32_t) stateInfo.state, &formState);
    SetPropertyValueByPropertyName(env, formStateInfoObject, "formState", formState);
    napi_close_handle_scope(env, scope);
    return formStateInfoObject;
}

void AcquireFormStateCallbackComplete(uv_work_t *work, int32_t status)
{
    HILOG_INFO("call");
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
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
            delete work;
            work = nullptr;
            return;
        }
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
        napi_close_handle_scope(env, scope);
    }

    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
    delete work;
    work = nullptr;
    HILOG_INFO("end");
}

void AcquireFormStatePromiseComplete(uv_work_t *work, int32_t status)
{
    HILOG_INFO("onAcquireFormState back");
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
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
            delete work;
            work = nullptr;
            return;
        }
        napi_value result;
        InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
        napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
        napi_close_handle_scope(env, scope);
    } else {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            delete asyncCallbackInfo;
            asyncCallbackInfo = nullptr;
            delete work;
            work = nullptr;
            return;
        }
        napi_value result = ParseFormStateInfo(env, asyncCallbackInfo->stateInfo);
        napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
        napi_close_handle_scope(env, scope);
    }

    delete asyncCallbackInfo;
    asyncCallbackInfo = nullptr;
    delete work;
    work = nullptr;
    HILOG_INFO("onAcquireFormState done");
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
            result = uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {},
                AcquireFormStateCallbackComplete, uv_qos_default);
        } else {
            result = uv_queue_work_with_qos(loop, work, [](uv_work_t *work) {},
                AcquireFormStatePromiseComplete, uv_qos_default);
        }
        // When uv_queue_work_with_qos returns 0, asyncCallbackInfo_ and work will be freed in the callback function.
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

class FormUninstallCallbackClient : public std::enable_shared_from_this<FormUninstallCallbackClient> {
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
            HILOG_INFO("handler is null");
            return;
        }
        handler_->PostSyncTask([thisWeakPtr = weak_from_this(), formId]() {
            auto sharedThis = thisWeakPtr.lock();
            if (sharedThis == nullptr) {
                HILOG_ERROR("sharedThis is null.");
                return;
            }
            HILOG_DEBUG("task end formId: form: %{public}" PRId64 ".", formId);
            std::string formIdString = std::to_string(formId);
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(sharedThis->env_, &scope);
            if (scope == nullptr) {
                HILOG_ERROR("null scope");
                return;
            }
            napi_value callbackValues;
            napi_create_string_utf8(sharedThis->env_, formIdString.c_str(), NAPI_AUTO_LENGTH, &callbackValues);
            napi_value callResult;
            napi_value myCallback = nullptr;
            napi_get_reference_value(sharedThis->env_, sharedThis->callbackRef_, &myCallback);
            if (myCallback != nullptr) {
                napi_call_function(sharedThis->env_, nullptr, myCallback, ARGS_SIZE_ONE, &callbackValues, &callResult);
            }
            napi_close_handle_scope(sharedThis->env_, scope);
        });
    }

    bool IsStrictEqual(napi_value callback)
    {
        bool isEqual = false;
        napi_value myCallback = nullptr;
        napi_get_reference_value(env_, callbackRef_, &myCallback);
        napi_strict_equals(env_, myCallback, callback, &isEqual);
        HILOG_INFO("isStrictEqual:%{public}d", isEqual);
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
            HILOG_INFO("equal callback");
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

napi_value AcquireFormStateCallback(napi_env env, napi_value callbackFunc,
    AsyncAcquireFormStateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("asyncCallback.");
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, callbackFunc, &valueType));
    NAPI_ASSERT(env, valueType == napi_function, "expected type is function.");
    napi_create_reference(env, callbackFunc, REF_COUNT, &asyncCallbackInfo->callback);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("napi_create_async_work running");
            auto *asyncCallbackInfo = static_cast<AsyncAcquireFormStateCallbackInfo*>(data);
            if (asyncCallbackInfo == nullptr) {
                HILOG_ERROR("null asyncCallbackInfo");
                return;
            }
            InnerAcquireFormState(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("napi_create_async_work complete");
            auto *asyncCallbackInfo = static_cast<AsyncAcquireFormStateCallbackInfo*>(data);
            if (asyncCallbackInfo == nullptr) {
                HILOG_ERROR("null asyncCallbackInfo");
                return;
            }
            // asyncCallbackInfo will be freed in OnAcquireState, so save the member variable asyncWork.
            napi_async_work asyncWork = asyncCallbackInfo->asyncWork;
            // When the result is not ERR_OK, OnAcquireState will be called here,
            // else OnAcquireState will be called after the form state is acquired.
            if (asyncCallbackInfo->result != ERR_OK) {
                FormHostClient::GetInstance()->OnAcquireState(FormState::UNKNOWN, asyncCallbackInfo->want);
            }
            if (asyncWork != nullptr) {
                napi_delete_async_work(env, asyncWork);
            }
            delete asyncCallbackInfo;
        }, (void *) asyncCallbackInfo, &asyncCallbackInfo->asyncWork);
    napi_status status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default);
    if (status != napi_ok) {
        HILOG_ERROR("async work failed!");
        if (asyncCallbackInfo->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        }
        delete asyncCallbackInfo;
        return nullptr;
    }
    return NapiGetResult(env, 1);
}

napi_value AcquireFormStatePromise(napi_env env, AsyncAcquireFormStateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("promise.");
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("runnning");
            auto *asyncCallbackInfo = static_cast<AsyncAcquireFormStateCallbackInfo*>(data);
            if (asyncCallbackInfo == nullptr) {
                HILOG_ERROR("null asyncCallbackInfo");
                return;
            }
            InnerAcquireFormState(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("complete");
            auto *asyncCallbackInfo = static_cast<AsyncAcquireFormStateCallbackInfo*>(data);
            if (asyncCallbackInfo == nullptr) {
                HILOG_ERROR("null asyncCallbackInfo");
                return;
            }
            // asyncCallbackInfo will be freed in OnAcquireState, so save the member variable asyncWork.
            napi_async_work asyncWork = asyncCallbackInfo->asyncWork;
            // When the result is not ERR_OK, OnAcquireState will be called here,
            // else OnAcquireState will be called after the form state is acquired.
            if (asyncCallbackInfo->result != ERR_OK) {
                FormHostClient::GetInstance()->OnAcquireState(FormState::UNKNOWN, asyncCallbackInfo->want);
            }
            if (asyncWork != nullptr) {
                napi_delete_async_work(env, asyncWork);
            }
            delete asyncCallbackInfo;
        }, (void *) asyncCallbackInfo, &asyncCallbackInfo->asyncWork);
    napi_status status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default);
    if (status != napi_ok) {
        HILOG_ERROR("async work failed!");
        if (asyncCallbackInfo->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        }
        delete asyncCallbackInfo;
        return nullptr;
    }
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
    HILOG_INFO("call");

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("argc:[%{public}zu]", argc);

    int32_t callbackType = (argc == ARGS_SIZE_TWO) ? CALLBACK_FLG : PROMISE_FLG;
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_object) {
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_INVALID_PARAM, callbackType, argv[1]));
    }

    auto asyncCallbackInfoPtr = std::make_unique<AsyncAcquireFormStateCallbackInfo>();
    if (!asyncCallbackInfoPtr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr.");
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_COMMON_CODE, callbackType, argv[1]));
    }

    asyncCallbackInfoPtr->env = env;
    asyncCallbackInfoPtr->callbackType = callbackType;
    asyncCallbackInfoPtr->result = ERR_OK;

    if (!UnwrapWant(env, argv[0], asyncCallbackInfoPtr->want)) {
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
        result = AcquireFormStateCallback(env, argv[1], asyncCallbackInfoPtr.release());
    } else {
        result = AcquireFormStatePromise(env, asyncCallbackInfoPtr.release());
    }
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
    HILOG_INFO("call");

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("argc:[%{public}zu]", argc);

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
    HILOG_INFO("call");

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr, nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("argc:[%{public}zu]", argc);

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

static void NotifyFormsVisibleCallbackComplete(napi_env env, napi_status, void *data)
{
    auto *asyncCallbackInfo = static_cast<AsyncNotifyFormsVisibleCallbackInfo*>(data);
    if (asyncCallbackInfo) {
        if (asyncCallbackInfo->callback) {
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(env, &scope);
            napi_value callback = nullptr;
            napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr, nullptr};
            InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, callbackValues);

            napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
            napi_value callResult = nullptr;
            napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
            napi_delete_reference(env, asyncCallbackInfo->callback);
            napi_close_handle_scope(env, scope);
        }
        if (asyncCallbackInfo->asyncWork) napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
    }
}

napi_value NotifyFormsVisibleCallback(napi_env env, napi_value callbackFunc,
    AsyncNotifyFormsVisibleCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("start");
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, callbackFunc, &valueType));
    NAPI_ASSERT(env, valueType == napi_function, "expected type is function.");
    napi_create_reference(env, callbackFunc, REF_COUNT, &asyncCallbackInfo->callback);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("running");
            auto *asyncCallbackInfo = static_cast<AsyncNotifyFormsVisibleCallbackInfo*>(data);
            if (asyncCallbackInfo == nullptr) {
                HILOG_ERROR("null asyncCallbackInfo");
                return;
            }
            InnerNotifyFormsVisible(env, asyncCallbackInfo);
        },
        NotifyFormsVisibleCallbackComplete,
        (void *) asyncCallbackInfo, &asyncCallbackInfo->asyncWork);
    napi_status status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default);
    if (status != napi_ok) {
        HILOG_ERROR("async work failed!");
        if (asyncCallbackInfo->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        }
        if (asyncCallbackInfo->callback != nullptr) {
            napi_delete_reference(env, asyncCallbackInfo->callback);
        }
        return nullptr;
    }
    return NapiGetResult(env, 1);
}

napi_value NotifyFormsVisiblePromise(napi_env env, AsyncNotifyFormsVisibleCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("NotifyFormsVisiblePromise start");
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("promise runnning");
            auto *asyncCallbackInfo = static_cast<AsyncNotifyFormsVisibleCallbackInfo*>(data);
            if (asyncCallbackInfo == nullptr) {
                HILOG_ERROR("null asyncCallbackInfo");
                return;
            }
            InnerNotifyFormsVisible(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("promise complete");
            auto *asyncCallbackInfo = static_cast<AsyncNotifyFormsVisibleCallbackInfo*>(data);
            if (asyncCallbackInfo == nullptr) {
                HILOG_ERROR("null asyncCallbackInfo");
                return;
            }
            napi_value result;
            InnerCreatePromiseRetMsg(env, asyncCallbackInfo->result, &result);
            if (asyncCallbackInfo->result == ERR_OK) {
                napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            } else {
                napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            }
            if (asyncCallbackInfo->asyncWork) {
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            }
            delete asyncCallbackInfo;
        }, (void *) asyncCallbackInfo, &asyncCallbackInfo->asyncWork);
    napi_status status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default);
    if (status != napi_ok) {
        HILOG_ERROR("async work failed!");
        if (asyncCallbackInfo->asyncWork) {
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        }
        return nullptr;
    }
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
    HILOG_INFO("call");

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

    auto asyncCallbackInfoPtr = std::make_unique<AsyncNotifyFormsVisibleCallbackInfo>();
    if (!asyncCallbackInfoPtr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr.");
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_COMMON_CODE, callbackType, argv[1]));
    }
    asyncCallbackInfoPtr->env = env;
    asyncCallbackInfoPtr->formIds = formIds;
    asyncCallbackInfoPtr->isVisible = false;

    napi_get_value_bool(env, argv[1], &asyncCallbackInfoPtr->isVisible);

    napi_value result;
    if (argc == ARGS_SIZE_THREE) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of arg 2 is incorrect, expected type is function.");
        result = NotifyFormsVisibleCallback(env, argv[ARGS_SIZE_TWO], asyncCallbackInfoPtr.release());
    } else {
        result = NotifyFormsVisiblePromise(env, asyncCallbackInfoPtr.release());
    }
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

static void NotifyFormsEnableUpdateCallbackComplete(napi_env env, napi_status status, void *data)
{
    HILOG_INFO("complete");
    auto *asyncCallbackInfo = static_cast<AsyncNotifyFormsEnableUpdateCallbackInfo*>(data);
    if (asyncCallbackInfo) {
        if (asyncCallbackInfo->callback != nullptr) {
            napi_value callback;
            napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr, nullptr};
            InnerCreateCallbackRetMsg(env, asyncCallbackInfo->result, callbackValues);

            napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
            napi_value callResult;
            napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
            napi_delete_reference(env, asyncCallbackInfo->callback);
        }
        if (asyncCallbackInfo->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        }
        delete asyncCallbackInfo;
    }
}

napi_value NotifyFormsEnableUpdateCallback(napi_env env, napi_value callbackFunc,
    AsyncNotifyFormsEnableUpdateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("enter");
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, callbackFunc, &valueType));
    NAPI_ASSERT(env, valueType == napi_function, "expected type is function.");
    napi_create_reference(env, callbackFunc, REF_COUNT, &asyncCallbackInfo->callback);
    napi_create_async_work(
        env, nullptr, resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("running");
            auto *asyncCallbackInfo = static_cast<AsyncNotifyFormsEnableUpdateCallbackInfo*>(data);
            if (asyncCallbackInfo == nullptr) {
                HILOG_ERROR("null asyncCallbackInfo");
                return;
            }
            InnerNotifyFormsEnableUpdate(env, asyncCallbackInfo);
        },
        NotifyFormsEnableUpdateCallbackComplete,
        (void *) asyncCallbackInfo, &asyncCallbackInfo->asyncWork);
    napi_status status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default);
    if (status != napi_ok) {
        HILOG_ERROR("async work failed!");
        if (asyncCallbackInfo->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        }
        if (asyncCallbackInfo->callback != nullptr) {
            napi_delete_reference(env, asyncCallbackInfo->callback);
        }
        delete asyncCallbackInfo;
        return nullptr;
    }
    return NapiGetResult(env, 1);
}

napi_value NotifyFormsEnableUpdatePromise(napi_env env,
                                          AsyncNotifyFormsEnableUpdateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("enter");
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
            HILOG_INFO("runnning");
            auto *asyncCallbackInfo = (AsyncNotifyFormsEnableUpdateCallbackInfo *) data;
            InnerNotifyFormsEnableUpdate(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("complete");
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
        }, (void *) asyncCallbackInfo, &asyncCallbackInfo->asyncWork);
    napi_status status = napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default);
    if (status != napi_ok) {
        HILOG_ERROR("async work failed!");
        if (asyncCallbackInfo->asyncWork != nullptr) {
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        }
        delete asyncCallbackInfo;
        return nullptr;
    }
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
    HILOG_INFO("call");

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

    auto asyncCallbackInfoPtr = std::make_unique<AsyncNotifyFormsEnableUpdateCallbackInfo>();
    if (!asyncCallbackInfoPtr) {
        HILOG_ERROR("asyncCallbackInfo == nullptr.");
        return RetErrMsg(InitErrMsg(env, ERR_APPEXECFWK_FORM_COMMON_CODE, callbackType, argv[1]));
    }
    asyncCallbackInfoPtr->env = env;
    asyncCallbackInfoPtr->formIds = formIds;
    asyncCallbackInfoPtr->isEnableUpdate = false;

    napi_get_value_bool(env, argv[1], &asyncCallbackInfoPtr->isEnableUpdate);

    napi_value result;
    if (argc == ARGS_SIZE_THREE) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of arg 2 is incorrect, expected type is function.");
        result = NotifyFormsEnableUpdateCallback(env, argv[ARGS_SIZE_TWO], asyncCallbackInfoPtr.release());
    } else {
        result = NotifyFormsEnableUpdatePromise(env, asyncCallbackInfoPtr.release());
    }
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

void NapiFormHost::Finalizer(napi_env env, void *data, void *hint)
{
    HILOG_DEBUG("NapiFormHost::Finalizer is called");
    std::unique_ptr<NapiFormHost>(static_cast<NapiFormHost*>(data));
}

napi_value NapiFormHost::ShareForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnShareForm);
}

napi_value NapiFormHost::DisableFormsUpdate(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnDisableFormsUpdate);
}

napi_value NapiFormHost::IsSystemReady(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnIsSystemReady);
}

napi_value NapiFormHost::GetAllFormsInfo(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnGetAllFormsInfo);
}

napi_value NapiFormHost::GetFormsInfo(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnGetFormsInfo);
}

napi_value NapiFormHost::DeleteForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnDeleteForm);
}

napi_value NapiFormHost::ReleaseForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnReleaseForm);
}

napi_value NapiFormHost::RequestForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnRequestForm);
}

napi_value NapiFormHost::CastTempForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnCastTempForm);
}

napi_value NapiFormHost::EnableFormsUpdate(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnEnableFormsUpdate);
}

napi_value NapiFormHost::DeleteInvalidForms(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnDeleteInvalidForms);
}

napi_value NapiFormHost::NotifyVisibleForms(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnNotifyVisibleForms);
}

napi_value NapiFormHost::NotifyInVisibleForms(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnNotifyInVisibleForms);
}

napi_value NapiFormHost::OnShareForm(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    if (argc > ARGS_SIZE_THREE || argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("wrong number of arguments.");
        errCode = ERR_ADD_INVALID_PARAM;
    }

    std::string strFormId =
        GetStringFromNAPI(env, argv[0]);
    std::string remoteDeviceId =
        GetStringFromNAPI(env, argv[1]);
    // The promise form has only two parameters
    decltype(argc) unwrapArgc = 2;

    int64_t formId = 0;
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert string formId to int64 failed.");
        errCode = ERR_COMMON;
    }
    if (formId == 0 || remoteDeviceId.empty()) {
        errCode = ERR_COMMON;
    }

    napi_value lastParam = (argc <= unwrapArgc) ? nullptr : argv[unwrapArgc];
    napi_value result = nullptr;

    std::unique_ptr<AbilityRuntime::NapiAsyncTask> uasyncTask =
        AbilityRuntime::CreateAsyncTaskWithLastParam(env, lastParam, nullptr, nullptr, &result);
    std::shared_ptr<AbilityRuntime::NapiAsyncTask> asyncTask = std::move(uasyncTask);

    ShareFormTask task = [env, asyncTask](int32_t code) {
        HILOG_DEBUG("task complete code: %{public}d", code);
        if (code == ERR_OK) {
            asyncTask->Resolve(env, CreateJsUndefined(env));
        } else {
            auto retCode = QueryRetCode(code);
            auto retMsg = QueryRetMsg(retCode);
            asyncTask->Reject(env, AbilityRuntime::CreateJsError(env, retCode, retMsg));
        }
    };

    if (errCode != ERR_OK) {
        asyncTask->Reject(env, AbilityRuntime::CreateJsError(env, errCode, "Invalidate params."));
    } else {
        InnerShareForm(env, asyncTask, std::move(task), formId, remoteDeviceId);
    }

    return result;
}

napi_value NapiFormHost::OnDisableFormsUpdate(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    if (argc > ARGS_TWO || argc < ARGS_ONE) {
        HILOG_ERROR("wrong number of arguments!");
        return CreateJsUndefined(env);
    }

    std::vector<string> strFormIdList;
    if (!GetStringsValue(env, argv[PARAM0], strFormIdList)) {
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

    auto complete = [formIds = iFormIds, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        auto ret = FormMgr::GetInstance().LifecycleUpdate(formIds, FormHostClient::GetInstance(), false);
        if (ret != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
            return;
        }
        task.Resolve(env, CreateJsValue(env, ret));
    };

    auto callback = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnDisableFormsUpdate",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));
    return result;
}

napi_value NapiFormHost::OnIsSystemReady(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (argc > ARGS_ONE || argc < ARGS_ZERO) {
        HILOG_ERROR("wrong number of arguments.");
        return CreateJsUndefined(env);
    }

    auto complete = [](napi_env env, NapiAsyncTask &task, int32_t status) {
        // Use original logic.
        // Use the error code to return whether the function executed successfully.
        auto ret = FormMgr::GetInstance().CheckFMSReady();
        if (ret == ERR_OK) {
            task.Resolve(env, CreateJsUndefined(env));
        } else {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
        }
    };

    auto callback = (argc == ARGS_ZERO) ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnIsSystemReady",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));
    return result;
}

napi_value NapiFormHost::OnGetAllFormsInfo(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    if (argc > ARGS_ONE || argc < ARGS_ZERO) {
        HILOG_ERROR("wrong number of arguments!");
        return CreateJsUndefined(env);
    }

    auto complete = [](napi_env env, NapiAsyncTask &task, int32_t status) {
        std::vector<FormInfo> formInfos;
        auto ret = FormMgr::GetInstance().GetAllFormsInfo(formInfos);
        if (ret != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
            return;
        }
        task.Resolve(env, CreateFormInfos(env, formInfos));
    };

    auto callback = (argc == ARGS_ZERO) ? nullptr : argv[PARAM0];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnGetAllFormsInfo",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));
    return result;
}

napi_value NapiFormHost::OnGetFormsInfo(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);
    int32_t errCode = ERR_OK;
    if (argc > ARGS_THREE || argc < ARGS_ONE) {
        HILOG_ERROR("wrong number of arguments!");
        return CreateJsUndefined(env);
    }

    std::string bName("");
    if (!ConvertFromJsValue(env, argv[PARAM0], bName)) {
        HILOG_ERROR("conversion failed!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME;
    }

    std::string mName("");
    bool bParam = false;
    bool flagCall = UnwrapGetFormsInfoParams(env, argc, argv, mName, bParam);
    auto complete = [bName, mName, bParam, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        std::string bundleName(bName);
        std::string moduleName(mName);
        std::vector<FormInfo> formInfos;
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        int ret = ERR_OK;
        if (!bParam) {
            ret = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
        } else {
            ret = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
        }

        if (ret != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
            return;
        }
        task.Resolve(env, CreateFormInfos(env, formInfos));
    };

    napi_value result = nullptr;
    auto callback = flagCall ? ((argc == ARGS_TWO) ? argv[PARAM1] : argv[PARAM2]) : nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnGetFormsInfo",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));
    return result;
}

napi_value NapiFormHost::OnDeleteForm(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    if (argc > ARGS_TWO || argc < ARGS_ONE) {
        HILOG_ERROR("OnDeleteForm wrong number of arguments.");
        return CreateJsUndefined(env);
    }
    if (!IsTypeForNapiValue(env, argv[PARAM0], napi_string)) {
        HILOG_ERROR("input arguments is not string!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    } else {
        std::string strFormId;
        if (!ConvertFromJsValue(env, argv[PARAM0], strFormId)) {
            HILOG_ERROR("conversion failed!");
            return CreateJsUndefined(env);
        }
        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("OnDeleteForm convert string formId to int64 failed.");
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        }
    }
    NapiAsyncTask::CompleteCallback complete = [formId, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        auto ret = FormMgr::GetInstance().DeleteForm(formId, FormHostClient::GetInstance());
        if (ret == ERR_OK) {
            auto result = QueryRetCode(ret);
            task.Resolve(env, CreateJsValue(env, result));
        } else {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
        }
    };

    napi_value lastParam = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnDeleteForm",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value NapiFormHost::OnReleaseForm(napi_env env,
    size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    bool isReleaseCache = false;
    if (argc > ARGS_THREE || argc < ARGS_ONE) {
        HILOG_ERROR("OnReleaseForm wrong number of arguments.");
        return CreateJsUndefined(env);
    }
    if (!IsTypeForNapiValue(env, argv[PARAM0], napi_string)) {
        HILOG_ERROR("input params is not string!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    } else {
        std::string strFormId;
        if (!ConvertFromJsValue(env, argv[PARAM0], strFormId)) {
            HILOG_ERROR("conversion error!");
            return CreateJsUndefined(env);
        }
        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("OnReleaseForm convert string formId to int64 failed.");
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        } else if ((argc == ARGS_TWO || argc == ARGS_THREE) &&
            !IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
            if (IsTypeForNapiValue(env, argv[PARAM1], napi_boolean)) {
                if (!ConvertFromJsValue(env, argv[PARAM1], isReleaseCache)) {
                    HILOG_ERROR("conversion bool failed!");
                    return CreateJsUndefined(env);
                }
            } else {
                HILOG_ERROR("promise second param type is illegal");
                errCode = ERR_APPEXECFWK_FORM_RELEASE_FLG_ERR;
            }
        }
    }

    NapiAsyncTask::CompleteCallback complete = [formId, errCode, isReleaseCache]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
            auto ret = ERR_COMMON;
            if (errCode != ERR_OK) {
                auto retCode = QueryRetCode(errCode);
                task.Reject(env, CreateJsError(env, retCode, QueryRetMsg(retCode)));
                return ;
            }
            ret = FormMgr::GetInstance().ReleaseForm(formId, FormHostClient::GetInstance(), isReleaseCache);
            if (ret == ERR_OK) {
                auto result = QueryRetCode(ret);
                task.Resolve(env, CreateJsValue(env, result));
            } else {
                auto retCode = QueryRetCode(ret);
                task.Reject(env, CreateJsError(env, retCode, QueryRetMsg(retCode)));
                return;
            }
    };

    napi_value lastParam = (argc == ARGS_ONE) ? nullptr :
        (argc == ARGS_TWO && !IsTypeForNapiValue(env, argv[PARAM1], napi_function)) ? nullptr :
        (argc == ARGS_THREE) ? argv[PARAM2] : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnReleaseForm",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value NapiFormHost::OnRequestForm(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    if (argc > ARGS_TWO || argc < ARGS_ONE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return CreateJsUndefined(env);
    }
    if (!IsTypeForNapiValue(env, argv[PARAM0], napi_string)) {
        HILOG_ERROR("input params is not string!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    } else {
        std::string strFormId;
        if (!ConvertFromJsValue(env, argv[PARAM0], strFormId)) {
            HILOG_ERROR("transform failed!");
            return CreateJsUndefined(env);
        }
        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("%{public}s, convert string formId to int64 failed.", __func__);
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        }
    }
    NapiAsyncTask::CompleteCallback complete = [formId, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        Want want;
        auto ret = FormMgr::GetInstance().RequestForm(formId, FormHostClient::GetInstance(), want);
        if (ret == ERR_OK) {
            auto result = QueryRetCode(ret);
            task.Resolve(env, CreateJsValue(env, result));
        } else {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
        }
    };

    napi_value lastParam = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnRequestForm",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value NapiFormHost::OnCastTempForm(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s called.", __func__);

    int32_t errCode = ERR_OK;
    int64_t formId = 0;
    if (argc > ARGS_TWO || argc < ARGS_ONE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return CreateJsUndefined(env);
    }
    if (!IsTypeForNapiValue(env, argv[PARAM0], napi_string)) {
        HILOG_ERROR("input arguments is not string!");
        errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
    } else {
        std::string strFormId;
        if (!ConvertFromJsValue(env, argv[PARAM0], strFormId)) {
            HILOG_ERROR("transform failed!");
            return CreateJsUndefined(env);
        }
        if (!ConvertStringToInt64(strFormId, formId)) {
            HILOG_ERROR("%{public}s, convert string formId to int64 failed.", __func__);
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        }
    }
    NapiAsyncTask::CompleteCallback complete = [formId, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        auto ret = FormMgr::GetInstance().CastTempForm(formId, FormHostClient::GetInstance());
        if (ret == ERR_OK) {
            auto result = QueryRetCode(ret);
            task.Resolve(env, CreateJsValue(env, result));
        } else {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
        }
    };

    napi_value lastParam = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnCastTempForm",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value NapiFormHost::OnEnableFormsUpdate(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("%{public}s is called", __FUNCTION__);

    int32_t errCode = ERR_OK;
    std::vector<int64_t> iFormIds;
    if (argc > ARGS_TWO|| argc < ARGS_ONE) {
        HILOG_ERROR("wrong number of arguments!");
        return CreateJsUndefined(env);
    }
    std::vector<string> strFormIdList;
    if (!GetStringsValue(env, argv[PARAM0], strFormIdList)) {
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
    auto complete = [iFormIds, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        auto ret = FormMgr::GetInstance().LifecycleUpdate(iFormIds, FormHostClient::GetInstance(), true);
        if (ret == ERR_OK) {
            auto result = QueryRetCode(ret);
            task.Resolve(env, CreateJsValue(env, result));
        } else {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
        }
    };

    auto callback = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnEnableFormsUpdate",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));
    return result;
}

bool NapiFormHost::GetStringsValue(napi_env env, napi_value array, std::vector<std::string> &strList)
{
    uint32_t nativeArrayLen = 0;
    napi_get_array_length(env, array, &nativeArrayLen);
    napi_value element = nullptr;

    for (uint32_t i = 0; i < nativeArrayLen; i++) {
        std::string itemStr("");
        napi_get_element(env, array, i, &element);
        if (!ConvertFromJsValue(env, element, itemStr)) {
            HILOG_ERROR("GetElement from to array [%{public}u] error", i);
            return false;
        }
        strList.push_back(itemStr);
    }

    return true;
}

bool NapiFormHost::UnwrapGetFormsInfoParams(
    napi_env env, size_t argc, napi_value* argv, std::string &moduleName, bool &bParam)
{
    bool flagCall = true;
    if (argc == ARGS_ONE) {
        flagCall = false;
        bParam = false;
    } else if (argc == ARGS_TWO && !IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
        if (!ConvertFromJsValue(env, argv[PARAM1], moduleName)) {
            HILOG_WARN("input params string error");
        }
        flagCall = false;
        bParam = true;
    } else if (argc == ARGS_TWO && IsTypeForNapiValue(env, argv[PARAM1], napi_function)) {
        bParam = false;
    } else if (argc == ARGS_THREE) {
        if (!ConvertFromJsValue(env, argv[PARAM1], moduleName)) {
            HILOG_WARN("input params string error");
        }
        bParam = true;
    }

    return flagCall;
}

void NapiFormHost::InnerShareForm(
    napi_env env,
    const std::shared_ptr<AbilityRuntime::NapiAsyncTask> &asyncTask,
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
        HILOG_INFO("share form fail");
        auto retCode = QueryRetCode(ret);
        auto retMsg = QueryRetMsg(retCode);
        asyncTask->Reject(env, AbilityRuntime::CreateJsError(env, retCode, retMsg));
        FormHostClient::GetInstance()->RemoveShareFormCallback(requestCode);
    }
}

napi_value NapiFormHost::NotifyFormsPrivacyProtected(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, NapiFormHost, OnNotifyFormsPrivacyProtected);
}

napi_value NapiFormHost::OnNotifyFormsPrivacyProtected(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_INFO("call");
    if (argc > ARGS_SIZE_THREE || argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }

    ErrCode errCode = ERR_OK;
    std::vector<int64_t> formIds {};
    GetFormIds(env, argv[0], errCode, formIds);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get formIds faild, code is %{public}d", errCode);
        return nullptr;
    }

    // The promise form has only two parameters
    decltype(argc) unwrapArgc = 2;
    bool isProtected = false;

    if (!ConvertFromJsValue(env, argv[1], isProtected)) {
        HILOG_ERROR("convert from Js value failed!");
        return nullptr;
    }

    NapiAsyncTask::CompleteCallback complete =
        [formIds, isProtected, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
            if (errCode != ERR_OK) {
                HILOG_ERROR("task reject, code is %{public}d", errCode);
                task.Reject(env, CreateJsError(env, errCode, QueryRetMsg(errCode)));
                return;
            }

            auto ret = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds,
                isProtected, FormHostClient::GetInstance());
            if (ret == ERR_OK) {
                task.Resolve(env, CreateJsUndefined(env));
            } else {
                HILOG_ERROR("task reject, result code is %{public}d", ret);
                NapiFormUtil::RejectCurrentTask(env, task, ret);
            }
        };

    napi_value lastParam = (argc <= unwrapArgc) ? nullptr : argv[unwrapArgc];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnNotifyFormsPrivacyProtected",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

bool NapiFormHost::OnDeleteInvalidFormsParseParam(napi_env env, size_t argc, napi_value* argv,
    int32_t &errCode, std::vector<std::string> &strFormIdList)
{
    if (argc > ARGS_TWO || argc < ARGS_ONE) {
        HILOG_ERROR("wrong number of arguments.");
        return false;
    }
    if (!GetStringsValue(env, argv[PARAM0], strFormIdList)) {
        HILOG_ERROR("conversion string failed!");
        errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
    }
    if (strFormIdList.empty()) {
        HILOG_ERROR("formId list is empty!");
        errCode = ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR;
    }
    return true;
}

napi_value NapiFormHost::OnDeleteInvalidForms(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("called");

    int32_t errCode = ERR_OK;
    std::vector<std::string> strFormIdList;
    if (!OnDeleteInvalidFormsParseParam(env, argc, argv, errCode, strFormIdList)) {
        HILOG_ERROR("parse param failed");
        return CreateJsNull(env);
    }

    std::shared_ptr<OnDeleteInvalidFormsS> onDeleteInvalidForms = std::make_shared<OnDeleteInvalidFormsS>();
    for (size_t i = 0; i < strFormIdList.size(); i++) {
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormIdList[i], formIdValue)) {
            HILOG_ERROR("conversion int failed!");
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        } else {
            onDeleteInvalidForms->iFormIds.push_back(formIdValue);
        }
    }
    auto execute = [data = onDeleteInvalidForms] {
        if (data == nullptr) {
            HILOG_ERROR("onDeleteInvalidForms is nullptr.");
            return;
        }
        data->result = FormMgr::GetInstance().DeleteInvalidForms(
            data->iFormIds, FormHostClient::GetInstance(), data->numFormsDeleted);
    };
    auto complete = [data = onDeleteInvalidForms, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        auto retCode = QueryRetCode(data->result);
        auto retMsg = QueryRetMsg(retCode);
        if (data->result == ERR_OK) {
            task.ResolveWithCustomize(env, CreateJsError(env, retCode, retMsg),
            CreateJsValue(env, data->numFormsDeleted));
        } else {
            task.Reject(env, CreateJsError(env, retCode, retMsg));
        }
    };

    auto callback = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnDeleteInvalidForms",
        env, CreateAsyncTaskWithLastParam(env, callback, std::move(execute), std::move(complete), &result));
    return result;
}

napi_value NapiFormHost::OnNotifyVisibleForms(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("called");

    int32_t errCode = ERR_OK;
    std::vector<int64_t> iFormIds;
    if (argc > ARGS_TWO || argc < ARGS_ONE) {
        HILOG_ERROR("wrong number of arguments!");
        return CreateJsUndefined(env);
    }
    bool isArray = false;
    napi_is_array(env, argv[PARAM0], &isArray);
    if (!isArray) {
        HILOG_ERROR("input params0 is not array!");
        errCode = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR;
    } else {
        std::vector<string> strFormIdList;
        if (!GetStringsValue(env, argv[PARAM0], strFormIdList)) {
            HILOG_ERROR("conversion string failed!");
            errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
        }
        for (size_t i = 0; i < strFormIdList.size(); i++) {
            int64_t formIdValue;
            if (!ConvertStringToInt64(strFormIdList[i], formIdValue)) {
                HILOG_ERROR("conversion int error!");
                errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
            } else {
                iFormIds.push_back(formIdValue);
            }
        }
    }
    auto complete = [iFormIds, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(iFormIds, FormHostClient::GetInstance(),
            Constants::FORM_VISIBLE);
        auto retCode = QueryRetCode(ret);
        if (ret == ERR_OK) {
            task.ResolveWithCustomize(env, CreateJsError(env, retCode, QueryRetMsg(retCode)), CreateJsUndefined(env));
        } else {
            task.Reject(env, CreateJsError(env, retCode, QueryRetMsg(retCode)));
        }
    };
    auto callback = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnNotifyVisibleForms",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));
    return result;
}

int32_t NapiFormHost::OnNotifyInVisibleFormsParseParam(napi_env env, size_t argc, napi_value* argv,
    std::vector<int64_t> &formIds)
{
    if (argc > ARGS_TWO || argc < ARGS_ONE) {
        HILOG_ERROR("wrong number of arguments. argc is %{public}zu", argc);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    bool isArray = false;
    int32_t errCode = ERR_OK;
    napi_is_array(env, argv[PARAM0], &isArray);
    if (!isArray) {
        HILOG_ERROR("input params is not array!");
        errCode = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR;
    } else {
        std::vector<string> strFormIdList;
        if (!GetStringsValue(env, argv[PARAM0], strFormIdList)) {
            HILOG_ERROR("conversion string failed!");
            errCode = ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
        } else {
            if (strFormIdList.size() == 0) {
                HILOG_ERROR("input params is null!");
                errCode = ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR;
            }
        }
        for (size_t i = 0; i < strFormIdList.size(); i++) {
            int64_t formIdValue;
            if (!ConvertStringToInt64(strFormIdList[i], formIdValue)) {
                HILOG_ERROR("transform  int failed!");
                errCode = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR;
            } else {
                formIds.push_back(formIdValue);
            }
        }
    }
    return errCode;
}

napi_value NapiFormHost::OnNotifyInVisibleForms(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_DEBUG("called");

    int32_t errCode;
    std::vector<int64_t> formIds;

    errCode = OnNotifyInVisibleFormsParseParam(env, argc, argv, formIds);
    if (errCode == ERR_APPEXECFWK_FORM_INVALID_PARAM) {
        return CreateJsUndefined(env);
    }

    auto complete = [formIds = formIds, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (errCode != ERR_OK) {
            NapiFormUtil::RejectCurrentTask(env, task, errCode);
            return;
        }
        auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds,
            FormHostClient::GetInstance(), Constants::FORM_INVISIBLE);
        if (ret == ERR_OK) {
            auto resultCode = QueryRetCode(ret);
            task.ResolveWithCustomize(
                env, CreateJsError(env, resultCode, QueryRetMsg(resultCode)), CreateJsUndefined(env));
        } else {
            NapiFormUtil::RejectCurrentTask(env, task, ret);
        }
    };

    auto callback = (argc == ARGS_ONE) ? nullptr : argv[PARAM1];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("NapiFormHost::OnNotifyInVisibleForms",
        env, CreateAsyncTaskWithLastParam(env, callback, nullptr, std::move(complete), &result));
    return result;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
