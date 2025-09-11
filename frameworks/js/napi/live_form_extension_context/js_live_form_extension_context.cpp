/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "js_live_form_extension_context.h"
#include "js_caller_complex.h"
#include "js_extension_context.h"
#include "js_error_utils.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "element_name.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_errors.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
namespace {
constexpr int32_t INDEX_ZERO = 0;
constexpr int32_t INDEX_ONE = 1;
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr int32_t CALLER_TIME_OUT = 10; // 10s
constexpr int32_t ERR_FAILED = -1;

std::map<UIExtensionConnectionKey, sptr<JSUIExtensionConnection>, key_compare> g_connects;
std::mutex g_connectsMutex_;
int64_t g_serialNumber = 0;

void GetConnectionInfo(AAFwk::Want &want, sptr<JSUIExtensionConnection> &connection, int64_t connectId)
{
    HILOG_DEBUG("connection:%{public}d", static_cast<int32_t>(connectId));
    std::lock_guard<std::mutex> lock(g_connectsMutex_);
    auto item = std::find_if(g_connects.begin(), g_connects.end(), [connectId](const auto &obj) {
        return connectId == obj.first.id;
    });
    if (item != g_connects.end()) {
        want = item->first.want;
        connection = item->second;
    }
    return;
}

void RemoveConnection(int64_t connectId)
{
    std::lock_guard<std::mutex> lock(g_connectsMutex_);
    auto item = std::find_if(g_connects.begin(), g_connects.end(), [connectId](const auto &obj) {
        return connectId == obj.first.id;
    });
    if (item != g_connects.end()) {
        HILOG_DEBUG("ability exist");
        if (item->second) {
            item->second->RemoveConnectionObject();
        }
        g_connects.erase(item);
    } else {
        HILOG_DEBUG("ability not exist");
    }
}

class StartAbilityByCallParameters {
public:
    int err = ERR_OK;
    sptr<IRemoteObject> remoteCallee = nullptr;
    std::shared_ptr<CallerCallBack> callerCallBack = nullptr;
    std::mutex mutexlock;
    std::condition_variable condition;
};

void GenerateCallerCallBack(std::shared_ptr<StartAbilityByCallParameters> calls,
    std::shared_ptr<CallerCallBack> callerCallBack)
{
    if (calls == nullptr) {
        HILOG_ERROR("null calls");
        return;
    }
    if (callerCallBack == nullptr) {
        HILOG_ERROR("null callerCallBack");
        return;
    }
    auto callBackDone = [calldata = calls] (const sptr<IRemoteObject> &obj) {
        HILOG_DEBUG("callBackDone called start");
        std::unique_lock<std::mutex> lock(calldata->mutexlock);
        calldata->remoteCallee = obj;
        calldata->condition.notify_all();
    };

    auto releaseListen = [](const std::string &str) {
        HILOG_DEBUG("releaseListen is called %{public}s", str.c_str());
    };

    callerCallBack->SetCallBack(callBackDone);
    callerCallBack->SetOnRelease(releaseListen);
}

void StartAbilityByCallExecuteDone(std::shared_ptr<StartAbilityByCallParameters> calldata)
{
    if (calldata == nullptr) {
        HILOG_ERROR("null calldata");
        return;
    }
    std::unique_lock<std::mutex> lock(calldata->mutexlock);
    if (calldata->remoteCallee != nullptr) {
        HILOG_ERROR("not null callExecute callee");
        return;
    }

    if (calldata->condition.wait_for(lock, std::chrono::seconds(CALLER_TIME_OUT)) == std::cv_status::timeout) {
        HILOG_DEBUG("callExecute waiting callee timeout");
        calldata->err = ERR_FAILED;
    }
    HILOG_DEBUG("end");
}

void StartAbilityByCallComplete(napi_env env, NapiAsyncTask &task,
    std::weak_ptr<LiveFormExtensionContext> liveFormExtensionContext,
    std::shared_ptr<StartAbilityByCallParameters> calldata, std::shared_ptr<CallerCallBack> callerCallBack)
{
    HILOG_DEBUG("call");
    if (calldata == nullptr) {
        HILOG_ERROR("null calldata");
        return;
    }
    if (calldata->err != ERR_OK) {
        HILOG_ERROR("calldata err: %{public}d", calldata->err);
        task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
        auto context = liveFormExtensionContext.lock();
        if (context == nullptr || callerCallBack == nullptr) {
            HILOG_ERROR("null context or callBack");
            return;
        }
        context->ClearFailedCallConnection(callerCallBack);
        return;
    }
    auto context = liveFormExtensionContext.lock();
    if (context == nullptr || callerCallBack == nullptr || calldata->remoteCallee == nullptr) {
        HILOG_ERROR("null callComplete params error %{public}s",
            context == nullptr ? "context" : (calldata->remoteCallee == nullptr ? "remoteCallee" : "callerCallBack"));
        task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
        HILOG_DEBUG("callComplete end");
        return;
    }
    auto releaseCallAbilityFunc = [liveFormExtensionContext] (
        const std::shared_ptr<CallerCallBack> &callback) -> ErrCode {
        auto contextForRelease = liveFormExtensionContext.lock();
        if (contextForRelease == nullptr) {
            HILOG_ERROR("null releaseCallAbilityFunction");
            return ERR_FAILED;
        }
        return contextForRelease->ReleaseCall(callback);
    };
    task.Resolve(env, CreateJsCallerComplex(env, releaseCallAbilityFunc, calldata->remoteCallee, callerCallBack));
    HILOG_DEBUG("end");
}
} // namespace

void JsLiveFormExtensionContext::Finalizer(napi_env env, void *data, void *hint)
{
    HILOG_DEBUG("called");
    std::unique_ptr<JsLiveFormExtensionContext>(static_cast<JsLiveFormExtensionContext *>(data));
}

napi_value JsLiveFormExtensionContext::CreateJsLiveFormExtensionContext(
    napi_env env, std::shared_ptr<LiveFormExtensionContext> context)
{
    HILOG_DEBUG("begin");
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }

    napi_value objValue = CreateJsExtensionContext(env, context, abilityInfo);
    std::unique_ptr<JsLiveFormExtensionContext> jsContext = std::make_unique<JsLiveFormExtensionContext>(context);
    napi_status status = napi_wrap(env, objValue, jsContext.release(), Finalizer, nullptr, nullptr);
    if (status != napi_ok) {
        HILOG_ERROR("Failed to do napi wrap");
    }

    const char *moduleName = "JsLiveFormExtensionContext";
    BindNativeFunction(env, objValue, "setWindowBackgroundColor", moduleName, SetWindowBackgroundColor);
    BindNativeFunction(env, objValue, "startAbilityByLiveForm", moduleName, StartAbilityByLiveForm);
    BindNativeFunction(env, objValue, "connectServiceExtensionAbility", moduleName, ConnectAbility);
    BindNativeFunction(env, objValue, "disconnectServiceExtensionAbility", moduleName, DisconnectAbility);
    BindNativeFunction(env, objValue, "startAbilityByCall", moduleName, StartAbilityByCall);

    return objValue;
}

napi_value JsLiveFormExtensionContext::SetWindowBackgroundColor(napi_env env, napi_callback_info info)
{
    HILOG_DEBUG("called");
    GET_NAPI_INFO_AND_CALL(env, info, JsLiveFormExtensionContext, OnSetWindowBackgroundColor);
}

napi_value JsLiveFormExtensionContext::StartAbilityByLiveForm(napi_env env, napi_callback_info info)
{
    HILOG_DEBUG("called");
    GET_NAPI_INFO_AND_CALL(env, info, JsLiveFormExtensionContext, OnStartAbilityByLiveForm);
}

napi_value JsLiveFormExtensionContext::ConnectAbility(napi_env env, napi_callback_info info)
{
    HILOG_DEBUG("called");
    GET_NAPI_INFO_AND_CALL(env, info, JsLiveFormExtensionContext, OnConnectAbility);
}

napi_value JsLiveFormExtensionContext::DisconnectAbility(napi_env env, napi_callback_info info)
{
    HILOG_DEBUG("called");
    GET_NAPI_INFO_AND_CALL(env, info, JsLiveFormExtensionContext, OnDisconnectAbility);
}

napi_value JsLiveFormExtensionContext::StartAbilityByCall(napi_env env, napi_callback_info info)
{
    HILOG_DEBUG("called");
    GET_NAPI_INFO_AND_CALL(env, info, JsLiveFormExtensionContext, OnStartAbilityByCall);
}

napi_value JsLiveFormExtensionContext::OnSetWindowBackgroundColor(napi_env env, NapiCallbackInfo &info)
{
    HILOG_DEBUG("called");
    NapiAsyncTask::CompleteCallback complete =
        [weak = context_](napi_env env, NapiAsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnSetWindowBackgroundColor begin");
        auto context = weak.lock();
        if (!context) {
            HILOG_ERROR("null context");
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
            return;
        }

        bool isSuccess = context->SetWindowBackgroundColor();
        if (!isSuccess) {
            HILOG_ERROR("SetWindowBackgroundColor failed");
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
            return;
        }

        task.ResolveWithNoError(env, CreateJsUndefined(env));
    };

    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("JsLiveFormExtensionContext OnSetWindowBackgroundColor", env,
        CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsLiveFormExtensionContext::OnStartAbilityByLiveForm(napi_env env, NapiCallbackInfo &info)
{
    HILOG_DEBUG("called: param size: %{public}d", static_cast<int32_t>(info.argc));
    if (info.argc != ARGC_TWO) {
        HILOG_ERROR("argc is not two");
        ThrowError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR));
        return CreateJsUndefined(env);
    }
 
    auto context = context_.lock();
    if (context == nullptr) {
        HILOG_ERROR("Context is nullptr");
        ThrowError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR));
        return CreateJsUndefined(env);
    }
 
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, info.argv[0], want);
    std::string formId;
    if (!AppExecFwk::UnwrapStringFromJS2(env, info.argv[1], formId)) {
        HILOG_ERROR("parse param failed");
        return CreateJsUndefined(env);
    }
    NapiAsyncTask::CompleteCallback complete =
        [weak = context_, want, formId](napi_env env, NapiAsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnStartAbilityByLiveForm begin");
        auto context = weak.lock();
        if (!context) {
            HILOG_ERROR("Context is nullptr");
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
            return;
        }

        ErrCode errCode = context->StartAbilityByFms(want, formId);
        if (errCode == ERR_OK) {
            task.ResolveWithNoError(env, CreateJsUndefined(env));
            return;
        }

        if (errCode == ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED || errCode == ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME) {
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED)));
        } else {
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
        }
    };
 
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("JsLiveFormExtensionContext OnStartAbilityByLiveForm", env,
        CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
 
    return result;
}

napi_value JsLiveFormExtensionContext::OnConnectAbility(napi_env env, NapiCallbackInfo &info)
{
    HILOG_DEBUG("called");
    if (!CheckCallerIsSystemApp()) {
        HILOG_ERROR("not system app");
        ThrowError(env, AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return CreateJsUndefined(env);
    }
    // Check params count
    if (info.argc != ARGC_TWO) {
        HILOG_ERROR("invalid argc");
        ThrowError(env, ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED);
        return CreateJsUndefined(env);
    }
    // Unwrap want and connection
    AAFwk::Want want;
    sptr<JSUIExtensionConnection> connection(new JSUIExtensionConnection(env));
    if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want) ||
        !CheckConnectionParam(env, info.argv[INDEX_ONE], connection, want)) {
        ThrowError(env, ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED);
        return CreateJsUndefined(env);
    }
    int64_t connectId = connection->GetConnectionId();
    NapiAsyncTask::CompleteCallback complete =
        [weak = context_, want, connection, connectId](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto context = weak.lock();
            if (!context) {
                HILOG_ERROR("null context");
                connection->CallJsFailed(ERR_FAILED);
                task.Resolve(env, CreateJsUndefined(env));
                RemoveConnection(connectId);
                return;
            }
            HILOG_DEBUG("ConnectAbility connection:%{public}d", static_cast<int32_t>(connectId));
            auto innerErrorCode = context->ConnectAbility(want, connection);
            if (innerErrorCode != ERR_OK) {
                connection->CallJsFailed(ERR_FAILED);
                RemoveConnection(connectId);
            }
            task.Resolve(env, CreateJsUndefined(env));
        };
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("JSUIExtensionContext::OnConnectAbility",
        env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return CreateJsValue(env, connectId);
}

napi_value JsLiveFormExtensionContext::OnDisconnectAbility(napi_env env, NapiCallbackInfo &info)
{
    HILOG_DEBUG("called");
    if (!CheckCallerIsSystemApp()) {
        HILOG_ERROR("not system app");
        ThrowError(env, AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return CreateJsUndefined(env);
    }
    if (info.argc != ARGC_ONE) {
        HILOG_ERROR("invalid argc");
        ThrowError(env, ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED);
        return CreateJsUndefined(env);
    }
    int64_t connectId = -1;
    if (!AppExecFwk::UnwrapInt64FromJS2(env, info.argv[INDEX_ZERO], connectId)) {
        ThrowError(env, ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED);
        return CreateJsUndefined(env);
    }
    AAFwk::Want want;
    sptr<JSUIExtensionConnection> connection = nullptr;
    GetConnectionInfo(want, connection, connectId);
    // begin disconnect
    NapiAsyncTask::CompleteCallback complete =
        [weak = context_, want, connection](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto context = weak.lock();
            if (!context) {
                HILOG_ERROR("null context");
                task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                    FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
                return;
            }
            if (connection == nullptr) {
                HILOG_ERROR("null connection");
                task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                    FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
                return;
            }
            auto innerErrorCode = context->DisconnectAbility(want, connection);
            if (innerErrorCode != ERR_OK) {
                task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                    FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
            } else {
                task.Resolve(env, CreateJsUndefined(env));
            }
        };
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("JSLiveFormExtensionContext::OnDisconnectAbility",
        env, CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsLiveFormExtensionContext::OnStartAbilityByCall(napi_env env, NapiCallbackInfo &info)
{
    HILOG_INFO("called");
    if (!CheckCallerIsSystemApp()) {
        HILOG_ERROR("not system app");
        ThrowError(env, AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return CreateJsUndefined(env);
    }
    // 1. Check params
    if (info.argc != ARGC_ONE) {
        HILOG_ERROR("invalid argc");
        ThrowError(env, ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED);
        return CreateJsUndefined(env);
    }
    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want)) {
        ThrowError(env, ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED);
        return CreateJsUndefined(env);
    }

    // 2. create CallBack function
    std::shared_ptr<StartAbilityByCallParameters> calls = std::make_shared<StartAbilityByCallParameters>();
    auto callExecute = [calldata = calls] () { StartAbilityByCallExecuteDone(calldata); };
    auto callerCallBack = std::make_shared<CallerCallBack>();
    GenerateCallerCallBack(calls, callerCallBack);
    auto callComplete = [weak = context_, calldata = calls, callerCallBack] (
        napi_env env, NapiAsyncTask &task, int32_t status) {
        StartAbilityByCallComplete(env, task, weak, calldata, callerCallBack);
    };

    // 3. StartAbilityByCall
    napi_value retsult = nullptr;
    auto context = context_.lock();
    if (context == nullptr) {
        HILOG_ERROR("null context");
        ThrowError(env, ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR);
        return CreateJsUndefined(env);
    }

    auto ret = context->StartAbilityByCall(want, callerCallBack);
    if (ret != ERR_OK) {
        HILOG_ERROR("startAbility failed %{public}d", static_cast<int32_t>(ret));
        ThrowError(env, ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR);
        return CreateJsUndefined(env);
    }

    if (calls->remoteCallee == nullptr) {
        HILOG_ERROR("null remoteCallee");
        NapiAsyncTask::ScheduleHighQos("JsLiveFormExtensionContext::OnStartAbilityByCall", env,
            CreateAsyncTaskWithLastParam(env, nullptr, std::move(callExecute), std::move(callComplete), &retsult));
    } else {
        HILOG_DEBUG("promise return result execute");
        NapiAsyncTask::ScheduleHighQos("JsLiveFormExtensionContext::OnStartAbilityByCall", env,
            CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(callComplete), &retsult));
    }

    HILOG_DEBUG("end");
    return retsult;
}

bool JsLiveFormExtensionContext::CheckConnectionParam(napi_env env, napi_value value,
    sptr<JSUIExtensionConnection> &connection, AAFwk::Want &want)
{
    if (!CheckTypeForNapiValue(env, value, napi_object)) {
        HILOG_ERROR("get connection object failed");
        return false;
    }
    connection->SetJsConnectionObject(value);
    UIExtensionConnectionKey key;
    key.id = g_serialNumber;
    key.want = want;
    connection->SetConnectionId(key.id);
    std::lock_guard<std::mutex> lock(g_connectsMutex_);
    g_connects.emplace(key, connection);
    if (g_serialNumber < INT32_MAX) {
        g_serialNumber++;
    } else {
        g_serialNumber = 0;
    }
    HILOG_DEBUG("not find connection");
    return true;
}

bool JsLiveFormExtensionContext::CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
}
} // namespace AbilityRuntime
} // namespace OHOS