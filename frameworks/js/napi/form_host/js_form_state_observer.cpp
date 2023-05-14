/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "js_form_state_observer.h"

#include "hilog_wrapper.h"
#include "napi_common_util.h"
#include "napi_form_util.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "running_form_info.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
    constexpr int REF_COUNT = 1;
    constexpr uint KEY_LIMIT = 16;
}

sptr<JsFormStateObserver> JsFormStateObserver::instance_ = nullptr;
std::mutex JsFormStateObserver::mutex_;

FormAddCallbackClient::FormAddCallbackClient(napi_env env, napi_ref callbackRef)
{
    env_ = env;
    callbackRef_ = callbackRef;
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
}

FormAddCallbackClient::~FormAddCallbackClient()
{
    napi_delete_reference(env_, callbackRef_);
}

void FormAddCallbackClient::ProcessFormAdd(const std::string bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    if (handler_ == nullptr) {
        HILOG_INFO("handler is nullptr");
        return;
    }
    handler_->PostSyncTask([thisWeakPtr = weak_from_this(), bundleName, runningFormInfo]() {
        auto sharedThis = thisWeakPtr.lock();
        if (sharedThis == nullptr) {
            HILOG_ERROR("sharedThis is nullptr.");
            return;
        }
        napi_value callbackValues = nullptr;
        napi_create_object(sharedThis->env_, &callbackValues);
        ParseRunningFormInfoIntoNapi(sharedThis->env_, runningFormInfo, callbackValues);
        napi_value callResult;
        napi_value myCallback = nullptr;
        napi_get_reference_value(sharedThis->env_, sharedThis->callbackRef_, &myCallback);
        if (myCallback != nullptr) {
            napi_call_function(sharedThis->env_, nullptr, myCallback, ARGS_ONE, &callbackValues, &callResult);
        }
    });
}

bool FormAddCallbackClient::IsStrictEqual(napi_value callback)
{
    bool isEqual = false;
    napi_value myCallback = nullptr;
    napi_get_reference_value(env_, callbackRef_, &myCallback);
    napi_strict_equals(env_, myCallback, callback, &isEqual);
    HILOG_INFO("isStrictEqual: %{public}d", isEqual);
    return isEqual;
}

FormRemoveCallbackClient::FormRemoveCallbackClient(napi_env env, napi_ref callbackRef)
{
    env_ = env;
    callbackRef_ = callbackRef;
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
}

FormRemoveCallbackClient::~FormRemoveCallbackClient()
{
    napi_delete_reference(env_, callbackRef_);
}

void FormRemoveCallbackClient::ProcessFormRemove(const std::string bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    if (handler_ == nullptr) {
        HILOG_INFO("handler is nullptr");
        return;
    }
    handler_->PostSyncTask([thisWeakPtr = weak_from_this(), bundleName, runningFormInfo]() {
        auto sharedThis = thisWeakPtr.lock();
        if (sharedThis == nullptr) {
            HILOG_ERROR("sharedThis is nullptr.");
            return;
        }
        napi_value callbackValues = nullptr;
        napi_create_object(sharedThis->env_, &callbackValues);
        ParseRunningFormInfoIntoNapi(sharedThis->env_, runningFormInfo, callbackValues);
        napi_value callResult;
        napi_value myCallback = nullptr;
        napi_get_reference_value(sharedThis->env_, sharedThis->callbackRef_, &myCallback);
        if (myCallback != nullptr) {
            napi_call_function(sharedThis->env_, nullptr, myCallback, ARGS_ONE, &callbackValues, &callResult);
        }
    });
}

bool FormRemoveCallbackClient::IsStrictEqual(napi_value callback)
{
    bool isEqual = false;
    napi_value myCallback = nullptr;
    napi_get_reference_value(env_, callbackRef_, &myCallback);
    napi_strict_equals(env_, myCallback, callback, &isEqual);
    HILOG_INFO("isStrictEqual: %{public}d", isEqual);
    return isEqual;
}

sptr<JsFormStateObserver> JsFormStateObserver::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) JsFormStateObserver();
            if (instance_ == nullptr) {
                HILOG_ERROR("error, failed to create JsFormStateObserver.");
            }
        }
    }
    return instance_;
}

bool JsFormStateObserver::CheckMapSize(const std::string type, const std::string bundleName)
{
    HILOG_DEBUG("start");
    if (type == "formAdd") {
        std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
        if (formAddCallbackMap_.find(bundleName) == formAddCallbackMap_.end()) {
            if (formAddCallbackMap_.size() >= KEY_LIMIT) {
                HILOG_ERROR("the number of the bundleName exceeds the limit.");
                return false;
            }
        }
    } else if (type == "formRemove") {
        std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
        if (formRemoveCallbackMap_.find(bundleName) == formRemoveCallbackMap_.end()) {
            if (formRemoveCallbackMap_.size() >= KEY_LIMIT) {
                HILOG_ERROR("the number of the bundleName exceeds the limit.");
                return false;
            }
        }
    } else {
        return false;
    }
    return true;
}

bool JsFormStateObserver::RegisterFormAddCallback(const napi_env env,
    const std::string bundleName, const napi_value callback)
{
    HILOG_DEBUG("start.");
    napi_ref callbackRef;
    napi_create_reference(env, callback, REF_COUNT, &callbackRef);
    std::shared_ptr<FormAddCallbackClient> callbackClient = std::make_shared<FormAddCallbackClient>(env,
        callbackRef);

    std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
    auto formAddCallbacks = formAddCallbackMap_.find(bundleName);
    if (formAddCallbacks == formAddCallbackMap_.end()) {
        std::vector<std::shared_ptr<FormAddCallbackClient>> callbacks;
        callbacks.emplace_back(callbackClient);
        formAddCallbackMap_.emplace(bundleName, callbacks);
        return true;
    } else {
        auto &callbacks = formAddCallbacks->second;
        for (auto &iter : callbacks) {
            if (iter->IsStrictEqual(callback)) {
                HILOG_ERROR("found equal callback.");
                return false;
            }
        }
        formAddCallbacks->second.emplace_back(callbackClient);
        return true;
    }
}

bool JsFormStateObserver::RegisterFormRemoveCallback(const napi_env env,
    const std::string bundleName, const napi_value callback)
{
    HILOG_DEBUG("start.");
    napi_ref callbackRef;
    napi_create_reference(env, callback, REF_COUNT, &callbackRef);
    std::shared_ptr<FormRemoveCallbackClient> callbackClient =
        std::make_shared<FormRemoveCallbackClient>(env, callbackRef);

    std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
    auto formRemoveCallbacks = formRemoveCallbackMap_.find(bundleName);
    if (formRemoveCallbacks == formRemoveCallbackMap_.end()) {
        std::vector<std::shared_ptr<FormRemoveCallbackClient>> callbacks;
        callbacks.emplace_back(callbackClient);
        formRemoveCallbackMap_.emplace(bundleName, callbacks);
        return true;
    } else {
        auto &callbacks = formRemoveCallbacks->second;
        for (auto &iter : callbacks) {
            if (iter->IsStrictEqual(callback)) {
                HILOG_ERROR("found equal callback.");
                return false;
            }
        }
        formRemoveCallbacks->second.emplace_back(callbackClient);
        return true;
    }
}

void JsFormStateObserver::ClearFormAddCallbackByBundle(const std::string bundleName)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
    auto formAddCallbacks = formAddCallbackMap_.find(bundleName);
    if (formAddCallbacks == formAddCallbackMap_.end()) {
        HILOG_INFO("There is no formAddCallback has been register");
    } else {
        auto &callbacks = formAddCallbacks->second;
        callbacks.clear();
        formAddCallbackMap_.erase(formAddCallbacks);
    }
}

void JsFormStateObserver::DelFormAddCallbackByBundle(const napi_value callback, const std::string bundleName)
{
    HILOG_DEBUG("start");

    std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
    auto formAddCallbacks = formAddCallbackMap_.find(bundleName);
    if (formAddCallbacks == formAddCallbackMap_.end()) {
        HILOG_INFO("There is no formAddCallback has been registered with this bundleName.");
    } else {
        auto &callbacks = formAddCallbacks->second;
        auto iter = std::find_if(callbacks.begin(), callbacks.end(), [&](const auto &cb) {
            return cb->IsStrictEqual(callback);
        });
        if (iter != callbacks.end()) {
            HILOG_INFO("Found equal callback");
            callbacks.erase(iter);
        } else {
            HILOG_INFO("There is no formAddCallback has been registered with the same callback.");
        }
    }
}

int32_t JsFormStateObserver::OnAddForm(const std::string bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("called.");

    std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
    auto callbackClient = formAddCallbackMap_.find(bundleName);
    if (callbackClient != formAddCallbackMap_.end()) {
        for (auto iter : callbackClient->second) {
            iter->ProcessFormAdd(bundleName, runningFormInfo);
        }
    }
    return ERR_OK;
}

void JsFormStateObserver::ClearFormRemoveCallbackByBundle(const std::string bundleName)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
    auto formRemoveCallbacks = formRemoveCallbackMap_.find(bundleName);
    if (formRemoveCallbacks == formRemoveCallbackMap_.end()) {
        HILOG_INFO("There is no formRemoveCallback has been register");
    } else {
        auto &callbacks = formRemoveCallbacks->second;
        callbacks.clear();
        formRemoveCallbackMap_.erase(formRemoveCallbacks);
    }
}

void JsFormStateObserver::DelFormRemoveCallbackByBundle(const napi_value callback, const std::string bundleName)
{
    HILOG_DEBUG("start");

    std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
    auto formRemoveCallbacks = formRemoveCallbackMap_.find(bundleName);
    if (formRemoveCallbacks == formRemoveCallbackMap_.end()) {
        HILOG_INFO("There is no formRemoveCallback has been registered with this bundleName.");
    } else {
        auto &callbacks = formRemoveCallbacks->second;
        auto iter = std::find_if(callbacks.begin(), callbacks.end(), [&](const auto &cb) {
            return cb->IsStrictEqual(callback);
        });
        if (iter != callbacks.end()) {
            HILOG_INFO("Found equal callback");
            callbacks.erase(iter);
        } else {
            HILOG_INFO("There is no formRemoveCallback has been registered with the same callback.");
        }
    }
}

int32_t JsFormStateObserver::OnRemoveForm(const std::string bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("called.");

    std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
    auto callbackClient = formRemoveCallbackMap_.find(bundleName);
    if (callbackClient != formRemoveCallbackMap_.end()) {
        for (auto iter : callbackClient->second) {
            iter->ProcessFormRemove(bundleName, runningFormInfo);
        }
    }
    return ERR_OK;
}
}  // namespace AbilityRuntime
}  // namespace OHOS