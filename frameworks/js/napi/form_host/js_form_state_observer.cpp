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

#include <regex>

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "js_runtime_utils.h"
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

void FormAddCallbackClient::ProcessFormAdd(const std::string &bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    if (handler_ == nullptr) {
        HILOG_INFO("null handler");
        return;
    }
    handler_->PostSyncTask([thisWeakPtr = weak_from_this(), bundleName, runningFormInfo]() {
        auto sharedThis = thisWeakPtr.lock();
        if (sharedThis == nullptr) {
            HILOG_ERROR("null sharedThis");
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
    HILOG_INFO("isStrictEqual:%{public}d", isEqual);
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

void FormRemoveCallbackClient::ProcessFormRemove(const std::string &bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    if (handler_ == nullptr) {
        HILOG_INFO("null handler");
        return;
    }
    handler_->PostSyncTask([thisWeakPtr = weak_from_this(), bundleName, runningFormInfo]() {
        auto sharedThis = thisWeakPtr.lock();
        if (sharedThis == nullptr) {
            HILOG_ERROR("null sharedThis");
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
    HILOG_INFO("isStrictEqual:%{public}d", isEqual);
    return isEqual;
}

sptr<JsFormStateObserver> JsFormStateObserver::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) JsFormStateObserver();
            if (instance_ == nullptr) {
                HILOG_ERROR("create JsFormStateObserver failed");
            }
        }
    }
    return instance_;
}

bool JsFormStateObserver::CheckMapSize(const std::string &type, const std::string &bundleName)
{
    HILOG_DEBUG("start");
    if (type == "formAdd") {
        std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
        if (formAddCallbackMap_.find(bundleName) == formAddCallbackMap_.end()) {
            if (formAddCallbackMap_.size() >= KEY_LIMIT) {
                HILOG_ERROR("the number of the bundleName exceeds the limit");
                return false;
            }
        }
    } else if (type == "formRemove") {
        std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
        if (formRemoveCallbackMap_.find(bundleName) == formRemoveCallbackMap_.end()) {
            if (formRemoveCallbackMap_.size() >= KEY_LIMIT) {
                HILOG_ERROR("the number of the bundleName exceeds the limit");
                return false;
            }
        }
    } else {
        return false;
    }
    return true;
}

bool JsFormStateObserver::RegisterFormAddCallback(const napi_env env,
    const std::string &bundleName, const napi_value callback)
{
    HILOG_DEBUG("start");
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
                HILOG_ERROR("found equal callback");
                return false;
            }
        }
        formAddCallbacks->second.emplace_back(callbackClient);
        return true;
    }
}

bool JsFormStateObserver::RegisterFormRemoveCallback(const napi_env env,
    const std::string &bundleName, const napi_value callback)
{
    HILOG_DEBUG("start");
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
                HILOG_ERROR("found equal callback");
                return false;
            }
        }
        formRemoveCallbacks->second.emplace_back(callbackClient);
        return true;
    }
}

void JsFormStateObserver::ClearFormAddCallbackByBundle(const std::string &bundleName)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
    auto formAddCallbacks = formAddCallbackMap_.find(bundleName);
    if (formAddCallbacks == formAddCallbackMap_.end()) {
        HILOG_INFO("No formAddCallback register");
    } else {
        auto &callbacks = formAddCallbacks->second;
        callbacks.clear();
        formAddCallbackMap_.erase(formAddCallbacks);
    }
}

void JsFormStateObserver::DelFormAddCallbackByBundle(const napi_value callback, const std::string &bundleName)
{
    HILOG_DEBUG("start");

    std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
    auto formAddCallbacks = formAddCallbackMap_.find(bundleName);
    if (formAddCallbacks == formAddCallbackMap_.end()) {
        HILOG_INFO("no formAddCallback registered with this bundleName");
    } else {
        auto &callbacks = formAddCallbacks->second;
        auto iter = std::find_if(callbacks.begin(), callbacks.end(), [&](const auto &cb) {
            return cb->IsStrictEqual(callback);
        });
        if (iter != callbacks.end()) {
            HILOG_INFO("equal callback");
            callbacks.erase(iter);
        } else {
            HILOG_INFO("no formAddCallback");
        }
    }
}

int32_t JsFormStateObserver::OnAddForm(const std::string &bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("call");

    std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
    auto callbackClient = formAddCallbackMap_.find(bundleName);
    if (callbackClient != formAddCallbackMap_.end()) {
        for (auto iter : callbackClient->second) {
            iter->ProcessFormAdd(bundleName, runningFormInfo);
        }
    }
    return ERR_OK;
}

void JsFormStateObserver::ClearFormRemoveCallbackByBundle(const std::string &bundleName)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
    auto formRemoveCallbacks = formRemoveCallbackMap_.find(bundleName);
    if (formRemoveCallbacks == formRemoveCallbackMap_.end()) {
        HILOG_INFO("no formRemoveCallback register");
    } else {
        auto &callbacks = formRemoveCallbacks->second;
        callbacks.clear();
        formRemoveCallbackMap_.erase(formRemoveCallbacks);
    }
}

void JsFormStateObserver::DelFormRemoveCallbackByBundle(const napi_value callback, const std::string &bundleName)
{
    HILOG_DEBUG("start");

    std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
    auto formRemoveCallbacks = formRemoveCallbackMap_.find(bundleName);
    if (formRemoveCallbacks == formRemoveCallbackMap_.end()) {
        HILOG_INFO("no formRemoveCallback registered with this bundleName");
    } else {
        auto &callbacks = formRemoveCallbacks->second;
        auto iter = std::find_if(callbacks.begin(), callbacks.end(), [&](const auto &cb) {
            return cb->IsStrictEqual(callback);
        });
        if (iter != callbacks.end()) {
            HILOG_INFO("equal callback");
            callbacks.erase(iter);
        } else {
            HILOG_INFO("no formRemoveCallback");
        }
    }
}

int32_t JsFormStateObserver::OnRemoveForm(const std::string &bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("call");

    std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
    auto callbackClient = formRemoveCallbackMap_.find(bundleName);
    if (callbackClient != formRemoveCallbackMap_.end()) {
        for (auto iter : callbackClient->second) {
            iter->ProcessFormRemove(bundleName, runningFormInfo);
        }
    }
    return ERR_OK;
}

int JsFormStateObserver::RegisterFormInstanceCallback(napi_env env, napi_value jsObserverObject,
    bool isVisibility, std::string &bundleName, sptr<JsFormStateObserver> &formObserver)
{
    HILOG_DEBUG("call");
    if (env_ == nullptr) {
        env_ = env;
    }
    std::string specialFlag = "#";
    std::lock_guard<std::mutex> lock(formIsvisibleCallbackMutex_);
    napi_ref ref = nullptr;
    if (isVisibility) {
        auto visibleCallback = formVisibleCallbackMap_.find(bundleName);
        if (visibleCallback != formVisibleCallbackMap_.end()) {
            HILOG_ERROR("bundleName is already in the map,bundleName id %{public}s", bundleName.c_str());
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        napi_create_reference(env, jsObserverObject, 1, &ref);
        formVisibleCallbackMap_.emplace(
            bundleName, std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference *>(ref)));
    } else {
        auto invisibleCallback = formInvisibleCallbackMap_.find(bundleName);
        if (invisibleCallback != formInvisibleCallbackMap_.end()) {
            HILOG_ERROR("bundleName is already in the map,bundleName id %{public}s", bundleName.c_str());
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        napi_create_reference(env, jsObserverObject, 1, &ref);
        formInvisibleCallbackMap_.emplace(
            bundleName, std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference *>(ref)));
    }
    AppExecFwk::FormMgr::GetInstance().RegisterAddObserver(bundleName + specialFlag + std::to_string(isVisibility),
        formObserver);
    return ERR_OK;
}

ErrCode JsFormStateObserver::ClearFormNotifyVisibleCallbackByBundle(const std::string bundleName,
    bool isVisibility, sptr<JsFormStateObserver> &formObserver)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formIsvisibleCallbackMutex_);
    std::string specialFlag = "#";
    if (isVisibility) {
        auto visibleCallback = formVisibleCallbackMap_.find(bundleName);
        if (visibleCallback != formVisibleCallbackMap_.end()) {
            AppExecFwk::FormMgr::GetInstance().RegisterRemoveObserver(
                bundleName + specialFlag + std::to_string(isVisibility), formObserver);
            formVisibleCallbackMap_.erase(visibleCallback);
            return ERR_OK;
        } else {
            HILOG_ERROR("There is no formVisibleCallbackMap_ has been register");
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
    } else {
        auto invisibleCallback = formInvisibleCallbackMap_.find(bundleName);
        if (invisibleCallback != formInvisibleCallbackMap_.end()) {
            AppExecFwk::FormMgr::GetInstance().RegisterRemoveObserver(
                bundleName + specialFlag + std::to_string(isVisibility), formObserver);
            formInvisibleCallbackMap_.erase(invisibleCallback);
            return ERR_OK;
        } else {
            HILOG_ERROR("There is no formInvisibleCallbackMap_ has been register");
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
    }
}

ErrCode JsFormStateObserver::DelFormNotifyVisibleCallbackByBundle(const std::string bundleName,
    bool isVisibility, napi_value jsObserverObject, sptr<JsFormStateObserver> &formObserver)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formIsvisibleCallbackMutex_);
    std::string specialFlag = "#";
    if (isVisibility) {
        auto visibleCallback = formVisibleCallbackMap_.find(bundleName);
        if (visibleCallback != formVisibleCallbackMap_.end()) {
            napi_value value = visibleCallback->second->GetNapiValue();
            bool isEqual = false;
            napi_strict_equals(env_, value, jsObserverObject, &isEqual);
            if (isEqual) {
                AppExecFwk::FormMgr::GetInstance().RegisterRemoveObserver(
                    bundleName + specialFlag + std::to_string(isVisibility), formObserver);
                formVisibleCallbackMap_.erase(visibleCallback);
                return ERR_OK;
            } else {
                HILOG_ERROR("There is no formVisibleCallbackMap_ has been register");
                return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
            }
        } else {
            HILOG_ERROR("There is no formVisibleCallbackMap_ has been register");
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
    } else {
        auto invisibleCallback = formInvisibleCallbackMap_.find(bundleName);
        if (invisibleCallback != formInvisibleCallbackMap_.end()) {
            napi_value value = invisibleCallback->second->GetNapiValue();
            bool isEqual = false;
            napi_strict_equals(env_, value, jsObserverObject, &isEqual);
            if (isEqual) {
                AppExecFwk::FormMgr::GetInstance().RegisterRemoveObserver(
                    bundleName + specialFlag + std::to_string(isVisibility), formObserver);
                formInvisibleCallbackMap_.erase(invisibleCallback);
                return ERR_OK;
            } else {
                HILOG_ERROR("There is no formInvisibleCallbackMap_ has been register");
                return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
            }
        } else {
            HILOG_ERROR("There is no formInvisibleCallbackMap_ has been register");
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
    }
}

std::shared_ptr<AppExecFwk::EventHandler> JsFormStateObserver::GetMainEventRunner()
{
    std::lock_guard<std::mutex> handlerLock(handlerMutex_);
    if (handler_ == nullptr) {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }
    return handler_;
}

int32_t JsFormStateObserver::NotifyWhetherFormsVisible(const AppExecFwk::FormVisibilityType visibleType,
    const std::string &bundleName, std::vector<AppExecFwk::FormInstance> &formInstances)
{
    HILOG_DEBUG("call");
    std::shared_ptr<AppExecFwk::EventHandler> handler = GetMainEventRunner();
    std::lock_guard<std::mutex> lock(formIsvisibleCallbackMutex_);
    if (handler) {
        wptr<JsFormStateObserver> weakObserver = this;
        handler->PostSyncTask([weakObserver, visibleType, formInstances, bundleName]() {
            std::string specialFlag = "#";
            bool isVisibleTypeFlag = false;
            auto sharedThis = weakObserver.promote();
            if (sharedThis == nullptr) {
                HILOG_ERROR("null sharedThis");
                return;
            }
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(sharedThis->env_, &scope);
            if (scope == nullptr) {
                HILOG_ERROR("null scope");
                return;
            }
            if (visibleType == AppExecFwk::FormVisibilityType::VISIBLE) {
                isVisibleTypeFlag = true;
                if (bundleName.find((specialFlag + std::to_string(isVisibleTypeFlag))) != std::string::npos) {
                    std::string bundleNameNew =
                        std::regex_replace(bundleName, std::regex(specialFlag + std::to_string(isVisibleTypeFlag)), "");
                    auto visibleCallback = sharedThis->formVisibleCallbackMap_.find(bundleNameNew);
                    if (visibleCallback != sharedThis->formVisibleCallbackMap_.end()) {
                        napi_value res = visibleCallback->second->GetNapiValue();
                        napi_value argv[] = { CreateFormInstances(sharedThis->env_, formInstances) };
                        napi_call_function(sharedThis->env_, res, res, sizeof(argv) / sizeof(argv[0]), argv, nullptr);
                    }
                }
            } else {
                isVisibleTypeFlag = false;
                if (bundleName.find((specialFlag + std::to_string(isVisibleTypeFlag))) != std::string::npos) {
                    std::string bundleNameNew =
                        std::regex_replace(bundleName, std::regex(specialFlag + std::to_string(isVisibleTypeFlag)), "");
                    auto invisibleCallback = sharedThis->formInvisibleCallbackMap_.find(bundleNameNew);
                    if (invisibleCallback != sharedThis->formInvisibleCallbackMap_.end()) {
                        napi_value res = invisibleCallback->second->GetNapiValue();
                        napi_value argv[] = { CreateFormInstances(sharedThis->env_, formInstances) };
                        napi_call_function(sharedThis->env_, res, res, sizeof(argv) / sizeof(argv[0]), argv, nullptr);
                    }
                }
            }
            napi_close_handle_scope(sharedThis->env_, scope);
        });
    }
    return ERR_OK;
}

ErrCode JsFormStateObserver::OnFormClickEvent(
    const std::string &bundleName, const std::string &callType, const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("call");
    if (callType.empty()) {
        HILOG_ERROR("empty Calltype");
        return ERR_INVALID_VALUE;
    }

    std::shared_ptr<AppExecFwk::EventHandler> handler = GetMainEventRunner();
    if (handler == nullptr) {
        HILOG_ERROR("null Handler");
        return ERR_INVALID_VALUE;
    }

    wptr<JsFormStateObserver> weakObserver = this;
    auto notify = [bundleName, callType, runningFormInfo, weakObserver]() {
        auto self = weakObserver.promote();
        if (self == nullptr) {
            HILOG_ERROR("null Self");
            return;
        }
        std::unique_lock<std::mutex> lock(self->formEventMapMutex_);
        auto formEventCallbackListIter = self->formEventMap_.find(bundleName);
        if (formEventCallbackListIter != self->formEventMap_.end()) {
            auto &callbackListVec = formEventCallbackListIter->second;
            auto callBackListIter = std::find_if(callbackListVec.begin(), callbackListVec.end(),
            [bundleName, callType](auto &iter) {
                return iter != nullptr &&
                       iter->BindFormEventType() == callType &&
                       iter->BindHostBundleName() == bundleName;
            });
            if (callBackListIter != callbackListVec.end() && (*callBackListIter) != nullptr) {
                (*callBackListIter)->HandleFormEvent(runningFormInfo);
            }
        }
    };

    handler->PostSyncTask(notify);
    return ERR_OK;
}

ErrCode JsFormStateObserver::RegisterClickEventCallback(
    const napi_env env, const std::string &bundleName, const napi_value callback, const std::string &type)
{
    HILOG_DEBUG("call");
    auto record = std::make_shared<FormEventCallbackList>(bundleName, type, env);
    if (record == nullptr) {
        HILOG_ERROR("New obj error");
        return ERR_INVALID_VALUE;
    }
    record->PushCallback(callback);

    std::unique_lock<std::mutex> lock(formEventMapMutex_);

    auto formEventCallbackListIter = formEventMap_.find(bundleName);
    if (formEventCallbackListIter == formEventMap_.end()) {
        std::vector<std::shared_ptr<FormEventCallbackList>> formEventCallbackListVector {record};
        formEventMap_.emplace(bundleName, formEventCallbackListVector);
        AppExecFwk::FormMgr::GetInstance().RegisterClickEventObserver(
            bundleName, type, JsFormStateObserver::GetInstance());
        return ERR_OK;
    }

    auto &callbackListVec = formEventCallbackListIter->second;
    auto callBackListIter = std::find_if(
        callbackListVec.begin(), callbackListVec.end(), [bundleName, type](auto &iter) {
            return iter != nullptr && iter->BindFormEventType() == type && iter->BindHostBundleName() == bundleName;
        });
    if (callBackListIter != callbackListVec.end() && (*callBackListIter) != nullptr) {
        (*callBackListIter)->PushCallback(callback);
        return ERR_OK;
    }

    formEventCallbackListIter->second.emplace_back(record);
    AppExecFwk::FormMgr::GetInstance().RegisterClickEventObserver(bundleName, type, JsFormStateObserver::GetInstance());
    return ERR_OK;
}

ErrCode JsFormStateObserver::ClearFormClickCallbackByBundleName(const std::string &type, const std::string &bundleName)
{
    HILOG_DEBUG("call");
    std::unique_lock<std::mutex> lock(formEventMapMutex_);
    auto formEventCallbackListIter = formEventMap_.find(bundleName);
    if (formEventCallbackListIter == formEventMap_.end()) {
        HILOG_ERROR("Invalid bundleName");
        return ERR_INVALID_VALUE;
    }

    auto &callbackListVec = formEventCallbackListIter->second;
    auto callBackListIter = std::find_if(
        callbackListVec.begin(), callbackListVec.end(), [bundleName, type](auto &iter) {
            return iter != nullptr && iter->BindFormEventType() == type && iter->BindHostBundleName() == bundleName;
        });
    if (callBackListIter == callbackListVec.end()) {
        HILOG_ERROR("This bundle hasn't registered any callback of this type");
        return ERR_INVALID_VALUE;
    }
    callbackListVec.erase(callBackListIter);
    AppExecFwk::FormMgr::GetInstance().UnregisterClickEventObserver(
        bundleName, type, JsFormStateObserver::GetInstance());
    return ERR_OK;
}

ErrCode JsFormStateObserver::ClearFormClickCallback(
    const std::string &type, const std::string &bundleName, const napi_value &callback)
{
    HILOG_DEBUG("call");
    std::unique_lock<std::mutex> lock(formEventMapMutex_);
    auto formEventCallbackListIter = formEventMap_.find(bundleName);
    if (formEventCallbackListIter == formEventMap_.end()) {
        HILOG_ERROR("Invalid bundleName");
        return ERR_INVALID_VALUE;
    }

    auto &callbackListVec = formEventCallbackListIter->second;
    auto callBackListIter = std::find_if(
        callbackListVec.begin(), callbackListVec.end(), [bundleName, type](auto &iter) {
            return iter != nullptr && iter->BindFormEventType() == type && iter->BindHostBundleName() == bundleName;
        });
    if (callBackListIter == callbackListVec.end()) {
        HILOG_ERROR("This bundle hasn't registered any callback of this type");
        return ERR_INVALID_VALUE;
    }

    auto sharedItem = *callBackListIter;
    if (sharedItem == nullptr) {
        HILOG_ERROR("Holding empty objects");
        return ERR_INVALID_VALUE;
    }

    sharedItem->RemoveCallback(callback);
    if (sharedItem->IsEmpty()) {
        callbackListVec.erase(callBackListIter);
        // Need to notify fms
        AppExecFwk::FormMgr::GetInstance().UnregisterClickEventObserver(
            bundleName, type, JsFormStateObserver::GetInstance());
    }
    return ERR_OK;
}

FormEventCallbackList::~FormEventCallbackList()
{
    for (auto &iter : callbacks_) {
        napi_delete_reference(env_, iter);
    }
}

bool FormEventCallbackList::ContainEqualCallback(napi_value callback) const
{
    HILOG_DEBUG("call");
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    bool ref = false;
    napi_value compareCallback = nullptr;
    for (auto &call : callbacks_) {
        napi_get_reference_value(env_, call, &compareCallback);
        napi_strict_equals(env_, compareCallback, callback, &ref);
        if (ref) {
            return ref;
        }
    }
    return ref;
}

void FormEventCallbackList::PushCallback(napi_value call)
{
    HILOG_DEBUG("call");
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    if (!ContainEqualCallback(call)) {
        napi_ref callbackRef;
        napi_create_reference(env_, call, REF_COUNT, &callbackRef);
        if (callbackRef != nullptr) {
            callbacks_.emplace_back(callbackRef);
        }
    }
}

void FormEventCallbackList::RemoveCallback(napi_value call)
{
    HILOG_DEBUG("call");
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    auto iter = std::find_if(callbacks_.begin(), callbacks_.end(), [env = env_, callback = call](auto &item) {
        bool equal = false;
        napi_value callbackFun = nullptr;
        napi_get_reference_value(env, item, &callbackFun);
        if (callbackFun != nullptr) {
            napi_strict_equals(env, callbackFun, callback, &equal);
        }
        return equal;
    });
    if (iter != callbacks_.end()) {
        napi_delete_reference(env_, *iter);
        callbacks_.erase(iter);
    }
}

void FormEventCallbackList::HandleFormEvent(const AppExecFwk::RunningFormInfo &runningFormInfo) const
{
    HILOG_DEBUG("call");
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    napi_value formInfo = nullptr;
    napi_create_object(env_, &formInfo);
    ParseRunningFormInfoIntoNapi(env_, runningFormInfo, formInfo);
    napi_value callResult;
    napi_value callbackfun = nullptr;
    for (auto &iter : callbacks_) {
        napi_get_reference_value(env_, iter, &callbackfun);
        if (callbackfun != nullptr) {
            napi_call_function(env_, nullptr, callbackfun, ARGS_ONE, &formInfo, &callResult);
        }
    }
}
}  // namespace AbilityRuntime
}  // namespace OHOS
