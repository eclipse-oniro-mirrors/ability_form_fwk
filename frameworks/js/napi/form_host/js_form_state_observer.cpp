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

void FormRemoveCallbackClient::ProcessFormRemove(const std::string &bundleName,
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

bool JsFormStateObserver::CheckMapSize(const std::string &type, const std::string &bundleName)
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
    const std::string &bundleName, const napi_value callback)
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
    const std::string &bundleName, const napi_value callback)
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

void JsFormStateObserver::ClearFormAddCallbackByBundle(const std::string &bundleName)
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

void JsFormStateObserver::DelFormAddCallbackByBundle(const napi_value callback, const std::string &bundleName)
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

int32_t JsFormStateObserver::OnAddForm(const std::string &bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
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

void JsFormStateObserver::ClearFormRemoveCallbackByBundle(const std::string &bundleName)
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

void JsFormStateObserver::DelFormRemoveCallbackByBundle(const napi_value callback, const std::string &bundleName)
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

int32_t JsFormStateObserver::OnRemoveForm(const std::string &bundleName,
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

int JsFormStateObserver::RegisterFormInstanceCallback(napi_env env, napi_value jsObserverObject,
    bool isVisibility, std::string &bundleName, sptr<JsFormStateObserver> &formObserver)
{
    HILOG_DEBUG("called.");
    if (env_ == nullptr) {
        env_ = env;
    }
    std::string specialFlag = "#";
    std::lock_guard<std::mutex> lock(formIsvisibleCallbackMutex_);
    napi_ref ref = nullptr;
    if (isVisibility) {
        auto visibleCallback = formVisibleCallbackMap_.find(bundleName);
        if (visibleCallback != formVisibleCallbackMap_.end()) {
            HILOG_ERROR("bundleName is already in the map, bundleName id %{public}s", bundleName.c_str());
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        napi_create_reference(env, jsObserverObject, 1, &ref);
        formVisibleCallbackMap_.emplace(
            bundleName, std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference *>(ref)));
    } else {
        auto invisibleCallback = formInvisibleCallbackMap_.find(bundleName);
        if (invisibleCallback != formInvisibleCallbackMap_.end()) {
            HILOG_ERROR("bundleName is already in the map, bundleName id %{public}s", bundleName.c_str());
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
    HILOG_DEBUG("called.");
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
    HILOG_DEBUG("called.");
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

int32_t JsFormStateObserver::NotifyWhetherFormsVisible(const AppExecFwk::FormVisibilityType visibleType,
    const std::string &bundleName, std::vector<AppExecFwk::FormInstance> &formInstances)
{
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    HILOG_DEBUG("called.");
    std::lock_guard<std::mutex> lock(formIsvisibleCallbackMutex_);
    if (handler_) {
        wptr<JsFormStateObserver> weakObserver = this;
        handler_->PostSyncTask([weakObserver, visibleType, formInstances, bundleName]() {
            std::string specialFlag = "#";
            bool isVisibleTypeFlag = false;
            auto sharedThis = weakObserver.promote();
            if (sharedThis == nullptr) {
                HILOG_ERROR("sharedThis is nullptr.");
                return;
            }
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(sharedThis->env_, &scope);
            if (scope == nullptr) {
                HILOG_ERROR("scope is nullptr.");
                return;
            }
            if (visibleType == AppExecFwk::FormVisibilityType::VISIBLE) {
                isVisibleTypeFlag = true;
                if (bundleName.find((specialFlag + std::to_string(isVisibleTypeFlag))) != std::string::npos) {
                    std::string bundleNameNew =
                        std::regex_replace(bundleName, std::regex(specialFlag + std::to_string(isVisibleTypeFlag)), "");
                    auto visibleCallback = sharedThis->formVisibleCallbackMap_.find(bundleNameNew);
                    if (visibleCallback != sharedThis->formVisibleCallbackMap_.end()) {
                        napi_value value = visibleCallback->second->GetNapiValue();
                        napi_value argv[] = { CreateFormInstances(sharedThis->env_, formInstances) };
                        napi_call_function(sharedThis->env_,
                            value, value, sizeof(argv) / sizeof(argv[0]), argv, nullptr);
                    }
                }
            } else {
                isVisibleTypeFlag = false;
                if (bundleName.find((specialFlag + std::to_string(isVisibleTypeFlag))) != std::string::npos) {
                    std::string bundleNameNew =
                        std::regex_replace(bundleName, std::regex(specialFlag + std::to_string(isVisibleTypeFlag)), "");
                    auto invisibleCallback = sharedThis->formInvisibleCallbackMap_.find(bundleNameNew);
                    if (invisibleCallback != sharedThis->formInvisibleCallbackMap_.end()) {
                        napi_value value = invisibleCallback->second->GetNapiValue();
                        napi_value argv[] = { CreateFormInstances(sharedThis->env_, formInstances) };
                        napi_call_function(sharedThis->env_,
                            value, value, sizeof(argv) / sizeof(argv[0]), argv, nullptr);
                    }
                }
            }
            napi_close_handle_scope(sharedThis->env_, scope);
        });
    }
    return ERR_OK;
}

ErrCode JsFormStateObserver::OnFormClickEvent(
    const std::string &callType, const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("Called.");
    std::lock_guard<std::mutex> lock(formClickCallbackMutex_);
    if (callType.empty()) {
        HILOG_ERROR("Calltype is empty.");
        return ERR_INVALID_VALUE;
    }
    if (handler_ == nullptr) {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
        if (handler_ == nullptr) {
            HILOG_ERROR("Handler is nullptr.");
            return ERR_INVALID_VALUE;
        }
    }
    wptr<JsFormStateObserver> weakObserver = this;
    handler_->PostSyncTask([weakObserver, runningFormInfo, callType]() {
        auto formClickCallbacks = weakObserver->formClickCallbackMap_.find(callType);
        if (formClickCallbacks != weakObserver->formClickCallbackMap_.end()) {
            auto callBacks = formClickCallbacks->second.find("");
            auto sharedThis = weakObserver.promote();
            if (sharedThis == nullptr) {
                HILOG_ERROR("Sharedthis is nullptr.");
                return ERR_INVALID_VALUE;
            }
            if (callBacks != formClickCallbacks->second.end()) {
                for (const auto &callback : callBacks->second) {
                    napi_value value = callback->GetNapiValue();
                    napi_value argv[] = { CreateRunningFormInfo(sharedThis->env_, runningFormInfo) };
                    HILOG_DEBUG("callfunction successful");
                    napi_call_function(sharedThis->env_,
                        value, value, sizeof(argv) / sizeof(argv[0]), argv, nullptr);
                }
            }
            auto callBacksByBundleName = formClickCallbacks->second.find(runningFormInfo.hostBundleName);
            if (callBacksByBundleName != formClickCallbacks->second.end()) {
                for (const auto &callback : callBacksByBundleName->second) {
                    napi_value value = callback->GetNapiValue();
                    napi_value argv[] = { CreateRunningFormInfo(sharedThis->env_, runningFormInfo) };
                    napi_call_function(sharedThis->env_,
                        value, value, sizeof(argv) / sizeof(argv[0]), argv, nullptr);
                }
            }
        }
        return ERR_OK;
    });
    return ERR_OK;
}


bool JsFormStateObserver::IsFormClickCallbackMapEmpty()
{
    HILOG_DEBUG("Called.");
    if (formClickCallbackMap_.empty()) {
        HILOG_DEBUG("Form click callback map is empty.");
        return true;
    }
    HILOG_DEBUG("Form click callback map is not empty.");
    return false;
}

ErrCode JsFormStateObserver::FormClickAddCallTask(napi_env env, napi_value callback,
        std::vector<std::shared_ptr<NativeReference>> &callbacks)
{
    HILOG_DEBUG("Called.");
    if (env == nullptr || callback == nullptr) {
        HILOG_ERROR("The callback or the env is nullptr.");
        return ERR_INVALID_VALUE;
    }

    for (auto &iter : callbacks) {
        if (iter == nullptr) {
            HILOG_ERROR("iter is nullptr.");
            return ERR_INVALID_VALUE;
        }
        bool isEqual;
        napi_strict_equals(env, iter->GetNapiValue(), callback, &isEqual);
        if (isEqual) {
            HILOG_ERROR("Found the equal callback.");
            return ERR_ALREADY_EXISTS;
        }
    }
    napi_ref callbackRef;
    napi_create_reference(env, callback, REF_COUNT, &callbackRef);
    callbacks.emplace_back(reinterpret_cast<NativeReference *>(callbackRef));
    return ERR_OK;
}

ErrCode JsFormStateObserver::RegisterClickCallbackEventCallback(const napi_env env,const std::string &bundleName,
    const napi_value callback, const std::string &type)
{
    HILOG_DEBUG("Called.");
    std::lock_guard<std::mutex> lock(formClickCallbackMutex_);
    if (env_ == nullptr) {
        env_ = env;
    }
    if (formClickCallbackMap_.empty()) {
        HILOG_DEBUG("Form click callback map is empty.");
        auto result = AppExecFwk::FormMgr::GetInstance().RegisterClickCallbackEventObserver(GetInstance());
        if (result != ERR_OK) {
            HILOG_ERROR("Get event observe fail,errcode is: %{public}d", result);
            return result;
        }
    }
    napi_ref callbackRef;
    auto formClickCallbacks = formClickCallbackMap_.find(type);
    if (formClickCallbacks != formClickCallbackMap_.end()) {
        auto callBacks = formClickCallbacks->second.find(bundleName);
        if (callBacks == formClickCallbacks->second.end()) {
            std::vector<std::shared_ptr<NativeReference>> callbacks;
            napi_create_reference(env, callback, REF_COUNT, &callbackRef);
            callbacks.emplace_back(std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference *>(callbackRef)));
            formClickCallbacks->second.emplace(bundleName, callbacks);
            return ERR_OK;
        }
        return FormClickAddCallTask(env_, callback, callBacks->second);
    } else {
        std::vector<std::shared_ptr<NativeReference>> callbacks;
        napi_create_reference(env, callback, REF_COUNT, &callbackRef);
        callbacks.emplace_back(std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference *>(callbackRef)));
        std::map<std::string, std::vector<std::shared_ptr<NativeReference>>> typeMap = { {bundleName, callbacks} };
        formClickCallbackMap_[type] = typeMap;
    }
    return ERR_OK;
}

ErrCode JsFormStateObserver::ClearFormClickCallbackByBundleName(const std::string &type, const std::string &bundleName)
{
    HILOG_DEBUG("Called");
    std::lock_guard<std::mutex> lock(formClickCallbackMutex_);
    auto formClickCallbacks = formClickCallbackMap_.find(type);
    if (formClickCallbacks == formClickCallbackMap_.end()) {
        HILOG_ERROR("There is no formClickCallbackType has been registed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    HILOG_DEBUG("The formClickCallbackType has been registed successful");
    auto callBacks = formClickCallbacks->second.find(bundleName);
    if (callBacks == formClickCallbacks->second.end()) {
        HILOG_ERROR("There is no formClickCallbackBundleName has been register");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    auto &callbacksVector = callBacks->second;
    callbacksVector.clear();
    formClickCallbacks->second.erase(callBacks);
    if (formClickCallbacks->second.empty()) {
        HILOG_DEBUG("Bundlename map is empty,erase the type");
        formClickCallbackMap_.erase(formClickCallbacks);
    }
    return ERR_OK;
}

ErrCode JsFormStateObserver::ClearFormClickCallback(const std::string &type, const std::string &bundleName,
    const napi_value &callback)
{
    HILOG_DEBUG("Called");
    std::lock_guard<std::mutex> lock(formClickCallbackMutex_);
    auto formClickCallbacks = formClickCallbackMap_.find(type);
    if (formClickCallbacks == formClickCallbackMap_.end()) {
        HILOG_ERROR("There is no type has been registed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    HILOG_DEBUG("Form click callback type has been registed");
    auto callBacks = formClickCallbacks->second.find(bundleName);
    if (callBacks == formClickCallbacks->second.end()) {
        HILOG_ERROR("There is no bundlename has been registed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    HILOG_DEBUG("Form click bundlename has been registed");
    auto iter = std::find_if(callBacks->second.begin(), callBacks->second.end(), [&](const auto &cb) {
        bool isEqual;
        napi_strict_equals(env_, cb->GetNapiValue(), callback, &isEqual);
        return isEqual;
    });
    if (iter != callBacks->second.end()) {
        HILOG_DEBUG("Find equal callback");
        callBacks->second.erase(iter);
    } else {
        HILOG_ERROR("There is no callback has been registed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }
    if (callBacks->second.empty()) {
        HILOG_DEBUG("The callback vector is empty,erase the bundlename");
        formClickCallbacks->second.erase(callBacks);
        if (formClickCallbacks->second.empty()) {
            HILOG_DEBUG("The bundlename map is empty,erase the type");
            formClickCallbackMap_.erase(formClickCallbacks);
        }
    }
    return ERR_OK;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
