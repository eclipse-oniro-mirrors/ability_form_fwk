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

#include "ets_form_state_observer.h"

#include <regex>

#include "ani_form_common_util.h"
#include "ani_form_util.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "running_form_info.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* CLASSNAME_CALLBACK_WRAPPER = "@ohos.app.form.formObserver.CallbackWrapper";
constexpr const char* FORM_STATE_OBSERVER_FORMADD = "formAdd";
constexpr const char* FORM_STATE_OBSERVER_FORMREMOVE = "formRemove";
constexpr uint KEY_LIMIT = 16;
constexpr ani_size REFERENCES_MAX_NUMBER = 16;
}

EtsFormAddCallbackClient::EtsFormAddCallbackClient(ani_env* env, ani_ref callbackRef)
{
    env_ = env;
    callbackRef_ = callbackRef;
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
}

EtsFormAddCallbackClient::~EtsFormAddCallbackClient()
{
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if ((status = env_->GlobalReference_Delete(callbackRef_)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
        return;
    }
}

void EtsFormAddCallbackClient::ProcessFormAdd(const std::string &bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    if (handler_ == nullptr) {
        HILOG_ERROR("null handler");
        return;
    }
    handler_->PostSyncTask([thisWeakPtr = weak_from_this(), bundleName, runningFormInfo]() {
        auto sharedThis = thisWeakPtr.lock();
        if (sharedThis == nullptr) {
            HILOG_ERROR("null sharedThis");
            return;
        }
        ani_object callbackValues = CreateRunningFormInfo(sharedThis->env_, runningFormInfo);
        if (callbackValues == nullptr) {
            HILOG_ERROR("null callbackValues");
            return;
        }
        bool bRet = Callback(sharedThis->env_, static_cast<ani_object>(sharedThis->callbackRef_),
            callbackValues, CLASSNAME_CALLBACK_WRAPPER);
        if (!bRet) {
            HILOG_ERROR("callback failed");
            return;
        }
    });
}

bool EtsFormAddCallbackClient::IsStrictEqual(ani_object callback)
{
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_boolean isEqual = false;
    env_->Reference_StrictEquals(callback, callbackRef_, &isEqual);
    HILOG_INFO("isStrictEqual:%{public}d", isEqual);
    return static_cast<bool>(isEqual);
}

EtsFormRemoveCallbackClient::EtsFormRemoveCallbackClient(ani_env* env, ani_ref callbackRef)
{
    env_ = env;
    callbackRef_ = callbackRef;
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
}

EtsFormRemoveCallbackClient::~EtsFormRemoveCallbackClient()
{
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if ((status = env_->GlobalReference_Delete(callbackRef_)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
        return;
    }
}

void EtsFormRemoveCallbackClient::ProcessFormRemove(const std::string &bundleName,
    const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    if (handler_ == nullptr) {
        HILOG_ERROR("null handler");
        return;
    }
    handler_->PostSyncTask([thisWeakPtr = weak_from_this(), bundleName, runningFormInfo]() {
        auto sharedThis = thisWeakPtr.lock();
        if (sharedThis == nullptr) {
            HILOG_ERROR("null sharedThis");
            return;
        }
        ani_object callbackValues = CreateRunningFormInfo(sharedThis->env_, runningFormInfo);
        if (callbackValues == nullptr) {
            HILOG_ERROR("null callbackValues");
            return;
        }
        bool bRet = Callback(sharedThis->env_, static_cast<ani_object>(sharedThis->callbackRef_),
            callbackValues, CLASSNAME_CALLBACK_WRAPPER);
        if (!bRet) {
            HILOG_ERROR("callback failed");
            return;
        }
    });
}

bool EtsFormRemoveCallbackClient::IsStrictEqual(ani_object callback)
{
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_boolean isEqual = false;
    env_->Reference_StrictEquals(callback, callbackRef_, &isEqual);
    HILOG_INFO("isStrictEqual:%{public}d", isEqual);
    return static_cast<bool>(isEqual);
}

sptr<EtsFormStateObserver> EtsFormStateObserver::GetInstance()
{
    static std::once_flag initFlag;
    static sptr<EtsFormStateObserver> instance;
    
    std::call_once(initFlag, []() {
        instance = sptr<EtsFormStateObserver>(new (std::nothrow) EtsFormStateObserver());
        if (instance == nullptr) {
            HILOG_ERROR("create EtsFormStateObserver failed");
        }
    });
    
    return instance;
}

bool EtsFormStateObserver::CheckMapSize(const std::string &type, const std::string &bundleName)
{
    HILOG_DEBUG("start");
    const size_t formAddLength = strlen(FORM_STATE_OBSERVER_FORMADD);
    const size_t formRemoveLength = strlen(FORM_STATE_OBSERVER_FORMREMOVE);
    if (type.length() != formAddLength && type.length() != formRemoveLength) {
        return false;
    }
    if (type == FORM_STATE_OBSERVER_FORMADD) {
        std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
        if (formAddCallbackMap_.find(bundleName) == formAddCallbackMap_.end()) {
            if (formAddCallbackMap_.size() >= KEY_LIMIT) {
                HILOG_ERROR("the number of the bundleName exceeds the limit");
                return false;
            }
        }
    } else if (type == FORM_STATE_OBSERVER_FORMREMOVE) {
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

ani_env* EtsFormStateObserver::GetAniEnv(ani_vm* ani_vm)
{
    if (ani_vm == nullptr) {
        HILOG_ERROR("ani_vm is null");
        return nullptr;
    }
    ani_env* env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = ani_vm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        HILOG_ERROR("GetEnv failed status: %{public}d", status);
        return nullptr;
    }
    return env;
}

bool EtsFormStateObserver::RegisterFormAddCallback(ani_vm* ani_vm,
    const std::string &bundleName, const ani_object callback)
{
    HILOG_DEBUG("start");
    ani_env* env = GetAniEnv(ani_vm);
    if (env == nullptr) {
        HILOG_ERROR("GetAniEnv failed");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref callbackRef;
    if ((status = env->GlobalReference_Create(callback, &callbackRef)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create status : %{public}d", status);
        return false;
    }
    std::shared_ptr<EtsFormAddCallbackClient> callbackClient = std::make_shared<EtsFormAddCallbackClient>(env,
        callbackRef);

    std::lock_guard<std::mutex> lock(addFormCallbackMutex_);
    auto formAddCallbacks = formAddCallbackMap_.find(bundleName);
    if (formAddCallbacks == formAddCallbackMap_.end()) {
        std::vector<std::shared_ptr<EtsFormAddCallbackClient>> callbacks;
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

bool EtsFormStateObserver::RegisterFormRemoveCallback(ani_vm* ani_vm,
    const std::string &bundleName, const ani_object callback)
{
    HILOG_DEBUG("start");
    ani_env* env = GetAniEnv(ani_vm);
    if (env == nullptr) {
        HILOG_ERROR("GetAniEnv failed");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref callbackRef;
    if ((status = env->GlobalReference_Create(callback, &callbackRef)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create status : %{public}d", status);
        return false;
    }
    std::shared_ptr<EtsFormRemoveCallbackClient> callbackClient =
        std::make_shared<EtsFormRemoveCallbackClient>(env, callbackRef);

    std::lock_guard<std::mutex> lock(removeFormCallbackMutex_);
    auto formRemoveCallbacks = formRemoveCallbackMap_.find(bundleName);
    if (formRemoveCallbacks == formRemoveCallbackMap_.end()) {
        std::vector<std::shared_ptr<EtsFormRemoveCallbackClient>> callbacks;
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

void EtsFormStateObserver::ClearFormAddCallbackByBundle(const std::string &bundleName)
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

void EtsFormStateObserver::DelFormAddCallbackByBundle(const ani_object callback, const std::string &bundleName)
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

int32_t EtsFormStateObserver::OnAddForm(const std::string &bundleName,
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

void EtsFormStateObserver::ClearFormRemoveCallbackByBundle(const std::string &bundleName)
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

void EtsFormStateObserver::DelFormRemoveCallbackByBundle(const ani_object callback, const std::string &bundleName)
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

int32_t EtsFormStateObserver::OnRemoveForm(const std::string &bundleName,
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

int EtsFormStateObserver::RegisterFormInstanceCallback(ani_vm* ani_vm, ani_object etsObserverObject,
    bool isVisibility, std::string &bundleName, sptr<EtsFormStateObserver> &formObserver)
{
    HILOG_DEBUG("call");
    if (ani_vm_ == nullptr) {
        ani_vm_ = ani_vm;
    }
    ani_env* env = GetAniEnv(ani_vm);
    if (env == nullptr) {
        HILOG_ERROR("GetAniEnv failed");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    std::string specialFlag = "#";
    std::lock_guard<std::mutex> lock(formIsvisibleCallbackMutex_);
    ani_ref ref = nullptr;
    auto etsReference = std::make_shared<AppExecFwk::ETSNativeReference>();
    if (isVisibility) {
        auto visibleCallback = formVisibleCallbackMap_.find(bundleName);
        if (visibleCallback != formVisibleCallbackMap_.end()) {
            HILOG_ERROR("bundleName is already in the map,bundleName id %{public}s", bundleName.c_str());
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        ani_status status = ANI_ERROR;
        if ((status = env->GlobalReference_Create(etsObserverObject, &ref)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Create status : %{public}d", status);
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        etsReference->aniRef = ref;
        formVisibleCallbackMap_.emplace(bundleName, etsReference);
    } else {
        auto invisibleCallback = formInvisibleCallbackMap_.find(bundleName);
        if (invisibleCallback != formInvisibleCallbackMap_.end()) {
            HILOG_ERROR("bundleName is already in the map,bundleName id %{public}s", bundleName.c_str());
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        ani_status status = ANI_ERROR;
        if ((status = env->GlobalReference_Create(etsObserverObject, &ref)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Create status : %{public}d", status);
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        etsReference->aniRef = ref;
        formInvisibleCallbackMap_.emplace(bundleName, etsReference);
    }
    AppExecFwk::FormMgr::GetInstance().RegisterAddObserver(bundleName + specialFlag + std::to_string(isVisibility),
        formObserver);
    return ERR_OK;
}

ErrCode EtsFormStateObserver::ClearFormNotifyVisibleCallbackByBundle(const std::string bundleName,
    bool isVisibility, sptr<EtsFormStateObserver> &formObserver)
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

ErrCode EtsFormStateObserver::DelFormNotifyVisibleCallbackByBundle(const std::string bundleName,
    bool isVisibility, ani_object etsObserverObject, sptr<EtsFormStateObserver> &formObserver)
{
    HILOG_DEBUG("call");
    ani_env* env = GetAniEnv(ani_vm_);
    if (env == nullptr) {
        HILOG_ERROR("GetAniEnv failed");
        return false;
    }
    ani_boolean isEqual = false;
    std::lock_guard<std::mutex> lock(formIsvisibleCallbackMutex_);
    std::string specialFlag = "#";
    if (isVisibility) {
        auto visibleCallback = formVisibleCallbackMap_.find(bundleName);
        if (visibleCallback != formVisibleCallbackMap_.end()) {
            ani_ref value = visibleCallback->second->aniRef;
            env->Reference_StrictEquals(etsObserverObject, value, &isEqual);
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
            ani_ref value = invisibleCallback->second->aniRef;
            env->Reference_StrictEquals(etsObserverObject, value, &isEqual);
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

int32_t EtsFormStateObserver::NotifyWhetherFormsVisible(const AppExecFwk::FormVisibilityType visibleType,
    const std::string &bundleName, std::vector<AppExecFwk::FormInstance> &formInstances)
{
    handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formIsvisibleCallbackMutex_);
    if (handler_) {
        wptr<EtsFormStateObserver> weakObserver = this;
        handler_->PostSyncTask([weakObserver, visibleType, formInstances, bundleName, aniVm = ani_vm_, this]() {
            std::string specialFlag = "#";
            bool isVisibleTypeFlag = false;
            auto sharedThis = weakObserver.promote();
            if (sharedThis == nullptr) {
                HILOG_ERROR("null sharedThis");
                return;
            }
            ani_env* env = GetAniEnv(aniVm);
            if (env == nullptr) {
                HILOG_ERROR("GetAniEnv failed");
                return;
            }
            ani_size nr_refs = REFERENCES_MAX_NUMBER;
            env->CreateLocalScope(nr_refs);
            if (visibleType == AppExecFwk::FormVisibilityType::VISIBLE) {
                isVisibleTypeFlag = true;
                if (bundleName.find((specialFlag + std::to_string(isVisibleTypeFlag))) != std::string::npos) {
                    std::string bundleNameNew = std::regex_replace(bundleName,
                        std::regex(specialFlag + std::to_string(isVisibleTypeFlag)), "");
                    auto visibleCallback = sharedThis->formVisibleCallbackMap_.find(bundleNameNew);
                    if (visibleCallback != sharedThis->formVisibleCallbackMap_.end()) {
                        ani_ref res = visibleCallback->second->aniRef;
                        ani_object aniValue = CreateFormInstances(env, formInstances);
                        bool bRet = Callback(env, static_cast<ani_object>(res), aniValue, CLASSNAME_CALLBACK_WRAPPER);
                        if (!bRet) {
                            HILOG_ERROR("callback failed");
                            return;
                        }
                    }
                }
            } else {
                isVisibleTypeFlag = false;
                if (bundleName.find((specialFlag + std::to_string(isVisibleTypeFlag))) != std::string::npos) {
                    std::string bundleNameNew =
                        std::regex_replace(bundleName, std::regex(specialFlag + std::to_string(isVisibleTypeFlag)), "");
                    auto invisibleCallback = sharedThis->formInvisibleCallbackMap_.find(bundleNameNew);
                    if (invisibleCallback != sharedThis->formInvisibleCallbackMap_.end()) {
                        ani_ref res = invisibleCallback->second->aniRef;
                        ani_object aniValue = CreateFormInstances(env, formInstances);
                        bool bRet = Callback(env, static_cast<ani_object>(res), aniValue, CLASSNAME_CALLBACK_WRAPPER);
                        if (!bRet) {
                            HILOG_ERROR("callback failed");
                            return;
                        }
                    }
                }
            }
            env->DestroyLocalScope();
        });
    }
    return ERR_OK;
}

ErrCode EtsFormStateObserver::OnFormClickEvent(
    const std::string &bundleName, const std::string &callType, const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("call");
    if (callType.empty()) {
        HILOG_ERROR("empty Calltype");
        return ERR_INVALID_VALUE;
    }
    if (handler_ == nullptr) {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    wptr<EtsFormStateObserver> weakObserver = this;
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

    handler_->PostSyncTask(notify);
    return ERR_OK;
}

ErrCode EtsFormStateObserver::RegisterClickEventCallback(
    ani_vm* ani_vm, const std::string &bundleName, const ani_object callback, const std::string &type)
{
    HILOG_DEBUG("call");
    ani_env* env = GetAniEnv(ani_vm);
    if (env == nullptr) {
        HILOG_ERROR("GetAniEnv failed");
        return ERR_INVALID_VALUE;
    }
    auto record = std::make_shared<EtsFormEventCallbackList>(bundleName, type, env);
    if (record == nullptr) {
        HILOG_ERROR("New obj error");
        return ERR_INVALID_VALUE;
    }
    record->PushCallback(callback);

    std::unique_lock<std::mutex> lock(formEventMapMutex_);

    auto formEventCallbackListIter = formEventMap_.find(bundleName);
    if (formEventCallbackListIter == formEventMap_.end()) {
        std::vector<std::shared_ptr<EtsFormEventCallbackList>> formEventCallbackListVector {record};
        formEventMap_.emplace(bundleName, formEventCallbackListVector);
        AppExecFwk::FormMgr::GetInstance().RegisterClickEventObserver(
            bundleName, type, EtsFormStateObserver::GetInstance());
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
    AppExecFwk::FormMgr::GetInstance().RegisterClickEventObserver(
        bundleName, type, EtsFormStateObserver::GetInstance());
    return ERR_OK;
}

ErrCode EtsFormStateObserver::ClearFormClickCallbackByBundleName(const std::string &type, const std::string &bundleName)
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
        bundleName, type, EtsFormStateObserver::GetInstance());
    return ERR_OK;
}

ErrCode EtsFormStateObserver::ClearFormClickCallback(
    const std::string &type, const std::string &bundleName, const ani_object &callback)
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
            bundleName, type, EtsFormStateObserver::GetInstance());
    }
    return ERR_OK;
}

EtsFormEventCallbackList::~EtsFormEventCallbackList()
{
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    for (auto &iter : callbacks_) {
        if ((status = env_->GlobalReference_Delete(iter)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            continue;
        }
    }
}

bool EtsFormEventCallbackList::ContainEqualCallback(ani_object callback) const
{
    HILOG_DEBUG("call");
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_boolean isEqual = false;
    for (auto &call : callbacks_) {
        env_->Reference_StrictEquals(callback, call, &isEqual);
        if (isEqual) {
            return isEqual;
        }
    }
    return isEqual;
}

void EtsFormEventCallbackList::PushCallback(ani_object call)
{
    HILOG_DEBUG("call");
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    if (!ContainEqualCallback(call)) {
        ani_status status = ANI_ERROR;
        ani_ref callbackRef;
        if ((status = env_->GlobalReference_Create(call, &callbackRef)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Create status: %{public}d", status);
            return;
        }
        if (callbackRef != nullptr) {
            callbacks_.emplace_back(callbackRef);
        }
    }
}

void EtsFormEventCallbackList::RemoveCallback(ani_object call)
{
    HILOG_DEBUG("call");
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    auto iter = std::find_if(callbacks_.begin(), callbacks_.end(), [env = env_, callback = call](auto &item) {
        ani_boolean equal = false;
        env->Reference_StrictEquals(callback, item, &equal);
        return equal;
    });
    if (iter != callbacks_.end()) {
        ani_status status = ANI_ERROR;
        if ((status = env_->GlobalReference_Delete(*iter)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            return;
        }
        callbacks_.erase(iter);
    }
}

void EtsFormEventCallbackList::HandleFormEvent(const AppExecFwk::RunningFormInfo &runningFormInfo) const
{
    HILOG_DEBUG("call");
    if (env_ == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    ani_object formInfo = CreateRunningFormInfo(env_, runningFormInfo);
    if (formInfo == nullptr) {
        HILOG_ERROR("null callbackValues");
        return;
    }
    for (auto &iter : callbacks_) {
        bool bRet = Callback(env_, static_cast<ani_object>(iter), formInfo, CLASSNAME_CALLBACK_WRAPPER);
        if (!bRet) {
            HILOG_ERROR("callback failed");
            continue;
        }
    }
}
}  // namespace AbilityRuntime
}  // namespace OHOS