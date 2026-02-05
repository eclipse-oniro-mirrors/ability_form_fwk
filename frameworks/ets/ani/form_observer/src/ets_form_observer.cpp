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

#include "ani_common_want.h"
#include "ani_form_common_util.h"
#include "ani_form_error_util.h"
#include "ani_form_util.h"
#include "ets_form_state_observer.h"
#include "ets_runtime.h"
#include "fms_log_wrapper.h"
#include "form_callback_interface.h"
#include "form_host_client.h"
#include "form_info.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using FormMgr = AppExecFwk::FormMgr;
namespace {
constexpr const char* ETS_FORM_OBSERVER_NAME = "@ohos.app.form.formObserver.formObserver";
constexpr const char* OBSERVER_CLASSNAME_ASYNC_CALLBACK_WRAPPER = "@ohos.app.form.formObserver.AsyncCallbackWrapper";
}
class EtsFormObserver {
public:
    EtsFormObserver() = default;
    ~EtsFormObserver() = default;

    static void RegisterFormObserver(ani_env* env, ani_string aniType,
        ani_object callback, ani_string aniHostBundleName)
    {
        HILOG_INFO("RegisterFormObserver Call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        if (!FormAniHelpers::CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }
        std::string type;
        if (!GetStdString(env, aniType, type)) {
            HILOG_ERROR("GetStdString failed");
            EtsFormErrorUtil::ThrowParamTypeError(env, "type",
                "formAdd, formRemove, notifyVisible, notifyInvisible, router, message, call.");
            return;
        }
        if (type == "formAdd") {
            OnRegisterFormAddObserver(env, aniHostBundleName, callback);
        } else if (type == "formRemove") {
            OnRegisterFormRemoveObserver(env, aniHostBundleName, callback);
        } else if (type == "notifyVisible") {
            OnRegisterFormIsVisibleObserver(env, aniHostBundleName, callback, true);
        } else if (type == "notifyInvisible") {
            OnRegisterFormIsVisibleObserver(env, aniHostBundleName, callback, false);
        } else if (type == "router" || type == "message" || type == "call") {
            OnRegisterClickEventCallback(env, type, aniHostBundleName, callback);
        } else {
            HILOG_ERROR("args[0] not formAdd,formRemove,notifyVisible,notifyInvisible,router,message,call");
            EtsFormErrorUtil::ThrowParamTypeError(env, "type",
                "formAdd, formRemove, notifyVisible, notifyInvisible, router, message, call.");
            return;
        }
    }

    static void UnregisterFormObserver(ani_env* env, ani_string aniType,
        ani_string aniHostBundleName, ani_object callback)
    {
        HILOG_INFO("UnregisterFormObserver Call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        if (!FormAniHelpers::CheckCallerIsSystemApp()) {
            HILOG_ERROR("The application not system-app, can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }
        std::string type;
        if (!GetStdString(env, aniType, type)) {
            HILOG_ERROR("GetStdString failed");
            EtsFormErrorUtil::ThrowParamTypeError(env, "type",
                "formAdd, formRemove, notifyVisible, notifyInvisible or notifyInvisible.");
            return;
        }

        if (type == "formAdd") {
            return OnUnregisterFormAddObserver(env, aniHostBundleName, callback);
        } else if (type == "formRemove") {
            return OnUnregisterFormRemoveObserver(env, aniHostBundleName, callback);
        } else if (type == "notifyVisible") {
            return OnUnregisterFormIsVisibleObserver(env, aniHostBundleName, callback, true);
        } else if (type == "notifyInvisible") {
            return OnUnregisterFormIsVisibleObserver(env, aniHostBundleName, callback, false);
        } else if (type == "router" || type == "message" || type == "call") {
            return OnUnregisterClickEventCallback(env, type, aniHostBundleName, callback);
        } else {
            HILOG_ERROR("args[0] not formAdd,formRemove,notifyVisible,notifyInvisible,router,message,call");
            EtsFormErrorUtil::ThrowParamTypeError(env, "type",
                "args[0] should be formAdd, formRemove,"
                "notifyVisible, notifyInvisible, router, message, call");
            return;
        }
    }

    static bool IsUndefined(ani_env* env, ani_ref ref)
    {
        if (env == nullptr) {
            HILOG_ERROR("null env");
            return false;
        }
        ani_status status = ANI_ERROR;
        ani_boolean isUndefined = false;
        if ((status = env->Reference_IsUndefined(ref, &isUndefined)) != ANI_OK) {
            HILOG_ERROR("Failed to check undefined status: %{public}d", status);
            return false;
        }
        return isUndefined;
    }
    static void GetRunningFormInfoById(ani_env *env, ani_string formId,
        ani_boolean aniIsUnusedIncluded, ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        std::string stdFormId = "";
        if (!GetStdString(env, formId, stdFormId)) {
            HILOG_ERROR("GetStdString failed");
            EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
            return;
        }
        int64_t formIdInt = -1;
        if (!ConvertStringToInt64(stdFormId, formIdInt)) {
            HILOG_ERROR("formId ConvertStringToInt64 failed");
            EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
            return;
        }
        bool isUnusedIncluded = static_cast<bool>(aniIsUnusedIncluded);
        std::shared_ptr<AppExecFwk::FormInstance> formInstance = std::make_shared<AppExecFwk::FormInstance>();

        ErrCode ret = FormMgr::GetInstance().GetFormInstanceById(formIdInt, isUnusedIncluded, *formInstance);
        if (ret != ERR_OK) {
            HILOG_ERROR("Get formInstance by id failed");
            AsyncCallback(env, OBSERVER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
                callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
            return;
        }
        ani_object aniFormInfo = CreateFormInstance(env, *formInstance);
        if (aniFormInfo == nullptr) {
            HILOG_ERROR("Create formInstance failed");
            return;
        }
        AsyncCallback(env, OBSERVER_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback, EtsFormErrorUtil::CreateError(env, ret),
            aniFormInfo);
    }

    static void GetRunningFormInfos(ani_env *env, ani_string hostBundleName,
        ani_boolean aniIsUnusedIncluded, ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        std::string stdBundleName = "";
        if (!GetStdString(env, hostBundleName, stdBundleName)) {
            HILOG_ERROR("GetStdString failed");
            EtsFormErrorUtil::ThrowParamError(env, "bundleName is empty.");
            return;
        }
        bool isUnusedIncluded = static_cast<bool>(aniIsUnusedIncluded);
        std::vector<AppExecFwk::RunningFormInfo> runningFormInfos;
        ErrCode ret = FormMgr::GetInstance().GetRunningFormInfosByBundleName(stdBundleName,
            isUnusedIncluded, runningFormInfos);
        if (ret != ERR_OK) {
            HILOG_ERROR("GetRunningFormInfosByBundleName failed, ret = %{public}d", ret);
            AsyncCallback(env, OBSERVER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
                callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
            return;
        }
        ani_object aniArrayFormInfos = CreateRunningFormInfos(env, runningFormInfos);
        if (aniArrayFormInfos == nullptr) {
            HILOG_ERROR("GetRunningFormInfos failed ret=%{public}d", ret);
            return;
        }
        AsyncCallback(env, OBSERVER_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback, EtsFormErrorUtil::CreateError(env, ret),
            aniArrayFormInfos);
        return;
    }

    static void GetRunningFormInfosNotBundlename(ani_env *env, ani_boolean aniIsUnusedIncludedValue,
        ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        bool isUnusedIncluded = static_cast<bool>(aniIsUnusedIncludedValue);
        std::vector<AppExecFwk::RunningFormInfo> runningFormInfos;
        ErrCode ret = FormMgr::GetInstance().GetRunningFormInfos(isUnusedIncluded, runningFormInfos);
        if (ret != ERR_OK) {
            HILOG_ERROR("GetRunningFormInfos failed ret=%{public}d", ret);
            AsyncCallback(env, OBSERVER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
                callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
            return;
        }
        ani_object aniArrayFormInfos = CreateRunningFormInfos(env, runningFormInfos);
        if (aniArrayFormInfos == nullptr) {
            HILOG_ERROR("GetRunningFormInfos failed ret=%{public}d", ret);
            return;
        }
        AsyncCallback(env, OBSERVER_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback, EtsFormErrorUtil::CreateError(env, ret),
            aniArrayFormInfos);
        return;
    }

    static void GetRunningFormInfosByFilter(ani_env *env, ani_object aniFormProviderFilter, ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        AppExecFwk::FormInstancesFilter filter;
        if (!ParseProviderFilter(env, aniFormProviderFilter, filter)) {
            HILOG_ERROR("Input params parse failed");
            EtsFormErrorUtil::ThrowParamTypeError(env, "formProviderFilter", "object");
        }
        auto formInstances = std::make_shared<std::vector<AppExecFwk::FormInstance>>();
        ErrCode ret = FormMgr::GetInstance().GetFormInstancesByFilter(filter, *formInstances);
        if (ret != ERR_OK) {
            HILOG_ERROR("Get form instances failed");
            AsyncCallback(env, OBSERVER_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
                callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
            return;
        }
        ani_object aniArrayFormInfos = CreateFormInstances(env, *formInstances);
        if (aniArrayFormInfos == nullptr) {
            HILOG_ERROR("GetRunningFormInfos failed ret=%{public}d", ret);
            return;
        }
        AsyncCallback(env, OBSERVER_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback, EtsFormErrorUtil::CreateError(env, ret),
            aniArrayFormInfos);
        return;
    }

    static void CheckFormIDParam(ani_env *env, ani_string formId)
    {
        if (env == nullptr) {
            HILOG_ERROR("null env");
            return;
        }
        std::string stdFormId = "";
        if (!GetStdString(env, formId, stdFormId)) {
            HILOG_ERROR("GetStdString failed");
            EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
            return;
        }
        HILOG_INFO("stdFormId %{public}s", stdFormId.c_str());
        int64_t formIdInt = -1;
        if (!ConvertStringToInt64(stdFormId, formIdInt)) {
            HILOG_ERROR("formId ConvertStringToInt64 failed");
            EtsFormErrorUtil::ThrowParamError(env, "The formId is invalid");
            return;
        }
    }

    static void CheckHostBundleNameParam(ani_env *env, ani_string hostBundleName)
    {
        if (env == nullptr) {
            HILOG_ERROR("null env");
            return;
        }
        std::string stdBundleName = "";
        if (!GetStdString(env, hostBundleName, stdBundleName)) {
            HILOG_ERROR("GetStdString failed");
            EtsFormErrorUtil::ThrowParamError(env, "bundleName is empty.");
            return;
        }
    }

    static void CheckformProviderFilterParam(ani_env *env, ani_object aniFormProviderFilter)
    {
        if (env == nullptr) {
            HILOG_ERROR("null env");
            return;
        }
        AppExecFwk::FormInstancesFilter filter;
        if (!ParseProviderFilter(env, aniFormProviderFilter, filter)) {
            HILOG_ERROR("Input params parse failed");
            EtsFormErrorUtil::ThrowParamTypeError(env, "formProviderFilter", "object");
        }
    }
private:

    static bool FormAniHelpers::CheckCallerIsSystemApp()
    {
        auto selfToken = IPCSkeleton::GetSelfTokenID();
        return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
    }

    static void OnRegisterFormAddObserver(ani_env* env, ani_string aniHostBundleName, ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("null env");
            return;
        }
        std::string bundleName = "";
        if (!GetStdString(env, aniHostBundleName, bundleName)) {
            HILOG_ERROR("GetStdString failed");
            EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
            return;
        }
        if (bundleName.empty()) {
            bundleName = "all";
        }
        if (!EtsFormStateObserver::GetInstance()->CheckMapSize("formAdd", bundleName)) {
            EtsFormErrorUtil::ThrowParamError(env,
                "The number of bundleNames registered to listen has exceeded the limit.");
            return;
        }
        ani_vm* aniVM = nullptr;
        if (env->GetVM(&aniVM) != ANI_OK) {
            HILOG_ERROR("get aniVM failed");
            return;
        }
        if (!EtsFormStateObserver::GetInstance()->RegisterFormAddCallback(aniVM, bundleName, callback)) {
            return;
        }
        FormMgr::GetInstance().RegisterFormAddObserverByBundle(bundleName, EtsFormStateObserver::GetInstance());
    }

    static void OnRegisterFormRemoveObserver(ani_env* env, ani_string aniHostBundleName, ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("null env");
            return;
        }
        std::string bundleName = "";
        if (!GetStdString(env, aniHostBundleName, bundleName)) {
            HILOG_ERROR("GetStdString failed");
            EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
            return;
        }
        if (bundleName.empty()) {
            bundleName = "all";
        }
        if (!EtsFormStateObserver::GetInstance()->CheckMapSize("formRemove", bundleName)) {
            EtsFormErrorUtil::ThrowParamError(env,
                "The number of bundleNames registered to listen has exceeded the limit.");
            return;
        }
        ani_vm* aniVM = nullptr;
        if (env->GetVM(&aniVM) != ANI_OK) {
            HILOG_ERROR("get aniVM failed");
            return;
        }
        if (!EtsFormStateObserver::GetInstance()->RegisterFormRemoveCallback(aniVM, bundleName, callback)) {
            HILOG_ERROR("RegisterFormRemoveCallback failed");
            return;
        }
        FormMgr::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, EtsFormStateObserver::GetInstance());
    }

    static void OnRegisterFormIsVisibleObserver(ani_env* env, ani_string aniHostBundleName,
        ani_object callback, bool isVisibility)
    {
        HILOG_DEBUG("call");
        std::string bundleName = "";
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        if (!IsUndefined(env, reinterpret_cast<ani_ref>(aniHostBundleName))) {
            if (!GetStdString(env, aniHostBundleName, bundleName) || bundleName.empty()) {
                HILOG_ERROR("GetStdString failed");
                EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
                return;
            }
        }
        sptr<EtsFormStateObserver> formObserver = EtsFormStateObserver::GetInstance();
        ani_vm* aniVM = nullptr;
        if (env->GetVM(&aniVM) != ANI_OK) {
            HILOG_ERROR("get aniVM failed");
            return;
        }
        EtsFormStateObserver::GetInstance()->
            RegisterFormInstanceCallback(aniVM, callback, isVisibility, bundleName, formObserver);
    }

    static void OnRegisterClickEventCallback(ani_env* env, const std::string &type,
        ani_string aniHostBundleName, ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("null env");
            return;
        }
        std::string bundleName = "";
        if (!GetStdString(env, aniHostBundleName, bundleName)) {
            HILOG_ERROR("GetStdString failed");
            EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
            return;
        }
        ani_vm* aniVM = nullptr;
        if (env->GetVM(&aniVM) != ANI_OK) {
            HILOG_ERROR("get aniVM failed");
            return;
        }
        EtsFormStateObserver::GetInstance()->RegisterClickEventCallback(aniVM, bundleName, callback, type);
    }

    static void OnUnregisterFormAddObserver(ani_env* env, ani_string aniHostBundleName, ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        bool isBundleNameUndefined = IsUndefined(env, reinterpret_cast<ani_ref>(aniHostBundleName));
        bool isCallbackUndefined = IsUndefined(env, reinterpret_cast<ani_ref>(callback));
        if (isBundleNameUndefined && isCallbackUndefined) {
            EtsFormStateObserver::GetInstance()->ClearFormAddCallbackByBundle("all");
            return;
        }
        if (isBundleNameUndefined && !isCallbackUndefined) {
            EtsFormStateObserver::GetInstance()->DelFormAddCallbackByBundle(callback, "all");
            return;
        }
        if (!isBundleNameUndefined && isCallbackUndefined) {
            std::string bundleName = "";
            if (!GetStdString(env, aniHostBundleName, bundleName)) {
                HILOG_ERROR("GetStdString failed");
                EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
                return;
            }
            EtsFormStateObserver::GetInstance()->ClearFormAddCallbackByBundle(bundleName);
            return;
        }
        if (!isBundleNameUndefined && !isCallbackUndefined) {
            std::string bundleName = "";
            if (!GetStdString(env, aniHostBundleName, bundleName)) {
                HILOG_ERROR("GetStdString failed");
                EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
                return;
            }
            EtsFormStateObserver::GetInstance()->DelFormAddCallbackByBundle(callback, bundleName);
            return;
        }
    }

    static void OnUnregisterFormRemoveObserver(ani_env* env, ani_string aniHostBundleName, ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        bool isBundleNameUndefined = IsUndefined(env, reinterpret_cast<ani_ref>(aniHostBundleName));
        bool isCallbackUndefined = IsUndefined(env, reinterpret_cast<ani_ref>(callback));
        if (isBundleNameUndefined && isCallbackUndefined) {
            EtsFormStateObserver::GetInstance()->ClearFormRemoveCallbackByBundle("all");
            return;
        }
        if (isBundleNameUndefined && !isCallbackUndefined) {
            EtsFormStateObserver::GetInstance()->DelFormRemoveCallbackByBundle(callback, "all");
            return;
        }
        if (!isBundleNameUndefined && isCallbackUndefined) {
            std::string bundleName = "";
            if (!GetStdString(env, aniHostBundleName, bundleName)) {
                HILOG_ERROR("GetStdString failed");
                EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
                return;
            }
            EtsFormStateObserver::GetInstance()->ClearFormRemoveCallbackByBundle(bundleName);
            return;
        }
        if (!isBundleNameUndefined && !isCallbackUndefined) {
            std::string bundleName = "";
            if (!GetStdString(env, aniHostBundleName, bundleName)) {
                HILOG_ERROR("GetStdString failed");
                EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
                return;
            }
            EtsFormStateObserver::GetInstance()->DelFormRemoveCallbackByBundle(callback, bundleName);
            return;
        }
    }

    static void OnUnregisterFormIsVisibleObserver(ani_env* env, ani_string aniHostBundleName,
        ani_object callback, bool isVisibility)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        bool isBundleNameUndefined = IsUndefined(env, reinterpret_cast<ani_ref>(aniHostBundleName));
        bool isCallbackUndefined = IsUndefined(env, reinterpret_cast<ani_ref>(callback));
        sptr<EtsFormStateObserver> formObserver = EtsFormStateObserver::GetInstance();
        
        if (isBundleNameUndefined && isCallbackUndefined) {
            EtsFormStateObserver::GetInstance()->ClearFormNotifyVisibleCallbackByBundle("",
                isVisibility, formObserver);
            return;
        }
        if (isBundleNameUndefined && !isCallbackUndefined) {
            EtsFormStateObserver::GetInstance()->DelFormNotifyVisibleCallbackByBundle("",
                isVisibility, callback, formObserver);
            return;
        }
        if (!isBundleNameUndefined && isCallbackUndefined) {
            std::string bundleName = "";
            if (!GetStdString(env, aniHostBundleName, bundleName) || bundleName.empty()) {
                HILOG_ERROR("GetStdString failed");
                EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
                return;
            }
            EtsFormStateObserver::GetInstance()->ClearFormNotifyVisibleCallbackByBundle(bundleName,
                isVisibility, formObserver);
            return;
        }
        if (!isBundleNameUndefined && !isCallbackUndefined) {
            std::string bundleName = "";
            if (!GetStdString(env, aniHostBundleName, bundleName) || bundleName.empty()) {
                HILOG_ERROR("GetStdString failed");
                EtsFormErrorUtil::ThrowParamTypeError(env, "bundleName", "string");
                return;
            }
            EtsFormStateObserver::GetInstance()->DelFormNotifyVisibleCallbackByBundle(bundleName,
                isVisibility, callback, formObserver);
            return;
        }
    }

    static void OnUnregisterClickEventCallback(ani_env* env, const std::string &type,
        ani_string aniHostBundleName, ani_object callback)
    {
        HILOG_DEBUG("call");
        if (env == nullptr) {
            HILOG_ERROR("env is nullptr");
            return;
        }
        bool isBundleNameUndefined = IsUndefined(env, reinterpret_cast<ani_ref>(aniHostBundleName));
        bool isCallbackUndefined = IsUndefined(env, reinterpret_cast<ani_ref>(callback));
        if (isBundleNameUndefined && isCallbackUndefined) {
            EtsFormStateObserver::GetInstance()->ClearFormClickCallbackByBundleName(type, "");
            return;
        }
        if (isBundleNameUndefined && !isCallbackUndefined) {
            EtsFormStateObserver::GetInstance()->ClearFormClickCallbackByBundleName(type, "");
            return;
        }
        if (!isBundleNameUndefined && isCallbackUndefined) {
            std::string bundleName = "";
            if (!GetStdString(env, aniHostBundleName, bundleName)) {
                HILOG_ERROR("GetStdString failed");
                return;
            }
            EtsFormStateObserver::GetInstance()->ClearFormClickCallbackByBundleName(type, bundleName);
            return;
        }
        if (!isBundleNameUndefined && !isCallbackUndefined) {
            std::string bundleName = "";
            if (!GetStdString(env, aniHostBundleName, bundleName)) {
                HILOG_ERROR("GetStdString failed");
                return;
            }
            EtsFormStateObserver::GetInstance()->ClearFormClickCallback(type, bundleName, callback);
            return;
        }
    }
};

void EtsFormObserverInit(ani_env* env)
{
    HILOG_INFO("EtsFormObserverInit Call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_namespace ns;
    status = env->FindNamespace(ETS_FORM_OBSERVER_NAME, &ns);
    if (status != ANI_OK) {
        HILOG_ERROR("FindNamespace application failed status: %{public}d", status);
        return;
    }
    std::array methods = {
        ani_native_function {
            "nativeGetRunningFormInfoById", nullptr,
            reinterpret_cast<void *>(EtsFormObserver::GetRunningFormInfoById)},
        ani_native_function {
            "nativeGetRunningFormInfos", nullptr, reinterpret_cast<void *>(EtsFormObserver::GetRunningFormInfos)},
        ani_native_function {
            "nativeGetRunningFormInfosNotBundlename", nullptr,
            reinterpret_cast<void *>(EtsFormObserver::GetRunningFormInfosNotBundlename)},
        ani_native_function {
            "nativeGetRunningFormInfosByFilter", nullptr,
            reinterpret_cast<void *>(EtsFormObserver::GetRunningFormInfosByFilter)},
        ani_native_function {
            "nativeOn", nullptr, reinterpret_cast<void *>(EtsFormObserver::RegisterFormObserver)},
        ani_native_function {
            "nativeOnArray", nullptr, reinterpret_cast<void *>(EtsFormObserver::RegisterFormObserver)},
        ani_native_function {
            "nativeOff", nullptr, reinterpret_cast<void *>(EtsFormObserver::UnregisterFormObserver)},
        ani_native_function {
            "nativeOffArray", nullptr, reinterpret_cast<void *>(EtsFormObserver::UnregisterFormObserver)},
        ani_native_function {
            "checkFormIDParam", nullptr, reinterpret_cast<void *>(EtsFormObserver::CheckFormIDParam)},
        ani_native_function {
            "checkHostBundleNameParam", nullptr, reinterpret_cast<void *>(EtsFormObserver::CheckHostBundleNameParam)},
        ani_native_function {
            "checkformProviderFilterParam", nullptr,
            reinterpret_cast<void *>(EtsFormObserver::CheckformProviderFilterParam)},
    };
    status = env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size());
    if (status != ANI_OK) {
        HILOG_ERROR("Namespace_BindNativeFunctions failed status: %{public}d", status);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    HILOG_INFO("in EtsFormObserver.ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        HILOG_ERROR("null vm or result");
        return ANI_INVALID_ARGS;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        HILOG_ERROR("GetEnv failed, status: %{public}d", status);
        return ANI_NOT_FOUND;
    }
    EtsFormObserverInit(env);
    *result = ANI_VERSION_1;
    HILOG_INFO("EtsFormObserver.ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS