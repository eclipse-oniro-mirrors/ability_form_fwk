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

#include "ets_form_host.h"

#include <iostream>
#include <vector>
#include <cinttypes>
#include <memory>
#include <regex>
#include <utility>
#include "ani_helpers.h"
#include "ani_task.h"
#include "form_callback_interface.h"
#include "event_handler.h"
#include "form_host_client.h"
#include "form_host_delegate_stub.h"
#include "form_info.h"
#include "form_info_filter.h"
#include "form_instance.h"
#include "form_instances_filter.h"
#include "form_callback_interface.h"
#include "form_errors.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::Constants;
namespace {
constexpr ani_size REFERENCES_MAX_NUMBER = 16;
constexpr const char* ETS_FORM_HOST_NAME = "@ohos.app.form.formHost.formHost";
constexpr const char* ETS_OVERFLOWREQUEST_NAME = "@ohos.app.form.formInfo.formInfo.OverflowRequestInner";
constexpr const char* ETS_CHANGESCENEANIMATIONSTATEQUEST_NAME =
    "@ohos.app.form.formInfo.formInfo.ChangeSceneAnimationStateRequestInner";
constexpr const char* ETS_RECT_NAME = "@ohos.app.form.formInfo.formInfo.RectInner";
constexpr const char* ETS_OVERFLOWINFO_NAME = "@ohos.app.form.formInfo.formInfo.OverflowInfoInner";
constexpr const char* CLASSNAME_CALLBACK_WRAPPER = "@ohos.app.form.formHost.CallbackWrapper";
constexpr const char* ETS_FORM_RECT_INFO_CALLBACK = "@ohos.app.form.formHost.formHost.GetFormRectInfoCallbackWrapper";
constexpr const char* ETS_LIVE_FORM_STATUS_CALLBACK =
    "@ohos.app.form.formHost.formHost.GetLiveFormStatusCallbackWrapper";
constexpr const char *CHECK_PROMISE_SIGNATURE = "Y:z";
constexpr const char *CALL_PROMISE_SIGNATURE = "C{std.core.Promise}:";
constexpr const char *FORM_HOST_FORMINFO_FORMID = "formId";
constexpr const char *FORM_HOST_FORMINFO_STATE = "state";
constexpr const char *FORM_HOST_FORMRECT_LIVEFORMINTERFACEPARAM = "liveFormInterfaceParam";
constexpr const char *FORM_HOST_INVOKE = "invoke";
constexpr const char *FORM_HOST_CHECKPROMISE = "checkPromise";
constexpr const char *FORM_HOST_CALLPROMISE = "callPromise";
constexpr const char *FORM_HOST_OVERFLOWREQUEST_ISOVERFLOW = "isOverflow";
constexpr const char *FORM_HOST_OVERFLOWREQUEST_OVERFLOWINFO = "overflowInfo";
constexpr const char* FORM_HOST_RECT_LEFT = "left";
constexpr const char* FORM_HOST_RECT_TOP = "top";
constexpr const char* FORM_HOST_RECT_WIDTH = "width";
constexpr const char* FORM_HOST_RECT_HEIGHT = "height";
constexpr const char* FORM_HOST_OVERFLOWINFO_AREA = "area";
constexpr const char* FORM_HOST_OVERFLOWINFO_DURATION = "duration";
constexpr const char* FORM_HOST_OVERFLOWINFO_USEDEFAULTANIMATION = "useDefaultAnimation";
constexpr const char* FORM_HOST_UPDATEFORMSIZE =
    "C{std.core.String}C{@ohos.app.form.formInfo.formInfo.FormDimension}C{@ohos.app.form.formInfo.formInfo.Rect}:";

constexpr int32_t CALL_INRTERFACE_TIMEOUT_MILLS = 10;

void CallBackReturn(const Rect &item, LiveFormInterfaceParam* liveFormInterfaceParam, bool ret)
{
    if (liveFormInterfaceParam == nullptr) {
        HILOG_INFO("getFormRect callback param has been released");
        return;
    }
    liveFormInterfaceParam->result = ret;
    liveFormInterfaceParam->formRect = item;
    HILOG_INFO("getFormRect end.");
}
}

class EtsFormHost {
public:
    EtsFormHost() = default;
    ~EtsFormHost() = default;

    static void OnRegisterOverflowListener(ani_env* env, ani_object callback)
    {
        HILOG_INFO("OnRegisterOverflowListener Call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }

        ErrCode result = AppExecFwk::FormMgr::GetInstance().RegisterOverflowProxy(EtsFormRouterProxyMgr::GetInstance());
        if (result != ERR_OK) {
            HILOG_ERROR("RegisterOverflowProxy failed");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, result);
            return;
        }
        ani_vm *aniVM = nullptr;
        if (env->GetVM(&aniVM) != ANI_OK) {
            HILOG_ERROR("get aniVM failed");
            return;
        }
        EtsFormRouterProxyMgr::GetInstance()->RegisterOverflowListener(aniVM, callback);
    }

    static void OffRegisterOverflowListener(ani_env* env, ani_object callback)
    {
        HILOG_INFO("OffRegisterOverflowListener Call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }
        ErrCode result = AppExecFwk::FormMgr::GetInstance().UnregisterOverflowProxy();
        if (result != ERR_OK) {
            HILOG_ERROR("UnregisterOverflowProxy failed");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, result);
            return;
        }
        EtsFormRouterProxyMgr::GetInstance()->UnregisterOverflowListener();
    }

    static void OnRegisterChangeSceneAnimationStateListener(ani_env* env, ani_object callback)
    {
        HILOG_INFO("OnRegisterChangeSceneAnimationStateListener Call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }

        ErrCode result = AppExecFwk::FormMgr::GetInstance().RegisterChangeSceneAnimationStateProxy(
            EtsFormRouterProxyMgr::GetInstance());
        if (result != ERR_OK) {
            HILOG_ERROR("RegisterOverflowProxy failed");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, result);
            return;
        }
        ani_vm *aniVM = nullptr;
        if (env->GetVM(&aniVM) != ANI_OK) {
            HILOG_ERROR("get aniVM failed");
            return;
        }
        EtsFormRouterProxyMgr::GetInstance()->RegisterChangeSceneAnimationStateListener(aniVM, callback);
    }

    static void OffRegisterChangeSceneAnimationStateListener(ani_env* env, ani_object callback)
    {
        HILOG_INFO("OffRegisterChangeSceneAnimationStateListener Call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }
        ErrCode result = AppExecFwk::FormMgr::GetInstance().UnregisterChangeSceneAnimationStateProxy();
        if (result != ERR_OK) {
            HILOG_ERROR("UnregisterOverflowProxy failed");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, result);
            return;
        }
        EtsFormRouterProxyMgr::GetInstance()->UnregisterChangeSceneAnimationStateListener();
    }

    static void OnRegisterGetFormRectListener(ani_env* env, ani_object callback)
    {
        HILOG_INFO("OnRegisterGetFormRectListener Call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }

        ErrCode result = AppExecFwk::FormMgr::GetInstance().RegisterGetFormRectProxy(
            EtsFormRouterProxyMgr::GetInstance());
        if (result != ERR_OK) {
            HILOG_ERROR("RegisterGetFormRectListener failed");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, result);
            return;
        }
        ani_vm *aniVM = nullptr;
        if (env->GetVM(&aniVM) != ANI_OK) {
            HILOG_ERROR("get aniVM failed");
            return;
        }
        EtsFormRouterProxyMgr::GetInstance()->RegisterGetFormRectListener(aniVM, callback);
    }

    static void OffRegisterGetFormRectListener(ani_env* env, ani_object callback)
    {
        HILOG_INFO("OffRegisterGetFormRectListener Call");
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }
        ErrCode result = AppExecFwk::FormMgr::GetInstance().UnregisterGetFormRectProxy();
        if (result != ERR_OK) {
            HILOG_ERROR("UnRegisterGetFormRectListener failed");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, result);
            return;
        }
        EtsFormRouterProxyMgr::GetInstance()->UnregisterChangeSceneAnimationStateListener();
    }

    static void OnRegisterGetLiveFormStatusListener(ani_env* env, ani_object callback)
    {
        HILOG_INFO("OnRegisterGetLiveFormStatusListener Call");
        std::lock_guard<std::mutex> lock(ani_vm_Mutex_);
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }

        auto result = AppExecFwk::FormMgr::GetInstance().RegisterGetLiveFormStatusProxy(
            EtsFormRouterProxyMgr::GetInstance());
        if (result != ERR_OK) {
            HILOG_ERROR("RegisterGetLiveFormStatusProxy failed, retcode:%{public}d", result);
            return;
        }
        ani_vm *aniVM = nullptr;
        if (env->GetVM(&aniVM) != ANI_OK) {
            HILOG_ERROR("get aniVM failed");
            return;
        }
        EtsFormRouterProxyMgr::GetInstance()->RegisterGetLiveFormStatusListener(aniVM, callback);
    }

    static void OffRegisterGetLiveFormStatusListener(ani_env* env, ani_object callback)
    {
        HILOG_INFO("OffRegisterGetLiveFormStatusListener Call");
        std::lock_guard<std::mutex> lock(ani_vm_Mutex_);
        if (!CheckCallerIsSystemApp()) {
            HILOG_ERROR("The app not system-app,can't use system-api");
            EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_NOT_SYSTEM_APP);
            return;
        }
        auto result = AppExecFwk::FormMgr::GetInstance().UnregisterGetLiveFormStatusProxy();
        if (result != ERR_OK) {
            HILOG_ERROR("UnregisterGetLiveFormStatusProxy failed, retcode:%{public}d", result);
            return;
        }
        EtsFormRouterProxyMgr::GetInstance()->UnregisterGetLiveFormStatusListener();
    }
private:
    static bool CheckCallerIsSystemApp()
    {
        auto selfToken = IPCSkeleton::GetSelfTokenID();
        return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
    }
};

void EtsFormHostInit(ani_env* env)
{
    HILOG_ERROR("EtsFormHostInit Call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_namespace ns;
    status = env->FindNamespace(ETS_FORM_HOST_NAME, &ns);
    if (status != ANI_OK) {
        HILOG_ERROR("FindNamespace application failed status: %{public}d", status);
        return;
    }
    std::array methods = {
        ani_native_function {
            "nativeOnFormOverflow", nullptr, reinterpret_cast<void *>(EtsFormHost::OnRegisterOverflowListener)
        },
        ani_native_function {
            "nativeOffFormOverflow", nullptr, reinterpret_cast<void *>(EtsFormHost::OffRegisterOverflowListener)
        },
        ani_native_function {
            "nativeOnChangeSceneAnimationState", nullptr,
            reinterpret_cast<void *>(EtsFormHost::OnRegisterChangeSceneAnimationStateListener)
        },
        ani_native_function {
            "nativeOffChangeSceneAnimationState", nullptr,
            reinterpret_cast<void *>(EtsFormHost::OffRegisterChangeSceneAnimationStateListener)
        },
        ani_native_function {
            "nativeOnGetFormRect", nullptr,
            reinterpret_cast<void *>(EtsFormHost::OnRegisterGetFormRectListener)
        },
        ani_native_function {
            "nativeOffGetFormRect", nullptr,
            reinterpret_cast<void *>(EtsFormHost::OffRegisterGetFormRectListener)
        },
        ani_native_function {
            "nativeOnGetLiveFormStatus", nullptr,
            reinterpret_cast<void *>(EtsFormHost::OnRegisterGetLiveFormStatusListener)
        },
        ani_native_function {
            "nativeOffGetLiveFormStatus", nullptr,
            reinterpret_cast<void *>(EtsFormHost::OffRegisterGetLiveFormStatusListener)
        },
    };
    status = env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size());
    if (status != ANI_OK) {
        HILOG_ERROR("Namespace_BindNativeFunctions failed status: %{public}d", status);
    }
}

sptr<EtsFormRouterProxyMgr> EtsFormRouterProxyMgr::GetInstance()
{
    static std::once_flag initFlag;
    static sptr<EtsFormRouterProxyMgr> instance;
    std::call_once(initFlag, []() {
        instance = sptr<EtsFormRouterProxyMgr>(new (std::nothrow) EtsFormRouterProxyMgr());
        if (instance == nullptr) {
            HILOG_ERROR("create EtsFormRouterProxyMgr failed");
        }
    });
    return instance;
}

ani_env* EtsFormRouterProxyMgr::GetAniEnv()
{
    if (ani_vm_ == nullptr) {
        HILOG_ERROR("ani_vm_ is null");
        return nullptr;
    }
    ani_env* env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = ani_vm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        HILOG_ERROR("GetEnv failed status: %{public}d", status);
        return nullptr;
    }
    return env;
}

void EtsFormRouterProxyMgr::AddFormRouterProxyCallback(ani_env* env, ani_object callback,
    const std::vector<int64_t> &formIds)
{
    HILOG_INFO("call");
#ifndef WATCH_API_DISABLE
    ani_vm *vm;
    auto getVmStatus = env->GetVM(&vm);
    if (getVmStatus != ANI_OK) {
        HILOG_ERROR("Failed to get VM: %{public}d", getVmStatus);
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }

    ani_ref setRouterProxyCallback = nullptr;
    auto globalrefStatus = env->GlobalReference_Create(callback, &setRouterProxyCallback);
    if (globalrefStatus != ANI_OK) {
        HILOG_ERROR("Failed to create global reference: %{public}d", globalrefStatus);
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }

    std::lock_guard<std::mutex> lock(FormRouterProxyCallbackMutex_);
    auto callbackClient = std::make_shared<FormRouterProxyCallbackClient>(vm, setRouterProxyCallback);
    for (const auto &formId : formIds) {
        auto iter = formRouterProxyCallbackMap_.find(formId);
        if (iter != formRouterProxyCallbackMap_.end()) {
            iter->second = callbackClient;
            continue;
        }
        formRouterProxyCallbackMap_.emplace(formId, callbackClient);
    }
    HILOG_INFO("End");
#endif
}

void EtsFormRouterProxyMgr::RemoveFormRouterProxyCallback(const std::vector<int64_t> &formIds)
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(FormRouterProxyCallbackMutex_);
    for (const auto &formId : formIds) {
        auto iter = formRouterProxyCallbackMap_.find(formId);
        if (iter != formRouterProxyCallbackMap_.end()) {
            formRouterProxyCallbackMap_.erase(formId);
        }
    }
}

ErrCode EtsFormRouterProxyMgr::RouterEvent(int64_t formId, const OHOS::AAFwk::Want &want)
{
    HILOG_INFO("Call");
    std::lock_guard<std::mutex> lock(FormRouterProxyCallbackMutex_);
    auto callbackClient = formRouterProxyCallbackMap_.find(formId);
    if (callbackClient != formRouterProxyCallbackMap_.end()) {
        if (callbackClient->second != nullptr) {
            callbackClient->second->ProcessFormRouterProxy(want);
        }
    }
    return ERR_OK;
}

ErrCode EtsFormRouterProxyMgr::ChangeSceneAnimationState(int64_t formId, int32_t state)
{
    HILOG_INFO("ChangeSceneAnimationState Call");
    std::shared_ptr<LiveFormInterfaceParam> dataParam = std::make_shared<LiveFormInterfaceParam>();
    dataParam->formId = std::to_string(formId);
    dataParam->state = state;
    std::shared_ptr<AppExecFwk::EventHandler> mainHandler =
        std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    std::function<void()> executeFunc = [client = sptr<EtsFormRouterProxyMgr>(this), dataParam]() {
        EtsFormRouterProxyMgr::GetInstance()->ChangeSceneAnimationStateInner(dataParam);
    };
    mainHandler->PostSyncTask(executeFunc, "EtsFormRouterProxyMgr::ChangeSceneAnimationState");
    HILOG_INFO("call ChangeSceneAnimationState end, result:%{public}d", dataParam->result);
    bool result = dataParam->result;
    return result ? ERR_OK : ERR_GET_INFO_FAILED;
}

void EtsFormRouterProxyMgr::ChangeSceneAnimationStateInner(std::shared_ptr<LiveFormInterfaceParam> dataParam)
{
    HILOG_INFO("ChangeSceneAnimationStateInner Call");
    ani_env* env = GetAniEnv();
    if (env == nullptr || dataParam == nullptr) {
        HILOG_ERROR("null env or dataParam");
        return;
    }
    ani_size nr_refs = REFERENCES_MAX_NUMBER;
    env->CreateLocalScope(nr_refs);
    ani_object object = CreateAniObject(env, ETS_CHANGESCENEANIMATIONSTATEQUEST_NAME);
    SetPropertyStringByName(env, object, FORM_HOST_FORMINFO_FORMID, dataParam->formId);
    SetPropertyIntByName(env, object, FORM_HOST_FORMINFO_STATE, dataParam->state);
    ani_object call;
    {
        std::lock_guard<std::mutex> lock(registerChangeSceneAnimationStateProxyMutex_);
        call = reinterpret_cast<ani_object>(changeSceneAnimationStateRigisterCallback_);
        if (call == nullptr) {
            HILOG_ERROR("call is null");
            return;
        }
    }
    bool bRet = Callback(env, call, object, CLASSNAME_CALLBACK_WRAPPER);
    if (!bRet) {
        HILOG_ERROR("Callback failed");
        dataParam->result = false;
        return;
    }
    dataParam->result = true;
    env->DestroyLocalScope();
}

ErrCode EtsFormRouterProxyMgr::GetFormRect(int64_t formId, AppExecFwk::Rect &rect)
{
    LiveFormInterfaceParam* dataParam = new (std::nothrow) LiveFormInterfaceParam {
        .formId = std::to_string(formId)
    };
    if (dataParam == nullptr) {
        HILOG_ERROR("Failed to new dataParam, formId:%{public}" PRId64 ".", formId);
        return ERR_GET_INFO_FAILED;
    }
    std::shared_ptr<AppExecFwk::EventHandler> mainHandler =
        std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    std::function<void()> executeFunc = [client = sptr<EtsFormRouterProxyMgr>(this), dataParam]() {
        EtsFormRouterProxyMgr::GetInstance()->GetFormRectInner(dataParam);
    };
    mainHandler->PostSyncTask(executeFunc, "EtsFormRouterProxyMgr::GetFormRect");
    HILOG_INFO("call GetFormRect end, result:%{public}d", dataParam->result);
    bool result = dataParam->result;
    rect = std::move(dataParam->formRect);
    delete dataParam;
    return result ? ERR_OK : ERR_GET_INFO_FAILED;
}

bool EtsFormRouterProxyMgr::bindNativeMethod(ani_env* env, ani_class cls, LiveFormInterfaceParam *dataParam)
{
    ani_status status = ANI_ERROR;
    std::array functions = {
        ani_native_function { "nativePromiseCallback", nullptr,
            reinterpret_cast<void *>(EtsFormRouterProxyMgr::GetFormRectPromiseCallback) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        HILOG_ERROR("BbindNativeMethod failed");
        return false;
    }
    ani_long dataParamLong = (ani_long)dataParam;
    ani_field dataParamField = nullptr;
    if ((status = env->Class_FindField(cls, FORM_HOST_FORMRECT_LIVEFORMINTERFACEPARAM, &dataParamField)) != ANI_OK) {
        HILOG_ERROR("findField failed");
        return false;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(getFormRectCallbackRef_);
    if ((status = env->Object_SetField_Long(callbackObj, dataParamField, dataParamLong)) != ANI_OK) {
        HILOG_ERROR("setField failed");
        return false;
    }
    return true;
}

void EtsFormRouterProxyMgr::GetFormRectInner(LiveFormInterfaceParam *dataParam)
{
    HILOG_INFO("call");
    ani_env* env = GetAniEnv();
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(ETS_FORM_RECT_INFO_CALLBACK, &cls)) != ANI_OK) {
        HILOG_ERROR("findClass failed");
        return;
    }
    if (!bindNativeMethod(env, cls, dataParam)) {
        HILOG_ERROR("bindNativeMethod failed");
        return;
    }
    ani_string aniFormId = nullptr;
    if ((status = env->String_NewUTF8(dataParam->formId.c_str(), dataParam->formId.size(), &aniFormId)) != ANI_OK) {
        HILOG_ERROR("string_NewUTF8 failed");
        return;
    }

    ani_object callbackObj;
    {
        std::lock_guard<std::mutex> lock(registerGetFormRectProxyMutex_);
        callbackObj = reinterpret_cast<ani_object>(getFormRectCallbackRef_);
        if (callbackObj == nullptr) {
            HILOG_ERROR("callbackObj is null");
            return;
        }
    }
    ani_ref callbackRet = nullptr;
    if ((status = env->Object_CallMethodByName_Ref(callbackObj, FORM_HOST_INVOKE, nullptr, &callbackRet,
        reinterpret_cast<ani_object>(aniFormId))) != ANI_OK || callbackRet == nullptr) {
        HILOG_ERROR("callMethod failed");
        return;
    }
    ani_method method = nullptr;
    auto retObj = reinterpret_cast<ani_object>(callbackRet);
        if ((status = env->Class_FindMethod(cls, FORM_HOST_CHECKPROMISE,
            CHECK_PROMISE_SIGNATURE, &method)) != ANI_OK) {
        HILOG_ERROR("findMethod failed");
        return;
    }
    ani_boolean isPromise = ANI_FALSE;
    if ((status = env->Object_CallMethod_Boolean(callbackObj, method, &isPromise, retObj)) != ANI_OK) {
        HILOG_ERROR("callMethod failed");
        return;
    }
    if (!isPromise) {
        HILOG_INFO("result not promise");
        std::unique_ptr<AppExecFwk::Rect> item = std::make_unique<AppExecFwk::Rect>();
        bool ret = ConvertFunctionResult(env, retObj, *item);
        CallBackReturn(*item, dataParam, ret);
        return;
    }
    CallPromise(env, cls, callbackObj, retObj, dataParam);
}

void EtsFormRouterProxyMgr::CallPromise(ani_env* env, ani_class cls, ani_object callbackObj,
    ani_object retObj, LiveFormInterfaceParam *params)
{
    HILOG_INFO("call");
    ani_status status = ANI_ERROR;
    ani_method method {};
    if ((status = env->Class_FindMethod(cls, FORM_HOST_CALLPROMISE, CALL_PROMISE_SIGNATURE, &method)) != ANI_OK) {
        HILOG_INFO("findMethod failed");
        Rect info;
        CallBackReturn(info, params, false);
        return;
    }
    if ((status = env->Object_CallMethod_Void(callbackObj, method, retObj)) != ANI_OK) {
        HILOG_INFO("callMethod failed");
        Rect info;
        CallBackReturn(info, params, false);
        return;
    }
}

bool EtsFormRouterProxyMgr::ConvertFunctionResult(ani_env* env, ani_object retObj, Rect &item)
{
    if (retObj == nullptr) {
        HILOG_ERROR("The retObj is error.");
        return false;
    }

    bool isItemValid = UnwrapFormRect(env, retObj, item);
    if (!isItemValid) {
        HILOG_ERROR("create form rect error");
        return false;
    }
    return true;
}

void EtsFormRouterProxyMgr::GetFormRectPromiseCallback(ani_env *env, ani_object aniObj, ani_object obj)
{
    HILOG_INFO("GetFormRectPromiseCallback Call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    std::unique_ptr<AppExecFwk::Rect> item = std::make_unique<AppExecFwk::Rect>();
    bool ret = ConvertFunctionResult(env, obj, *item);
    ani_long liveFormInterfaceParamLong = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, FORM_HOST_FORMRECT_LIVEFORMINTERFACEPARAM,
        &liveFormInterfaceParamLong)) != ANI_OK) {
        HILOG_ERROR("getField failed");
        return;
    }
    auto dataParam = reinterpret_cast<LiveFormInterfaceParam *>(liveFormInterfaceParamLong);
    CallBackReturn(*item, dataParam, ret);
}


ErrCode EtsFormRouterProxyMgr::GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap)
{
    HILOG_INFO("GetLiveFormStatus Call");
    std::shared_ptr<LiveFormInterfaceParam> dataParam = std::make_shared<LiveFormInterfaceParam>();
    auto task = [dataParam] () {
        EtsFormRouterProxyMgr::GetInstance()->GetLiveFormStatusInner(dataParam.get());
        HILOG_INFO("getLiveFormStatus start notify.");
        std::unique_lock<std::mutex> lock(dataParam->mutex);
        dataParam->isReady = true;
        dataParam->condition.notify_all();
    };
    if (AniTask::AniSendEvent(task) != ANI_OK) {
        HILOG_ERROR("Failed to aniSendEvent");
    }
    std::unique_lock<std::mutex> lock(dataParam->mutex);
    dataParam->condition.wait_for(
        lock, std::chrono::milliseconds(CALL_INRTERFACE_TIMEOUT_MILLS), [&] { return dataParam->isReady; });
    bool result = dataParam->result;
    liveFormStatusMap = std::move(dataParam->liveFormStatusMap);
    return result ? ERR_OK : ERR_GET_INFO_FAILED;
}

void EtsFormRouterProxyMgr::GetLiveFormStatusInner(LiveFormInterfaceParam *dataParam)
{
    HILOG_INFO("call");
    if (dataParam == nullptr) {
        HILOG_ERROR("null dataParam");
        return;
    }
    dataParam->result = false;
    ani_env *env = GetAniEnv();
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(ETS_LIVE_FORM_STATUS_CALLBACK, &cls)) != ANI_OK) {
        HILOG_ERROR("findClass failed");
        return;
    }
    ani_object callbackObj = reinterpret_cast<ani_object>(getLiveFormStatusCallbackRef_);
    ani_ref callResult = nullptr;
    if ((status = env->Object_CallMethodByName_Ref(callbackObj, FORM_HOST_INVOKE, nullptr, &callResult)) != ANI_OK ||
        callResult == nullptr) {
        HILOG_ERROR("callMethod failed");
        return;
    }

    HILOG_INFO("parse result");
    std::unordered_map<std::string, std::string> liveFormStatusMap;
    bool ret = ParseRecordString(env, reinterpret_cast<ani_object>(callResult), liveFormStatusMap);
    dataParam->result = ret;
    dataParam->liveFormStatusMap = liveFormStatusMap;
}

ErrCode EtsFormRouterProxyMgr::RequestOverflow(const int64_t formId, const AppExecFwk::OverflowInfo &overflowInfo,
    bool isOverflow)
{
    HILOG_INFO("RequestOverflow Call");
    LiveFormInterfaceParam* dataParam = new (std::nothrow) LiveFormInterfaceParam {
        .formId = std::to_string(formId),
        .overflowInfo = overflowInfo,
        .isOverflow = isOverflow
    };
    if (dataParam == nullptr) {
        HILOG_ERROR("Failed to new dataParam, formId:%{public}" PRId64 ".", formId);
        return ERR_GET_INFO_FAILED;
    }
    std::shared_ptr<AppExecFwk::EventHandler> mainHandler =
        std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    std::function<void()> executeFunc = [client = sptr<EtsFormRouterProxyMgr>(this), dataParam]() {
        EtsFormRouterProxyMgr::GetInstance()->RequestOverflowInner(dataParam);
    };
    mainHandler->PostSyncTask(executeFunc, "EtsFormRouterProxyMgr::RequestOverflow");
    HILOG_INFO("call RequestOverflow end, result:%{public}d", dataParam->result);
    bool result = dataParam->result;
    delete dataParam;
    return result ? ERR_OK : ERR_GET_INFO_FAILED;
}


void EtsFormRouterProxyMgr::RequestOverflowInner(LiveFormInterfaceParam* dataParam)
{
    HILOG_INFO("RequestOverflowInner Call");
    ani_env* env = GetAniEnv();
    if (env == nullptr) {
        HILOG_ERROR("env is null");
        return;
    }
    ani_size nr_refs = REFERENCES_MAX_NUMBER;
    env->CreateLocalScope(nr_refs);
    ani_object object = CreateAniObject(env, ETS_OVERFLOWREQUEST_NAME);
    SetPropertyStringByName(env, object, FORM_HOST_FORMINFO_FORMID, dataParam->formId);
    SetPropertyBoolByNameValue(env, object, FORM_HOST_OVERFLOWREQUEST_ISOVERFLOW, dataParam->isOverflow);
    SetPropertyByName(env, object, FORM_HOST_OVERFLOWREQUEST_OVERFLOWINFO,
        CreateFormOverflowInfo(env, dataParam->overflowInfo));
    ani_object call;
    {
        std::lock_guard<std::mutex> lock(registerOverflowProxyMutex_);
        call = reinterpret_cast<ani_object>(overflowRegisterCallback_);
        if (call == nullptr) {
            HILOG_ERROR("call is null");
            return;
        }
    }
    bool bRet = Callback(env, call, object, CLASSNAME_CALLBACK_WRAPPER);
    if (!bRet) {
        HILOG_ERROR("Callback failed");
        dataParam->result = false;
        return;
    }
    dataParam->result = true;
    env->DestroyLocalScope();
}

ani_object EtsFormRouterProxyMgr::CreateFormOverflowInfo(ani_env* env, AppExecFwk::OverflowInfo &overflowInfo)
{
    HILOG_INFO("CreateFormOverflowInfo Call");
    if (env == nullptr) {
        HILOG_ERROR("env is null");
        return nullptr;
    }
    ani_size nr_refs = REFERENCES_MAX_NUMBER;
    env->CreateLocalScope(nr_refs);
    ani_object area = CreateAniObject(env, ETS_RECT_NAME);
    SetPropertyDoubleByName(env, area, FORM_HOST_RECT_LEFT, overflowInfo.area.left);
    SetPropertyDoubleByName(env, area, FORM_HOST_RECT_TOP, overflowInfo.area.top);
    SetPropertyDoubleByName(env, area, FORM_HOST_RECT_WIDTH, overflowInfo.area.width);
    SetPropertyDoubleByName(env, area, FORM_HOST_RECT_HEIGHT, overflowInfo.area.height);

    ani_object object = CreateAniObject(env, ETS_OVERFLOWINFO_NAME);
    SetPropertyByName(env, object, FORM_HOST_OVERFLOWINFO_AREA, area);
    SetPropertyIntByName(env, object, FORM_HOST_OVERFLOWINFO_DURATION, overflowInfo.duration);
    SetPropertyBoolByName(env, object, FORM_HOST_OVERFLOWINFO_USEDEFAULTANIMATION, overflowInfo.useDefaultAnimation);
    env->DestroyLocalScope();
    return object;
}

void EtsFormRouterProxyMgr::RegisterOverflowListener(ani_vm* ani_vm, ani_object callback)
{
    std::lock_guard<std::mutex> lock(registerOverflowProxyMutex_);
    HILOG_INFO("RegisterOverflowListener Call");
    if (ani_vm == nullptr) {
        HILOG_ERROR("ani_vm is null");
        return;
    }
    ani_env* env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = ani_vm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        HILOG_ERROR("GetEnv failed status: %{public}d", status);
        return;
    }
    if (callback == nullptr) {
        HILOG_ERROR("Invalid callback reference");
        return;
    }
    if (overflowRegisterCallback_ != nullptr) {
        if ((status = env->GlobalReference_Delete(overflowRegisterCallback_)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            return;
        }
        overflowRegisterCallback_ = nullptr;
    }
    if ((status = env->GlobalReference_Create(callback, &overflowRegisterCallback_)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create status: %{public}d", status);
        return;
    }
    ani_vm_ = ani_vm;
}

void EtsFormRouterProxyMgr::UnregisterOverflowListener()
{
    std::lock_guard<std::mutex> lock(registerOverflowProxyMutex_);
    HILOG_INFO("UnregisterOverflowListener Call");
    ani_vm_ = nullptr;
    ani_env* env = GetAniEnv();
    if (env == nullptr) {
        HILOG_ERROR("env is null");
        return;
    }
    ani_status status = ANI_ERROR;
    if (overflowRegisterCallback_ != nullptr) {
        if ((status = env->GlobalReference_Delete(overflowRegisterCallback_)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            return;
        }
        overflowRegisterCallback_ = nullptr;
    }
}

void EtsFormRouterProxyMgr::RegisterGetFormRectListener(ani_vm* ani_vm, ani_object callback)
{
    std::lock_guard<std::mutex> lock(registerGetFormRectProxyMutex_);
    HILOG_INFO("RegisterGetFormRectListener Call");
    if (ani_vm == nullptr) {
        HILOG_ERROR("ani_vm is null");
        return;
    }
    ani_env* env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = ani_vm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        HILOG_ERROR("GetEnv failed status: %{public}d", status);
        return;
    }
    if (callback == nullptr) {
        HILOG_ERROR("Invalid callback reference");
        return;
    }
    if (getFormRectCallbackRef_ != nullptr) {
        if ((status = env->GlobalReference_Delete(getFormRectCallbackRef_)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            return;
        }
        getFormRectCallbackRef_ = nullptr;
    }
    if ((status = env->GlobalReference_Create(callback, &getFormRectCallbackRef_)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create status: %{public}d", status);
        return;
    }
    ani_vm_ = ani_vm;
}

void EtsFormRouterProxyMgr::UnregisterGetFormRectListener()
{
    std::lock_guard<std::mutex> lock(registerGetFormRectProxyMutex_);
    HILOG_INFO("UnregisterGetFormRectListener Call");
    ani_vm_ = nullptr;
    ani_env* env = GetAniEnv();
    if (env == nullptr) {
        HILOG_ERROR("env is null");
        return;
    }
    ani_status status = ANI_ERROR;
    if (getFormRectCallbackRef_ != nullptr) {
        if ((status = env->GlobalReference_Delete(getFormRectCallbackRef_)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            return;
        }
        getFormRectCallbackRef_ = nullptr;
    }
}

void EtsFormRouterProxyMgr::RegisterChangeSceneAnimationStateListener(ani_vm* ani_vm, ani_object callback)
{
    std::lock_guard<std::mutex> lock(registerChangeSceneAnimationStateProxyMutex_);
    HILOG_INFO("RegisterChangeSceneAnimationStateListener Call");
    if (ani_vm == nullptr) {
        HILOG_ERROR("ani_vm is null");
        return;
    }
    ani_env* env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = ani_vm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        HILOG_ERROR("GetEnv failed status: %{public}d", status);
        return;
    }
    if (callback == nullptr) {
        HILOG_ERROR("Invalid callback reference");
        return;
    }
    if (changeSceneAnimationStateRigisterCallback_ != nullptr) {
        if ((status = env->GlobalReference_Delete(changeSceneAnimationStateRigisterCallback_)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            return;
        }
        changeSceneAnimationStateRigisterCallback_ = nullptr;
    }
    if ((status = env->GlobalReference_Create(callback, &changeSceneAnimationStateRigisterCallback_)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create status: %{public}d", status);
        return;
    }
    ani_vm_ = ani_vm;
}

void EtsFormRouterProxyMgr::UnregisterChangeSceneAnimationStateListener()
{
    std::lock_guard<std::mutex> lock(registerChangeSceneAnimationStateProxyMutex_);
    HILOG_INFO("UnregisterChangeSceneAnimationStateListener Call");
    ani_env* env = GetAniEnv();
    if (env == nullptr) {
        HILOG_ERROR("env is null");
        return;
    }
    ani_status status = ANI_ERROR;
    if (changeSceneAnimationStateRigisterCallback_ != nullptr) {
        if ((status = env->GlobalReference_Delete(changeSceneAnimationStateRigisterCallback_)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            return;
        }
        changeSceneAnimationStateRigisterCallback_ = nullptr;
    }
    ani_vm_ = nullptr;
}

void EtsFormRouterProxyMgr::RegisterGetLiveFormStatusListener(ani_vm* ani_vm, ani_object callback)
{
    HILOG_INFO("RegisterGetLiveFormStatusListener Call");
    if (ani_vm == nullptr) {
        HILOG_ERROR("ani_vm is null");
        return;
    }
    ani_env* env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = ani_vm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        HILOG_ERROR("GetEnv failed status: %{public}d", status);
        return;
    }
    if (callback == nullptr) {
        HILOG_ERROR("Invalid callback reference");
        return;
    }
    if (getLiveFormStatusCallbackRef_ != nullptr) {
        if ((status = env->GlobalReference_Delete(getLiveFormStatusCallbackRef_)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            return;
        }
        getLiveFormStatusCallbackRef_ = nullptr;
    }
    if ((status = env->GlobalReference_Create(callback, &getLiveFormStatusCallbackRef_)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create status: %{public}d", status);
        return;
    }
    SetAniVM(ani_vm);
}

void EtsFormRouterProxyMgr::UnregisterGetLiveFormStatusListener()
{
    HILOG_INFO("UnregisterGetLiveFormStatusListener Call");
    ani_env* env = GetAniEnv();
    if (env == nullptr) {
        HILOG_ERROR("env is null");
        return;
    }
    ani_status status = ANI_ERROR;
    if (getLiveFormStatusCallbackRef_ != nullptr) {
        if ((status = env->GlobalReference_Delete(getLiveFormStatusCallbackRef_)) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Delete status: %{public}d", status);
            return;
        }
        getLiveFormStatusCallbackRef_ = nullptr;
    }
    SetAniVM(nullptr);
}

void EtsFormRouterProxyMgr::SetAniVM(ani_vm* ani_vm)
{
    std::lock_guard<std::mutex> lock(ani_vm_mutex_);
    ani_vm_ = ani_vm;
}

ErrCode EtsFormRouterProxyMgr::TemplateFormDetailInfoChange(
    const std::vector<AppExecFwk::TemplateFormDetailInfo> &templateFormInfo)
{
    return ERR_OK;
}

class EtsFormStateCallbackClient
    : public FormStateCallbackInterface, public std::enable_shared_from_this<EtsFormStateCallbackClient> {
public:
    using AcquireFormStateTask = std::function<void(int32_t, Want)>;
    explicit EtsFormStateCallbackClient(AcquireFormStateTask &&task) : task_(std::move(task))
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~EtsFormStateCallbackClient() = default;

    void ProcessAcquireState(FormState state) override
    {
        if (handler_) {
            handler_->PostSyncTask(
                [client = shared_from_this(), state]() { client->task_(static_cast<int32_t>(state), client->want_); });
        }
    }

    void SetWant(const Want &want)
    {
        want_ = want;
    }

private:
    Want want_;
    AcquireFormStateTask task_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
};


class EtsShareFormCallBackClient : public ShareFormCallBack,
                                public std::enable_shared_from_this<EtsShareFormCallBackClient> {
public:
    using ShareFormTask = std::function<void(int32_t)>;
    explicit EtsShareFormCallBackClient(ShareFormTask &&task) : task_(std::move(task))
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~EtsShareFormCallBackClient() = default;

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

class EtsFormDataCallbackClient : public FormDataCallbackInterface,
                                 public std::enable_shared_from_this<EtsFormDataCallbackClient> {
public:
    using AcquireFormDataTask = std::function<void(AAFwk::WantParams data)>;
    explicit EtsFormDataCallbackClient(AcquireFormDataTask &&task) : task_(std::move(task))
    {
        handler_ = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~EtsFormDataCallbackClient() = default;

    void ProcessAcquireFormData(AAFwk::WantParams data) override
    {
        if (handler_) {
            handler_->PostSyncTask([client = shared_from_this(), data] () {
                client->task_(data);
            });
        }
    }
private:
    AcquireFormDataTask task_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
};

bool CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
}

bool InnerAcquireFormState(ani_env *env, ani_ref callbackRef, int32_t state, Want want)
{
    auto callbackObject = static_cast<ani_object>(callbackRef);
    ani_object formStateInfoObject = CreateFormStateInfo(env, state, want);
    if (formStateInfoObject == nullptr) {
        HILOG_ERROR("Cannot create formState object with params");
        InvokeAsyncWithBusinessError(env, callbackObject,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return false;
    }

    ani_object errorEts = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    auto res = InvokeAsyncCallback(env, callbackObject, errorEts, formStateInfoObject);
    if (!res) {
        HILOG_ERROR("Cannot call callback");
        return false;
    }
    return true;
}

void AcquireFormState([[maybe_unused]] ani_env *env, ani_object wantObject, ani_object aniCallback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, aniCallback);
    ani_ref acquireFormStateCallback = nullptr;
    if (env->GlobalReference_Create(aniCallback, &acquireFormStateCallback) != ANI_OK) {
        InvokeAsyncWithBusinessError(env, aniCallback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    Want want;
    bool result = UnwrapWant(env, wantObject, want);
    if (!result) {
        HILOG_ERROR("Fail want parse");
        InvokeAsyncWithBusinessError(env, aniCallback, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM),
            nullptr);
        return;
    }

    ani_vm *vm;
    auto stat = env->GetVM(&vm);
    if (stat != ANI_OK || vm == nullptr) {
        HILOG_ERROR("Cannot get vm");
        InvokeAsyncWithBusinessError(env, aniCallback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    EtsFormStateCallbackClient::AcquireFormStateTask task(
        [vm, acquireFormStateCallback](int32_t state, Want want) -> void {
            ani_env *env = GetEnvFromVm(vm);
            CheckEnvOrThrow(env);
            if (acquireFormStateCallback == nullptr) {
                HILOG_ERROR("callback is nullptr");
                PrepareExceptionAndThrow(env,
                    static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
                return;
            }

            bool result = InnerAcquireFormState(env, acquireFormStateCallback, state, want);
            if (!result) {
                HILOG_ERROR("Cannot call callback");
                PrepareExceptionAndThrow(env,
                    static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
                return;
            }

            ani_status status = ANI_OK;
            if ((status = env->GlobalReference_Delete(acquireFormStateCallback)) != ANI_OK) {
                HILOG_ERROR("GlobalReference_Delete failed status:%{public}d", status);
                PrepareExceptionAndThrow(env,
                    static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
                return;
            }
        });
    auto callback = std::make_shared<EtsFormStateCallbackClient>(std::move(task));
    FormHostClient::GetInstance()->AddFormState(callback, want);
    FormStateInfo stateInfo;
    auto resultFromFormMgr = FormMgr::GetInstance().AcquireFormState(want, FormHostClient::GetInstance(), stateInfo);
    callback->SetWant(stateInfo.want);
    if (resultFromFormMgr != ERR_OK) {
        HILOG_ERROR("Cannot get state info from system");
        FormHostClient::GetInstance()->RemoveFormState(want);
        InvokeAsyncWithBusinessError(env, aniCallback, static_cast<int32_t>(resultFromFormMgr), nullptr);
        return;
    }

    HILOG_DEBUG("End");
}

void InnerAcquireFormData(ani_vm* vm, ani_ref callBackGlobRef, AAFwk::WantParams data)
{
    HILOG_DEBUG("Call");
    ani_env *env = nullptr;
    env = GetEnvFromVm(vm);
    CheckEnvOrThrow(env);
    if (callBackGlobRef == nullptr) {
        HILOG_ERROR("callback is nullptr");
        PrepareExceptionAndThrow(env,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }

    ani_object etsErrorCode = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (etsErrorCode == nullptr) {
        HILOG_ERROR("error code is nullptr");
    }

    ani_object callbackObj = static_cast<ani_object>(callBackGlobRef);
    ani_fn_object callbackFunc = reinterpret_cast<ani_fn_object>(callbackObj);
    if (callbackFunc == nullptr) {
        HILOG_ERROR("callbackFunc is nullptr");
        PrepareExceptionAndThrow(env,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }

    ani_object recordObj = NewRecordClass(env);
    ani_ref formDataWrapped = OHOS::AppExecFwk::WrapWantParams(env, data);
    ani_object formDataObject = static_cast<ani_object>(formDataWrapped);
    std::string keyFormData = "formData";
    SetRecordKeyValue(env, recordObj, keyFormData, formDataObject);
    InvokeAsyncCallback(env, callbackFunc, etsErrorCode, recordObj);
    ani_status status = ANI_OK;
    if ((status = env->GlobalReference_Delete(callBackGlobRef)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Delete failed status:%{public}d", status);
        PrepareExceptionAndThrow(env,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }
    callBackGlobRef = nullptr;
    HILOG_DEBUG("End");
}

void AcquireFormData([[maybe_unused]] ani_env *env, ani_string formId, ani_object callback)
{
#ifndef WATCH_API_DISABLE
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, callback);
    ani_ref receiveDataForResultCallback_ = nullptr;
    if (env->GlobalReference_Create(callback, &receiveDataForResultCallback_) != ANI_OK) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID), nullptr);
        return;
    }

    int64_t requestCode = SystemTimeMillis();
    ani_vm* vm;
    auto stat = env->GetVM(&vm);
    if (stat != ANI_OK || vm == nullptr) {
        HILOG_ERROR("Cannot get vm");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    EtsFormDataCallbackClient::AcquireFormDataTask task = [vm, receiveDataForResultCallback_](AAFwk::WantParams data) {
        InnerAcquireFormData(vm, receiveDataForResultCallback_, data);
    };

    auto acquireFormCallback = std::make_shared<EtsFormDataCallbackClient>(std::move(task));
    FormHostClient::GetInstance()->AddAcqiureFormDataCallback(acquireFormCallback, requestCode);
    AAFwk::WantParams formData;
    ErrCode ret = FormMgr::GetInstance().AcquireFormData(formIdNum, requestCode, FormHostClient::GetInstance(),
        formData);
    if (ret != ERR_OK) {
        HILOG_ERROR("Fail error code: %{public}d", ret);
        FormHostClient::GetInstance()->RemoveAcquireDataCallback(requestCode);
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    HILOG_DEBUG("End");
#else
    return;
#endif
}

void InnerShareForm(ani_vm* vm, ani_ref callBackGlobRef, int32_t code)
{
    HILOG_DEBUG("Call");
    ani_env *env = nullptr;
    env = GetEnvFromVm(vm);
    CheckEnvOrThrow(env);
    if (callBackGlobRef == nullptr) {
        HILOG_ERROR("callback is nullptr");
        PrepareExceptionAndThrow(env,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }

    ani_object callbackObj = static_cast<ani_object>(callBackGlobRef);
    ani_fn_object callbackFunc = reinterpret_cast<ani_fn_object>(callbackObj);
    if (callbackFunc == nullptr) {
        HILOG_ERROR("callbackFunc is nullptr");
        PrepareExceptionAndThrow(env,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }

    InvokeAsyncWithBusinessError(env, callbackFunc, code, nullptr);
    ani_status status = ANI_OK;
    if ((status = env->GlobalReference_Delete(callBackGlobRef)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Delete failed status:%{public}d", status);
        PrepareExceptionAndThrow(env,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }

    callBackGlobRef = nullptr;
    HILOG_DEBUG("End");
}

void ShareForm([[maybe_unused]] ani_env *env, ani_string formId, ani_string deviceId, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    CheckIfRefValidOrThrow(env, callback);
    ani_ref receiveDataForResultCallback_ = nullptr;
    if (env->GlobalReference_Create(callback, &receiveDataForResultCallback_) != ANI_OK) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    if (IsRefUndefined(env, deviceId)) {
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID), nullptr);
        return;
    }

    std::string stdDeviceId = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(deviceId));
    if (stdDeviceId.empty()) {
        HILOG_ERROR("deviceId ANIUtils_ANIStringToStdString failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    ani_vm* vm;
    auto stat = env->GetVM(&vm);
    if (stat != ANI_OK || vm == nullptr) {
        HILOG_ERROR("Cannot get vm");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    EtsShareFormCallBackClient::ShareFormTask task = [=](int32_t code) {
        InnerShareForm(vm, receiveDataForResultCallback_, code);
    };

    auto shareFormCallback = std::make_shared<EtsShareFormCallBackClient>(std::move(task));
    int64_t requestCode = SystemTimeMillis();
    FormHostClient::GetInstance()->AddShareFormCallback(shareFormCallback, requestCode);
    auto ret = FormMgr::GetInstance().ShareForm(formIdNum, stdDeviceId, FormHostClient::GetInstance(), requestCode);
    if (ret != ERR_OK) {
        HILOG_ERROR("ShareForm failed, error code: %{public}d: ", ret);
        FormHostClient::GetInstance()->RemoveShareFormCallback(requestCode);
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    HILOG_DEBUG("End");
}

void AddForm([[maybe_unused]] ani_env *env, ani_object wantObject, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    Want want;
    bool result = UnwrapWant(env, wantObject, want);
    if (!result) {
        HILOG_ERROR("want parsing error");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    RunningFormInfo runningFormInfo;
    auto ret = FormMgr::GetInstance().CreateForm(want, runningFormInfo);
    if (ret != ERR_OK) {
        HILOG_ERROR("AddForm failed, error code: %{public}d", static_cast<int32_t>(ret));
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    ani_object runningFormInfoObject = CreateANIObject(env, RUNNING_FORM_INFO_INNER_CLASS_NAME);
    if (IsRefUndefined(env, runningFormInfoObject)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    SetRunningFormInfoFields(env, runningFormInfoObject, runningFormInfo);
    if (!runningFormInfoObject) {
        HILOG_ERROR("RunningFormInfo parsing error");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, runningFormInfoObject);
    HILOG_DEBUG("End");
}

void DeleteForm([[maybe_unused]] ani_env *env, ani_string formId, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().DeleteForm(formIdNum, FormHostClient::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("DeleteForm failed, error code: %{public}d", static_cast<int32_t>(ret));
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void DeleteInvalidForms([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    int32_t num = 0;
    auto ret = FormMgr::GetInstance().DeleteInvalidForms(formIds, FormHostClient::GetInstance(), num);
    if (ret != ERR_OK) {
        HILOG_ERROR("DeleteInvalidForm failed error code : %{public}d", static_cast<int32_t>(ret));
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }
    auto result = createInt(env, num);
    if (result == nullptr) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, result);
    HILOG_DEBUG("End");
}

void GetFormsInfoByFilter([[maybe_unused]] ani_env *env, ani_object filterObj, ani_object callback)
{
    HILOG_DEBUG("Call");
    AppExecFwk::FormInfoFilter filter;
    if (!GetStringProperty(env, filterObj, "bundleName", filter.bundleName)) {
        HILOG_ERROR("Cannot get bundle name from filter");
    }

    if (!GetStringProperty(env, filterObj, "moduleName", filter.moduleName)) {
        HILOG_ERROR("Cannot get bundle name from filter");
    }

    ani_array supportDimensionAni;
    if (env->Object_GetPropertyByName_Ref(filterObj, "supportedDimensions",
        reinterpret_cast<ani_ref*>(&supportDimensionAni))) {
        HILOG_ERROR("Cannot get support Dimension Ani");
    }

    ani_boolean isUndefined = true;
    if (env->Reference_IsUndefined(supportDimensionAni, &isUndefined) != ANI_OK) {
        HILOG_ERROR("Reference_IsUndefined failed");
    }

    if (!isUndefined) {
        AniParseIntArray(env, supportDimensionAni, filter.supportDimensions);
        if (VectorHasNegativeValue(filter.supportDimensions)) {
            HILOG_ERROR("Dimensions value should not be negative.");
            InvokeAsyncWithBusinessError(env, callback,
                static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
            return;
        }
    }

    ani_array supportedShapes;
    if (env->Object_GetPropertyByName_Ref(filterObj, "supportedShapes", reinterpret_cast<ani_ref*>(&supportedShapes))) {
        HILOG_ERROR("Cannot get support Dimension Ani");
    }

    isUndefined = true;
    if (env->Reference_IsUndefined(supportedShapes, &isUndefined) != ANI_OK) {
        HILOG_ERROR("Reference_IsUndefined failed, status");
    }

    if (!isUndefined) {
        AniParseIntArray(env, supportedShapes, filter.supportShapes);
        if (VectorHasNegativeValue(filter.supportShapes)) {
            HILOG_ERROR("Shapes value should not be negative.");
            InvokeAsyncWithBusinessError(env, callback,
                static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
            return;
        }
    }

    std::vector<FormInfo> formInfos;
    auto ret = FormMgr::GetInstance().GetFormsInfoByFilter(filter, formInfos);
    if (ret != ERR_OK) {
        HILOG_ERROR("Failed get formInfo with filter");
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    auto result = CreateFormInfoAniArrayFromVec(env, formInfos);
    if (result == nullptr) {
        HILOG_ERROR("Cannot convert formInfos to ani object");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, result);
    HILOG_DEBUG("End");
}

void GetAllFormsInfo([[maybe_unused]] ani_env *env, ani_object callback)
{
    HILOG_DEBUG("Call");
    std::vector<FormInfo> allInfos;
    auto ret = FormMgr::GetInstance().GetAllFormsInfo(allInfos);
    if (ret != ERR_OK) {
        HILOG_ERROR("Error when get allformInfos");
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    auto result = CreateFormInfoAniArrayFromVec(env, allInfos);
    if (result == nullptr) {
        HILOG_ERROR("Cannot convert formInfos to ani object");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, result);
    HILOG_DEBUG("End");
}

void GetFormsInfo([[maybe_unused]] ani_env *env, ani_string bundleNameStr, ani_string moduleNameStr,
    ani_object callback)
{
    HILOG_DEBUG("Call");
    std::string bundleName = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(bundleNameStr));
    std::string moduleName = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(moduleNameStr));
    std::vector<FormInfo> formInfos;
    int retCode;
    if (moduleName.empty()) {
        retCode = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
    } else {
        retCode = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
    }

    if (retCode != ERR_OK) {
        HILOG_ERROR("call error when get allformInfos");
        InvokeAsyncWithBusinessError(env, callback, retCode, nullptr);
        return;
    }

    auto result = CreateFormInfoAniArrayFromVec(env, formInfos);
    if (result == nullptr) {
        HILOG_ERROR("Cannot convert formInfos to ani object");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, result);
    HILOG_DEBUG("End");
}

void IsSystemReady([[maybe_unused]] ani_env *env, ani_object callback)
{
    HILOG_DEBUG("Call");
    if (!CheckCallerIsSystemApp()) {
        HILOG_ERROR("caller is not system-app");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().CheckFMSReady();
    if (ret != ERR_OK) {
        HILOG_ERROR("CheckFMSReady not ready");
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void NotifyFormsEnableUpdate([[maybe_unused]] ani_env *env, ani_object arrayObj,
    ani_boolean isEnabled, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyFormsEnableUpdate(formIds, isEnabled, FormHostClient::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("NotifyFormsEnableUpdate failed, error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void NotifyFormsVisible([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_boolean isVisible, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyFormsVisible(formIds, isVisible, FormHostClient::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("NotifyFormsVisible failed, error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void SetEnableFormUpdate([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_boolean isEnable, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().LifecycleUpdate(formIds, FormHostClient::GetInstance(), isEnable);
    if (ret != ERR_OK) {
        HILOG_ERROR("LifecycleUpdate failed, error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void ReleaseForm([[maybe_unused]] ani_env *env, ani_string formId, ani_boolean isReleaseCache, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().ReleaseForm(formIdNum, FormHostClient::GetInstance(), isReleaseCache);
    if (ret != ERR_OK) {
        HILOG_ERROR("releaseform failed, error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void RequestForm([[maybe_unused]] ani_env *env, ani_string formId, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    Want want;
    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().RequestForm(formIdNum, FormHostClient::GetInstance(), want);
    if (ret != ERR_OK) {
        HILOG_ERROR("requestform failed error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void RequestFormWithParams([[maybe_unused]] ani_env *env, ani_string formId, ani_object wantParamsObject,
    ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    Want want;
    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID), nullptr);
        return;
    }

    AAFwk::WantParams wantParams;
    if (UnwrapWantParams(env, wantParamsObject, wantParams)) {
        want.SetParams(wantParams);
    }

    auto ret = FormMgr::GetInstance().RequestForm(formIdNum, FormHostClient::GetInstance(), want);
    if (ret != ERR_OK) {
        HILOG_ERROR("requestformwithparams failed error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void CastToNormalForm([[maybe_unused]] ani_env *env, ani_string formId, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().CastTempForm(formIdNum, FormHostClient::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("castToNormal form failed error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void NotifyVisibleForms([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, FormHostClient::GetInstance(),
        Constants::FORM_VISIBLE);
    if (ret != ERR_OK) {
        HILOG_ERROR("NotifyVisibleForms form failed error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void NotifyInvisibleForms([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, FormHostClient::GetInstance(),
        Constants::FORM_INVISIBLE);
    if (ret != ERR_OK) {
        HILOG_ERROR("NotifyInvisibleForms form failed error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void NotifyFormsPrivacyProtected([[maybe_unused]] ani_env *env, ani_object arrayObj,
    ani_boolean isProtected, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, FormHostClient::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("NotifyFormsPrivacyProtected failed, error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void UpdateFormLocation(ani_env *env, ani_string formId, ani_object formLocation)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formLocation)) {
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM));
        return;
    }
    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID));
        return;
    }

    ani_int formLocationValue = 0;
    ani_status formLocationValueStatus = GetEnumValueInt(env, formLocation, formLocationValue);
    if (formLocationValueStatus != ANI_OK) {
        HILOG_ERROR("enum value could not received %{public}d", formLocationValueStatus);
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM));
        return;
    }

    auto ret = FormMgr::GetInstance().UpdateFormLocation(formIdNum, static_cast<int32_t>(formLocationValue));
    if (ret != ERR_OK) {
        HILOG_ERROR("UpdateFormLocation failed, error code: %{public}d", static_cast<int32_t>(ret));
        PrepareExceptionAndThrow(env, ret);
        return;
    }

    HILOG_DEBUG("End");
}

void UpdateFormLockedState([[maybe_unused]] ani_env *env, ani_string formId, ani_boolean isLocked, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, formId)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().NotifyFormLocked(formIdNum, isLocked);
    if (ret != ERR_OK) {
        HILOG_ERROR("UpdateFormLockedState failed, error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void SetFormsRecyclable([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().SetFormsRecyclable(formIds);
    if (ret != ERR_OK) {
        HILOG_ERROR("SetFormsRecyclable failed, error code: %{public}d", static_cast<int32_t>(ret));
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void SetPublishFormResult(ani_env *env, ani_string formId, ani_object publishFormResultObj)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, publishFormResultObj)) {
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM));
        return;
    }

    int64_t formIdNum = FormIdAniStrtoInt64(env, formId);
    if (formIdNum == INVALID_FORMID) {
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_FORM_ID));
        return;
    }

    ani_ref messageRef;
    ani_status messageStatus = env->Object_GetPropertyByName_Ref(publishFormResultObj, "message", &messageRef);
    if (messageStatus != ANI_OK || IsRefUndefined(env, static_cast<ani_object>(messageRef))) {
        HILOG_ERROR("message field could not received %{public}d", messageStatus);
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM));
        return;
    }

    std::string messageInfo = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(messageRef));
    ani_ref codeEnumObj;
    ani_status codeEnumObjStatus = env->Object_GetPropertyByName_Ref(publishFormResultObj, "code", &codeEnumObj);
    if (codeEnumObjStatus != ANI_OK || IsRefUndefined(env, static_cast<ani_object>(codeEnumObj))) {
        HILOG_ERROR("code field could not received %{public}d", codeEnumObjStatus);
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM));
        return;
    }

    ani_int errorCodeValue = 0;
    ani_status errorCodeValueStatus = GetEnumValueInt(env, static_cast<ani_object>(codeEnumObj), errorCodeValue);
    if (errorCodeValueStatus != ANI_OK) {
        HILOG_ERROR("enum value could not received %{public}d", errorCodeValueStatus);
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM));
        return;
    }

    AppExecFwk::Constants::PublishFormResult publishFormResult;
    publishFormResult.code = static_cast<AppExecFwk::Constants::PublishFormErrorCode>(errorCodeValue);
    publishFormResult.message = messageInfo;
    auto ret = FormMgr::GetInstance().SetPublishFormResult(formIdNum, publishFormResult);
    if (ret != ERR_OK) {
        HILOG_ERROR("SetPublishFormResult failed, error code: %{public}d", static_cast<int32_t>(ret));
        PrepareExceptionAndThrow(env, ret);
        return;
    }
    HILOG_DEBUG("End");
}

void RecycleForms([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    Want want;
    auto ret = FormMgr::GetInstance().RecycleForms(formIds, want);
    if (ret != ERR_OK) {
        HILOG_ERROR("RecycleForms failed, error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void RecoverForms([[maybe_unused]] ani_env *env, ani_object arrayObj, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    Want want;
    auto ret = FormMgr::GetInstance().RecoverForms(formIds, want);
    if (ret != ERR_OK) {
        HILOG_ERROR("RecoverForms failed, error code: %{public}d", static_cast<int32_t>(ret));
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

class FormUninstallCallback : public std::enable_shared_from_this<FormUninstallCallback> {
public:
    FormUninstallCallback(ani_vm* vm, ani_ref callback) : m_vm(vm), m_callback(callback)
    {
        m_handler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    virtual ~FormUninstallCallback()
    {
        ani_env *env = GetEnvFromVm(m_vm);
        if (env == nullptr) {
            HILOG_ERROR("Env is null");
            return;
        }
        env->Reference_Delete(m_callback);
    }

    bool IsStrictEqual(ani_object callback)
    {
        ani_boolean equals = true;
        ani_env *env = GetEnvFromVm(m_vm);
        if (env == nullptr) {
            HILOG_ERROR("Env is null");
            return equals;
        }

        env->Reference_StrictEquals(callback, m_callback, &equals);
        return equals;
    }

    void ProcessFormUninstall(const int64_t formId)
    {
        HILOG_INFO("Call");
        if (m_handler == nullptr) {
            HILOG_INFO("null handler");
            return;
        }
       
        m_handler->PostSyncTask([thisWeakPtr = weak_from_this(), formId]() {
            auto sharedThis = thisWeakPtr.lock();
            if (sharedThis == nullptr) {
                HILOG_ERROR("null sharedThis");
                return;
            }

            ani_env *env = GetEnvFromVm(sharedThis->m_vm);
            if (env == nullptr) {
                HILOG_ERROR("Env is null");
                return;
            }

            std::string formIdString = std::to_string(formId);
            ani_string formIdAniStr {};
            ani_status newString_status = env->String_NewUTF8(formIdString.c_str(), formIdString.size(), &formIdAniStr);
            HILOG_INFO("String_NewUTF8 status: %{public}d", newString_status);
           
            auto res = InvokeCallback(env, static_cast<ani_object>(sharedThis->m_callback), formIdAniStr);
            if (!res) {
                HILOG_ERROR("Cannot call callback");
                return;
            }

            HILOG_INFO("PostSyncTask End");
        });
    }

private:
    std::shared_ptr<AppExecFwk::EventHandler> m_handler;
    ani_vm* m_vm;
    ani_ref m_callback;
};


std::list<std::shared_ptr<FormUninstallCallback>> g_formUninstallCallbackList {};
std::mutex g_formUninstallCallbackListMutex;


void OnFormUninstallCallback(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("Call");
    std::lock_guard<std::mutex> lock(g_formUninstallCallbackListMutex);
    for (auto item : g_formUninstallCallbackList) {
        for (int64_t formId : formIds) {
            item->ProcessFormUninstall(formId);
        }
    }
}

void AddFormUninstallCallback(ani_env* env, ani_object callback)
{
    HILOG_DEBUG("Call");
    std::lock_guard<std::mutex> lock(g_formUninstallCallbackListMutex);
    for (auto item : g_formUninstallCallbackList) {
        if (item->IsStrictEqual(callback)) {
            HILOG_INFO("Callback already added.");
            return;
        }
    }

    ani_ref uninstallCallback = nullptr;
    auto globalrefStatus = env->GlobalReference_Create(callback, &uninstallCallback);
    if (globalrefStatus != ANI_OK) {
        HILOG_ERROR("Failed to create global reference: %{public}d", globalrefStatus);
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }

    ani_vm *vm;
    auto getVmStatus = env->GetVM(&vm);
    if (getVmStatus != ANI_OK) {
        HILOG_ERROR("Failed to get VM: %{public}d", getVmStatus);
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE));
        return;
    }

    g_formUninstallCallbackList.push_back(std::make_shared<FormUninstallCallback>(vm, uninstallCallback));
    HILOG_DEBUG("End");
}

void RemoveFormUninstallCallback(ani_env* env, ani_object callback)
{
    HILOG_DEBUG("Call");
    std::lock_guard<std::mutex> lock(g_formUninstallCallbackListMutex);

    for (auto it = g_formUninstallCallbackList.begin(); it != g_formUninstallCallbackList.end(); ++it) {
        if ((*it)->IsStrictEqual(callback)) {
            HILOG_INFO("Removing FormUninstallCallback");
            g_formUninstallCallbackList.erase(it);
            return;
        }
    }

    HILOG_DEBUG("End");
}

void RegisterFormObserver(ani_env* env, ani_object callback)
{
    HILOG_DEBUG("Call");
    if (!CheckCallerIsSystemApp()) {
        HILOG_ERROR("caller is not system-app");
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS));
        return;
    }

    FormHostClient::GetInstance()->RegisterUninstallCallback(OnFormUninstallCallback);
    AddFormUninstallCallback(env, callback);
    HILOG_DEBUG("End");
}

void UnRegisterFormObserver(ani_env* env, ani_object callback)
{
    HILOG_DEBUG("Call");
    if (!CheckCallerIsSystemApp()) {
        HILOG_ERROR("caller is not system-app");
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS));
        return;
    }

    ani_boolean isUndefined = true;
    env->Reference_IsUndefined(callback, &isUndefined);
    if (!isUndefined) {
        HILOG_ERROR("Undefined");
        RemoveFormUninstallCallback(env, callback);
        return;
    }

    std::lock_guard<std::mutex> lock(g_formUninstallCallbackListMutex);
    g_formUninstallCallbackList.clear();
    HILOG_DEBUG("End");
}

void SetRouterProxy(ani_env *env, ani_object arrayObj, ani_object callback, ani_object asyncCallback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, asyncCallback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, asyncCallback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    auto ret = FormMgr::GetInstance().RegisterFormRouterProxy(formIds, EtsFormRouterProxyMgr::GetInstance());
    if (ret != ERR_OK) {
        HILOG_ERROR("RegisterFormRouterProxy failed, error code: %{public}d", static_cast<int32_t>(ret));
        InvokeAsyncWithBusinessError(env, asyncCallback, static_cast<int32_t>(ret), nullptr);
        return;
    }
    EtsFormRouterProxyMgr::GetInstance()->AddFormRouterProxyCallback(env, callback, formIds);

    InvokeAsyncWithBusinessError(env, asyncCallback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void ClearRouterProxy(ani_env *env, ani_object arrayObj, ani_object callback)
{
    HILOG_DEBUG("Call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, arrayObj)) {
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    std::vector<int64_t> formIds;
    if (!ConvertStringArrayToInt64Vector(env, arrayObj, formIds)) {
        HILOG_ERROR("ConvertStringArrayToInt64Vector failed");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    EtsFormRouterProxyMgr::GetInstance()->RemoveFormRouterProxyCallback(formIds);
    auto ret = FormMgr::GetInstance().UnregisterFormRouterProxy(formIds);
    if (ret != ERR_OK) {
        HILOG_ERROR("ClearRouterProxy failed, error code: %{public}d", ret);
        InvokeAsyncWithBusinessError(env, callback, static_cast<int32_t>(ret), nullptr);
        return;
    }

    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
    HILOG_DEBUG("End");
}

void UpdateFormSize(ani_env *env, ani_string aniFormId, ani_object aniNewDimension, ani_object aniNewRect)
{
    HILOG_DEBUG("call");
    CheckEnvOrThrow(env);
    if (IsRefUndefined(env, aniNewDimension) || IsRefUndefined(env, aniNewRect)) {
        PrepareExceptionAndThrow(env, static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM));
        return;
    }

    int64_t formId = FormIdAniStrtoInt64(env, aniFormId);
    if (formId == INVALID_FORMID) {
        HILOG_ERROR("Convert formId failed");
        EtsErrorUtil::ThrowError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST));
        return;
    }

    int32_t newDimension = 0;
    ani_status status = GetEnumValueInt(env, aniNewDimension, newDimension);
    if (status == ANI_OK) {
        if (newDimension < static_cast<int32_t>(Constants::Dimension::DIMENSION_MIN) ||
            newDimension > static_cast<int32_t>(Constants::Dimension::DIMENSION_MAX)) {
            HILOG_ERROR("newDimension not Dimension enum");
            EtsErrorUtil::ThrowError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FORM_DIMENSION_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FORM_DIMENSION_ERROR));
            return;
        }
    } else {
        HILOG_ERROR("newDimension not number, status:%{public}d", status);
        EtsErrorUtil::ThrowError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FORM_DIMENSION_ERROR),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FORM_DIMENSION_ERROR));
        return;
    }

    std::unique_ptr<AppExecFwk::Rect> newRect = std::make_unique<AppExecFwk::Rect>();
    if (!UnwrapFormRect(env, aniNewRect, *newRect)) {
        HILOG_ERROR("convert newRect failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "The newRect is invalid");
        return;
    }

    auto ret = FormMgr::GetInstance().UpdateFormSize(formId, newDimension, *newRect);
    if (ret == ERR_OK) {
        return;
    }
    EtsErrorUtil::ThrowError(env, ret, FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ret));
}

std::vector<ani_native_function> GetBindMethods()
{
    std::vector methods = {
        ani_native_function {
            "acquireFormStateInner",
            "C{@ohos.app.ability.Want.Want}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(AcquireFormState)},
        ani_native_function {
            "acquireFormDataInner", "C{std.core.String}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(AcquireFormData)},
        ani_native_function {
            "addFormInner", "C{@ohos.app.ability.Want.Want}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(AddForm)},
        ani_native_function {"deleteFormInner",
            "C{std.core.String}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:", reinterpret_cast<void *>(DeleteForm)},
        ani_native_function {
            "deleteInvalidFormsInner", "C{std.core.Array}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(DeleteInvalidForms)},
        ani_native_function {
            "getAllFormsInfoInner", "C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(GetAllFormsInfo)},
        ani_native_function {
            "getFormsInfoInner",
            "C{std.core.String}C{std.core.String}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(GetFormsInfo)},
        ani_native_function {
            "getFormsInfoByFilterInner",
            "C{@ohos.app.form.formInfo.formInfo.FormInfoFilter}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(GetFormsInfoByFilter)},
        ani_native_function {"isSystemReadyInner",
            "C{@ohos.app.form.formHost.AsyncCallbackWrapper}:", reinterpret_cast<void *>(IsSystemReady)},
        ani_native_function {"releaseFormInner",
            "C{std.core.String}zC{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(ReleaseForm)},
        ani_native_function {"requestFormInner",
            "C{std.core.String}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(RequestForm)},
        ani_native_function {"requestFormWithParamsInner",
            "C{std.core.String}C{std.core.Record}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(RequestFormWithParams)},
        ani_native_function {"castToNormalFormInner",
            "C{std.core.String}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(CastToNormalForm)},
        ani_native_function {"notifyVisibleFormsInner",
            "C{std.core.Array}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(NotifyVisibleForms)},
        ani_native_function {"notifyInvisibleFormsInner",
            "C{std.core.Array}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(NotifyInvisibleForms)},
        ani_native_function {"setFormUpdateInner",
            "C{std.core.Array}zC{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(SetEnableFormUpdate)},
        ani_native_function{"setPublishFormResult",
            "C{std.core.String}C{@ohos.app.form.formInfo.formInfo.PublishFormResult}:",
            reinterpret_cast<void *>(SetPublishFormResult)},
        ani_native_function {
            "shareFormInner", "C{std.core.String}C{std.core.String}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(ShareForm)},
        ani_native_function {
            "updateFormLocation", "C{std.core.String}C{@ohos.app.form.formInfo.formInfo.FormLocation}:",
            reinterpret_cast<void *>(UpdateFormLocation)},
        ani_native_function {
            "updateFormLockedStateInner", "C{std.core.String}zC{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(UpdateFormLockedState)},
        ani_native_function {
            "setFormsRecyclableInner", "C{std.core.Array}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(SetFormsRecyclable)},
        ani_native_function {
            "recycleFormsInner", "C{std.core.Array}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(RecycleForms)},
        ani_native_function {"recoverFormsInner", "C{std.core.Array}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(RecoverForms)},
        ani_native_function {
            "notifyFormsEnableUpdateInner", "C{std.core.Array}zC{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(NotifyFormsEnableUpdate)},
        ani_native_function {
            "notifyFormsVisibleInner", "C{std.core.Array}zC{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(NotifyFormsVisible)},
        ani_native_function {
            "notifyFormsPrivacyProtectedInner", "C{std.core.Array}zC{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(NotifyFormsPrivacyProtected)},
        ani_native_function {
            "registerFormObserverInner", "C{@ohos.app.form.formHost.CallbackWrapper}:",
            reinterpret_cast<void *>(RegisterFormObserver)},
        ani_native_function {
            "unRegisterFormObserverInner", "C{@ohos.app.form.formHost.CallbackWrapper}:",
            reinterpret_cast<void *>(UnRegisterFormObserver)},
        ani_native_function {"setRouterProxyInner",
            "C{std.core.Array}C{@ohos.app.form.formHost.CallbackWrapper}"
            "C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(SetRouterProxy)},
        ani_native_function {
            "clearRouterProxyInner", "C{std.core.Array}C{@ohos.app.form.formHost.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(ClearRouterProxy)},
        ani_native_function {
            "nativeUpdateFormSize",
            FORM_HOST_UPDATEFORMSIZE,
            reinterpret_cast<void *>(UpdateFormSize)},
    };
    return methods;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    HILOG_DEBUG("Call");
    if (vm == nullptr || result == nullptr) {
        HILOG_ERROR("vm or result is nullptr");
        return ANI_ERROR;
    }

    ani_env *env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        HILOG_ERROR("Unsupported ANI_VERSION_1");
        return ANI_OUT_OF_REF;
    }

    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return ANI_ERROR;
    }
    HILOG_INFO("before find namespace");
    const char *spaceName = "@ohos.app.form.formHost.formHost";
    ani_namespace spc;

    ani_status ret = env->FindNamespace(spaceName, &spc);
    if (ret != ANI_OK) {
        HILOG_ERROR("Not found %{public}s, ret = %{public}d", spaceName, ret);
        return ANI_NOT_FOUND;
    }

    std::vector methods = GetBindMethods();
    EtsFormHostInit(env);
    if (env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size()) != ANI_OK) {
        HILOG_ERROR("Cannot bind native methods to %{public}s ", spaceName);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    HILOG_DEBUG("End");
    return ANI_OK;
}
}
}
}