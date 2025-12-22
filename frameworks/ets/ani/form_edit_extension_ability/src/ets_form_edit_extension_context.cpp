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

#include "ani_form_error_util.h"
#include "ani_form_common_util.h"
#include "ets_form_edit_extension_context.h"
#include "fms_log_wrapper.h"
#include "ets_ui_extension_context.h"
#include "ets_runtime.h"
#include "ani_common_ability_result.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "form_constants.h"
#include "element_name.h"
#include "ets_error_utils.h"
#include "ets_context_utils.h"
#include "ets_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char *FORM_EDIT_EXTENSION_CONTEXT = "application.FormEditExtensionContext.FormEditExtensionContext";
const char *UI_EXTENSION_CONTEXT_CLEANER_CLASS_NAME = "application.UIExtensionContext.Cleaner";
constexpr const char* AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER =
    "application.FormEditExtensionContext.AsyncCallbackWrapper";
constexpr const char *ERR_MSG_INTERNAL_ERROR = "Internal error";
} // namespace
using namespace OHOS::AppExecFwk;

EtsFormEditExtensionContext* EtsFormEditExtensionContext::GetEtsFormEditExtensionContext(ani_env *env, ani_object obj)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }

    EtsFormEditExtensionContext *etsContext = nullptr;
    ani_status status = ANI_ERROR;
    ani_long etsContextLong = 0;
    if ((status = env->Object_GetFieldByName_Long(obj, "nativeExtensionContext", &etsContextLong)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    etsContext = reinterpret_cast<EtsFormEditExtensionContext *>(etsContextLong);
    if (etsContext == nullptr) {
        HILOG_ERROR("etsContext null");
        return nullptr;
    }
    return etsContext;
}

ani_object EtsFormEditExtensionContext::CreateEtsFormEditExtensionContext(
    ani_env *env, std::shared_ptr<FormEditExtensionContext> context)
{
    HILOG_DEBUG("called");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }

    if (context == nullptr) {
        HILOG_ERROR("null context");
        return nullptr;
    }

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object contextObj = nullptr;
    if ((status = env->FindClass(FORM_EDIT_EXTENSION_CONTEXT, &cls)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    std::unique_ptr<EtsFormEditExtensionContext> etsContext = std::make_unique<EtsFormEditExtensionContext>(context);
    if ((status = env->Object_New(cls, method, &contextObj, reinterpret_cast<ani_long>(etsContext.release()))) !=
        ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }

    std::array functions = {
        ani_native_function { "nativeStartSecondPage", nullptr,
            reinterpret_cast<void *>(EtsFormEditExtensionContext::StartSecondPage) },
        ani_native_function { "nativeStartUIAbility", nullptr,
            reinterpret_cast<void *>(EtsFormEditExtensionContext::StartUIAbility) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }

    auto workContext = new (std::nothrow)
        std::weak_ptr<AbilityRuntime::UIExtensionContext>(context);
    if (workContext == nullptr) {
        HILOG_ERROR("null workContext");
        return nullptr;
    }
    if (!ContextUtil::SetNativeContextLong(env, contextObj, (ani_long)workContext)) {
        HILOG_ERROR("SetNativeContextLong failed");
        delete workContext;
        return nullptr;
    }
    if (!EtsFormEditExtensionContext::BindNativePtrCleaner(env)) {
        HILOG_ERROR("status: %{public}d", status);
        delete workContext;
        return nullptr;
    }
    OHOS::AbilityRuntime::ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);
    OHOS::AbilityRuntime::CreateEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    ani_ref *contextGlobalRef = new (std::nothrow) ani_ref;
    if (contextGlobalRef == nullptr) {
        HILOG_ERROR("new contextGlobalRef failed");
        delete workContext;
        return nullptr;
    }
    if ((status = env->GlobalReference_Create(contextObj, contextGlobalRef)) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create failed status: %{public}d", status);
        delete contextGlobalRef;
        delete workContext;
        return nullptr;
    }
    context->Bind(contextGlobalRef);
    return contextObj;
}

bool EtsFormEditExtensionContext::BindNativePtrCleaner(ani_env *env)
{
    if (env == nullptr) {
        HILOG_ERROR("nullptr env");
        return false;
    }
    ani_class cleanerCls;
    ani_status status = env->FindClass(UI_EXTENSION_CONTEXT_CLEANER_CLASS_NAME, &cleanerCls);
    if (ANI_OK != status) {
        HILOG_ERROR("Not found Cleaner. status:%{public}d.", status);
        return false;
    }
    std::array methods = {
        ani_native_function { "clean", nullptr, reinterpret_cast<void *>(EtsFormEditExtensionContext::Clean) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, methods.data(), methods.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    return true;
}

void EtsFormEditExtensionContext::Clean(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        HILOG_ERROR("nullptr env");
        return;
    }

    ani_long ptr = 0;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeExtensionContext", &ptr)) {
        return;
    }

    if (ptr != 0) {
        delete reinterpret_cast<EtsFormEditExtensionContext*>(ptr);
        ptr = 0;
    }
}

void EtsFormEditExtensionContext::StartSecondPage(ani_env *env, ani_object aniObj,
    ani_object aniWant, ani_object callback)
{
    HILOG_INFO("called");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    auto etsContext = GetEtsFormEditExtensionContext(env, aniObj);
    if (etsContext == nullptr) {
        HILOG_ERROR("null etsContext");
        return;
    }
    etsContext->OnStartSecondPage(env, aniWant, callback);
    return;
}

void EtsFormEditExtensionContext::OnStartSecondPage(ani_env *env, ani_object aniWant, ani_object callback)
{
    HILOG_INFO("called");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    if (context_.lock() == nullptr) {
        HILOG_ERROR("Context is released");
        EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR), ERR_MSG_INTERNAL_ERROR);
        return ;
    }
    AAFwk::Want want;
    AppExecFwk::UnwrapWant(env, aniWant, want);

    auto contextPtr = context_.lock();
    if (!contextPtr) {
        HILOG_ERROR("Context is released");
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR)),
            nullptr);
        return;
    }
    ErrCode errCode = contextPtr->StartAbilityByFms(want);
    int resultCode = 0;
    ani_object abilityResult = AppExecFwk::WrapAbilityResult(env, resultCode, want);
    if (abilityResult == nullptr) {
        HILOG_ERROR("Wrap abilityResult failed");
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR)),
            nullptr);
        return;
    }
    AsyncCallback(env, callback, EtsFormErrorUtil::CreateError(env, errCode),
        abilityResult);
    return;
}

void EtsFormEditExtensionContext::StartUIAbility(ani_env *env, ani_object aniObj,
    ani_object aniWant, ani_object callback)
{
    HILOG_INFO("called");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    auto etsContext = GetEtsFormEditExtensionContext(env, aniObj);
    if (etsContext == nullptr) {
        HILOG_ERROR("null etsContext");
        return;
    }
    etsContext->OnStartUIAbility(env, aniWant, callback);
}

void EtsFormEditExtensionContext::OnStartUIAbility(ani_env *env, ani_object aniWant, ani_object callback)
{
    HILOG_INFO("called");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    if (context_.lock() == nullptr) {
        HILOG_ERROR("Context is released");
        EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR), ERR_MSG_INTERNAL_ERROR);
        return ;
    }
    AAFwk::Want want;
    AppExecFwk::UnwrapWant(env, aniWant, want);

    auto contextPtr = context_.lock();
    if (!contextPtr) {
        HILOG_ERROR("Context is released");
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR)),
            nullptr);
        return;
    }
    ErrCode errCode = contextPtr->StartUIAbilityByFms(want);
    int resultCode = 0;
    ani_object abilityResult = AppExecFwk::WrapAbilityResult(env, resultCode, want);
    if (abilityResult == nullptr) {
        HILOG_ERROR("Wrap abilityResult failed");
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR)),
            nullptr);
        return;
    }
    AsyncCallback(env, callback, EtsFormErrorUtil::CreateError(env, errCode),
        abilityResult);
    return;
}

bool EtsFormEditExtensionContext::AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass(AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER, &clsCall);
    if (status!= ANI_OK || clsCall == nullptr) {
        HILOG_ERROR("FindClass status: %{public}d, or null clsCall", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "invoke", nullptr, &method)) != ANI_OK || method == nullptr) {
        HILOG_ERROR("Class_FindMethod status: %{public}d, or null method", status);
        return false;
    }
    if (error == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        error = reinterpret_cast<ani_object>(nullRef);
    }
    if (result == nullptr) {
        ani_ref undefinedRef = nullptr;
        env->GetUndefined(&undefinedRef);
        result = reinterpret_cast<ani_object>(undefinedRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        HILOG_ERROR("Object_CallMethod_Void status: %{public}d", status);
        return false;
    }
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS