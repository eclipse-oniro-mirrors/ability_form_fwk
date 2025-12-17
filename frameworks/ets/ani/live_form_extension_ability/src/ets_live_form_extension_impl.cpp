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

#include "ets_live_form_extension_impl.h"
#include "ani.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_form_error_util.h"
#include "ets_ui_extension_content_session.h"
#include "ani_common_want.h"
#include "fms_log_wrapper.h"
#include "ets_live_form_extension_context.h"
#include "form_errors.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* LIVE_FORM_EXTENSION_CLASS_NAME =
    "@ohos.app.form.LiveFormExtensionAbility.LiveFormExtensionAbility";
constexpr const char* LIVE_FORM_CLASSNAME_ASYNC_CALLBACK_WRAPPER =
    "@ohos.app.form.LiveFormExtensionAbility.AsyncCallbackWrapper";
}

EtsLiveFormExtensionImpl::EtsLiveFormExtensionImpl(const std::unique_ptr<Runtime> &runtime)
    : EtsUIExtensionBase(runtime)
{}

void EtsLiveFormExtensionImpl::BindContext()
{
    if (etsObj_ == nullptr) {
        HILOG_ERROR("null etsObj_");
        return;
    }

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    if (context_ == nullptr) {
        HILOG_ERROR("null context_");
        return;
    }
    ani_object contextObj = EtsLiveFormExtensionContext::CreateEtsLiveFormExtensionContext(env, context_);
    if (contextObj == nullptr) {
        HILOG_ERROR("null contextObj");
        return;
    }
    ani_field contextField;
    auto status = env->Class_FindField(etsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_GetField context failed");
        return;
    }
    ani_ref contextRef = nullptr;
    if (env->GlobalReference_Create(contextObj, &contextRef) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create contextObj failed");
        env->GlobalReference_Delete(contextRef);
        return;
    }
    if (env->Object_SetField_Ref(etsObj_->aniObj, contextField, contextRef) != ANI_OK) {
        HILOG_ERROR("Object_SetField_Ref contextObj failed");
        return;
    }

    BindMethod(env);
}

void EtsLiveFormExtensionImpl::BindMethod(ani_env *env)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if ((status = env->FindClass(LIVE_FORM_EXTENSION_CLASS_NAME, &cls)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return;
    }
    std::array functions = {
        ani_native_function { "nativeSetWindowBackgroundColor", nullptr,
            reinterpret_cast<ani_int*>(EtsLiveFormExtensionImpl::SetWindowBackgroundColor) },
        };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return;
    }
}

EtsLiveFormExtensionImpl* EtsLiveFormExtensionImpl::GetEtsEtsLiveForm(ani_env *env, ani_object obj)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    EtsLiveFormExtensionImpl *etsLiveForm = nullptr;
    ani_status status = ANI_ERROR;
    ani_long etsContextLong = 0;
    if ((status = env->Object_GetFieldByName_Long(obj, "context", &etsContextLong)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    etsLiveForm = reinterpret_cast<EtsLiveFormExtensionImpl *>(etsContextLong);
    if (etsLiveForm == nullptr) {
        HILOG_ERROR("etsContext null");
        return nullptr;
    }
    return etsLiveForm;
}

void EtsLiveFormExtensionImpl::SetWindowBackgroundColor(ani_env *env, ani_object obj, ani_object callback)
{
    HILOG_INFO("called");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    auto etsContext = GetEtsEtsLiveForm(env, obj);
    if (etsContext == nullptr) {
        HILOG_ERROR("null etsContext");
        return;
    }
    etsContext->OnSetWindowBackgroundColor(env, callback);
}

void EtsLiveFormExtensionImpl::OnSetWindowBackgroundColor(ani_env *env, ani_object callback)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    if (!context_) {
        HILOG_ERROR("null context");
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)), nullptr);
        return;
    }
    bool isSuccess = context_->SetWindowBackgroundColor();
    if (!isSuccess) {
        HILOG_ERROR("SetWindowBackgroundColor failed");
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)), nullptr);
        return;
    }
    AsyncCallback(env, callback, EtsFormErrorUtil::CreateError(env, ERR_OK), nullptr);
}

bool EtsLiveFormExtensionImpl::AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass(LIVE_FORM_CLASSNAME_ASYNC_CALLBACK_WRAPPER, &clsCall);
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