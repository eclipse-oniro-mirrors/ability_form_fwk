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
#include "ani_form_common_util.h"
#include "ets_ui_extension_content_session.h"
#include "ani_common_want.h"
#include "fms_log_wrapper.h"
#include "ets_live_form_extension_context.h"
#include "form_errors.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr double MAX_FONT_SCALE = 1.3;
constexpr const char *LIVE_FORM_EXTENSION_CLASS_NAME =
    "@ohos.app.form.LiveFormExtensionAbility.LiveFormExtensionAbility";
constexpr const char *LIVE_FORM_CLASSNAME_ASYNC_CALLBACK_WRAPPER =
    "@ohos.app.form.LiveFormExtensionAbility.AsyncCallbackWrapper";
constexpr const char *SIGNATURE_SET_FONT_SCALE = "d:";
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
    auto status = env->Class_FindField(etsObj_->aniCls, "liveFormContext", &contextField);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_GetField liveFormContext failed");
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
        ani_native_function { "nativeSetFontScale", SIGNATURE_SET_FONT_SCALE,
            reinterpret_cast<void *>(EtsLiveFormExtensionImpl::SetFontScale) },
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

void EtsLiveFormExtensionImpl::SetFontScale(ani_env *env, ani_object aniObj, ani_double fontScale)
{
    HILOG_DEBUG("called");
    auto etsLiveForm = GetEtsEtsLiveForm(env, aniObj);
    if (etsLiveForm == nullptr) {
        HILOG_ERROR("null EtsLiveFormExtensionImpl");
        return;
    }
    etsLiveForm->OnSetFontScale(env, fontScale);
}

void EtsLiveFormExtensionImpl::OnSetFontScale(ani_env *env, ani_double fontScale)
{
    HILOG_DEBUG("called");

    if (std::isnan(fontScale) || std::islessequal(fontScale, 0.0f)) {
        HILOG_ERROR("fontScale %{public}f is nan or less than default scale", fontScale);
        EtsFormErrorUtil::ThrowByExternalErrorCode(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    if (std::isgreaterequal(fontScale, MAX_FONT_SCALE)) {
        HILOG_WARN("fontScale %{public}f greater than max scale", fontScale);
        fontScale = MAX_FONT_SCALE;
    }

    if (!context_) {
        HILOG_ERROR("null context");
        EtsFormErrorUtil::ThrowByExternalErrorCode(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR));
        return;
    }

    context_->SetAbilityFontSize(fontScale);
}

bool EtsLiveFormExtensionImpl::AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    // Use the unified implementation from EtsFormErrorUtil
    return FormAniUtil::AsyncCallback(env, LIVE_FORM_CLASSNAME_ASYNC_CALLBACK_WRAPPER, call, error, result);
}
} // namespace AbilityRuntime
} // namespace OHOS