/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "ets_form_edit_extension_impl.h"
#include "fms_log_wrapper.h"
#include "ets_form_edit_extension_context.h"
#include "ets_ui_extension_content_session.h"
#include "ani_common_want.h"
#include "ani_form_error_util.h"
#include "ani_form_common_util.h"
#include "form_errors.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *FORM_EDIT_EXTENSION_CLASS_NAME =
    "@ohos.app.form.FormEditExtensionAbility.FormEditExtensionAbility";
}

EtsFormEditExtensionImpl::EtsFormEditExtensionImpl(const std::unique_ptr<Runtime> &etsRuntime)
    : EtsUIExtensionBase(etsRuntime)
{}

void EtsFormEditExtensionImpl::BindContext()
{
    HILOG_INFO("BindContext");
    if (etsObj_ == nullptr) {
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
    ani_object contextObj = EtsFormEditExtensionContext::CreateEtsFormEditExtensionContext(env, context_);
    if (contextObj == nullptr) {
        HILOG_ERROR("null contextObj");
        return;
    }
    ani_field contextField;
    auto status = env->Class_FindField(etsObj_->aniCls, "formEditContext", &contextField);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_GetField formEditContext failed");
        return;
    }
    ani_ref contextRef = nullptr;
    if (env->GlobalReference_Create(contextObj, &contextRef) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create contextObj failed");
        return;
    }
    if (env->Object_SetField_Ref(etsObj_->aniObj, contextField, contextRef) != ANI_OK) {
        HILOG_ERROR("Object_SetField_Ref contextObj failed");
        env->GlobalReference_Delete(contextRef);
        return;
    }
    shellContextRef_ = std::make_shared<AppExecFwk::ETSNativeReference>();
    shellContextRef_->aniObj = contextObj;
    shellContextRef_->aniRef = contextRef;

    BindMethod(env);

    HILOG_INFO("BindContext end");
}

void EtsFormEditExtensionImpl::BindMethod(ani_env *env)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object object = nullptr;
    if ((status = env->FindClass(FORM_EDIT_EXTENSION_CLASS_NAME, &cls)) != ANI_OK) {
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
        ani_native_function { "nativeSetWindowBackgroundColor", "C{std.core.String}:",
            reinterpret_cast<void *>(EtsFormEditExtensionImpl::SetWindowBackgroundColor) },
        };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return;
    }
}

EtsFormEditExtensionImpl* EtsFormEditExtensionImpl::GetEtsFormEditExtension(ani_env *env, ani_object obj)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    EtsFormEditExtensionImpl *etsFormEdit = nullptr;
    ani_status status = ANI_ERROR;
    ani_long etsContextLong = 0;
    if ((status = env->Object_GetFieldByName_Long(obj, "context", &etsContextLong)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    etsFormEdit = reinterpret_cast<EtsFormEditExtensionImpl *>(etsContextLong);
    if (etsFormEdit == nullptr) {
        HILOG_ERROR("etsContext null");
        return nullptr;
    }
    return etsFormEdit;
}

void EtsFormEditExtensionImpl::SetWindowBackgroundColor(ani_env *env, ani_object obj, ani_string color)
{
    HILOG_INFO("called");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    auto etsContext = GetEtsFormEditExtension(env, obj);
    if (etsContext == nullptr) {
        HILOG_ERROR("null etsContext");
        return;
    }
    std::string colorStr = FormAniUtil::AniStringToStdString(env, color);
    if (colorStr.empty()) {
        HILOG_ERROR("color is empty");
        EtsFormErrorUtil::ThrowParamTypeError(env, "color", "string");
        return;
    }
    etsContext->OnSetWindowBackgroundColor(env, colorStr);
}

void EtsFormEditExtensionImpl::OnSetWindowBackgroundColor(ani_env *env, const std::string &color)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    if (!context_) {
        HILOG_ERROR("null context");
        EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_IPC_ERROR);
        return;
    }
    bool isSuccess = context_->SetWindowBackgroundColor(color);
    if (!isSuccess) {
        HILOG_ERROR("SetWindowBackgroundColor failed");
        EtsFormErrorUtil::ThrowByExternalErrorCode(env, ERR_FORM_EXTERNAL_IPC_ERROR);
        return;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS