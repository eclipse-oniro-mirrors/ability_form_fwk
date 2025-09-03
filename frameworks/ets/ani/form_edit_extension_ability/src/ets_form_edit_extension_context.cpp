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
#include "hilog_tag_wrapper.h"
#include "ets_ui_extension_context.h"
#include "ets_runtime.h"
#include "ani_common_ability_result.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "form_constants.h"
#include "element_name.h"
#include "ets_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char *FORM_EDIT_EXTENSION_CONTEXT = "C{application.FormEditExtensionContext.FormEditExtensionContext}";
constexpr const char* AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER =
    "L@application/FormEditExtensionContext/AsyncCallbackWrapper;";
constexpr const char *ERR_MSG_INTERNAL_ERROR = "Internal error";
} // namespace
using namespace OHOS::AppExecFwk;

EtsFormEditExtensionContext* EtsFormEditExtensionContext::GetEtsFormEditExtensionContext(ani_env *env, ani_object obj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return nullptr;
    }
    EtsFormEditExtensionContext *etsContext = nullptr;
    ani_status status = ANI_ERROR;
    ani_long etsContextLong = 0;
    if ((status = env->Object_GetFieldByName_Long(obj, "nativeExtensionContext", &etsContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    etsContext = reinterpret_cast<EtsFormEditExtensionContext *>(etsContextLong);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "etsContext null");
        return nullptr;
    }
    return etsContext;
}

ani_object EtsFormEditExtensionContext::CreateEtsFormEditExtensionContext(
    ani_env *env, std::shared_ptr<FormEditExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "begin");
    ani_object contextObj = AbilityRuntime::CreateEtsUIExtensionContext(env, context);
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((env->FindClass(FORM_EDIT_EXTENSION_CONTEXT, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    std::array functions = {
        ani_native_function { "startSecondPage", nullptr,
            reinterpret_cast<ani_int*>(EtsFormEditExtensionContext::StartSecondPage) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    return contextObj;
}

void EtsFormEditExtensionContext::StartSecondPage(ani_env *env, ani_object obj, ani_object aniWant, ani_object callback)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "called");
    auto etsContext = GetEtsFormEditExtensionContext(env, obj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsContext");
        return;
    }
    etsContext->OnStartSecondPage(env, aniWant, callback);
    return;
}

void EtsFormEditExtensionContext::OnStartSecondPage(ani_env *env, ani_object aniWant, ani_object callback)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "called");
    if (context_.lock() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
        EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR), ERR_MSG_INTERNAL_ERROR);
        return ;
    }
    AAFwk::Want want;
    AppExecFwk::UnwrapWant(env, aniWant, want);

    auto contextPtr = context_.lock();
    if (!contextPtr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR)),
            nullptr);
        return;
    }
    ErrCode errCode = contextPtr->StartAbilityByFms(want);
    int resultCode = 0;
    ani_object abilityResult = AppExecFwk::WrapAbilityResult(env, resultCode, want);
    if (abilityResult == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Wrap abilityResult failed");
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
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return false;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass(AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER, &clsCall);
    if (status!= ANI_OK || clsCall == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "FindClass status: %{public}d, or null clsCall", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "invoke", nullptr, &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindMethod status: %{public}d, or null method", status);
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
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_CallMethod_Void status: %{public}d", status);
        return false;
    }
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS