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

#include "ets_live_form_extension_context.h"
#include "ets_ui_extension_context.h"
#include "ets_runtime.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_form_error_util.h"
#include "element_name.h"
#include "ets_context_utils.h"
#include "ets_extension_context.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_errors.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
    const char *LIVE_FORM_EXTENSION_CONTEXT = "Lapplication/LiveFormExtensionContext/LiveFormExtensionContext;";
    const char *UI_EXTENSION_CONTEXT_CLEANER_CLASS_NAME = "Lapplication/UIExtensionContext/Cleaner;";
}

using namespace OHOS::AppExecFwk;
EtsLiveFormExtensionContext* EtsLiveFormExtensionContext::GetEtsLiveFormExtensionContext(ani_env *env, ani_object obj)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }

    EtsLiveFormExtensionContext *etsContext = nullptr;
    ani_status status = ANI_ERROR;
    ani_long etsContextLong = 0;
    if ((status = env->Object_GetFieldByName_Long(obj, "nativeEtsContext", &etsContextLong)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    etsContext = reinterpret_cast<EtsLiveFormExtensionContext *>(etsContextLong);
    if (etsContext == nullptr) {
        HILOG_ERROR("etsContext null");
        return nullptr;
    }
    return etsContext;
}

ani_object EtsLiveFormExtensionContext::CreateEtsLiveFormExtensionContext(
    ani_env *env, std::shared_ptr<LiveFormExtensionContext> context)
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
    if ((status = env->FindClass(LIVE_FORM_EXTENSION_CONTEXT, &cls)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "J:V", &method)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    std::unique_ptr<EtsLiveFormExtensionContext> etsContext = std::make_unique<EtsLiveFormExtensionContext>(context);
    if ((status = env->Object_New(cls, method, &contextObj, reinterpret_cast<ani_long>(etsContext.release()))) !=
        ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }

    std::array functions = {
        ani_native_function { "nativeStartAbilityByLiveForm", nullptr,
            reinterpret_cast<void *>(EtsLiveFormExtensionContext::StartAbilityByLiveForm) },
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
    if (!EtsLiveFormExtensionContext::BindNativePtrCleaner(env)) {
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

bool EtsLiveFormExtensionContext::BindNativePtrCleaner(ani_env *env)
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
        ani_native_function { "clean", nullptr, reinterpret_cast<void *>(EtsLiveFormExtensionContext::Clean) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, methods.data(), methods.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    return true;
}

void EtsLiveFormExtensionContext::Clean(ani_env *env, ani_object object)
{
    if (env == nullptr) {
        HILOG_ERROR("nullptr env");
        return;
    }
    ani_long ptr = 0;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeEtsContext", &ptr)) {
        return;
    }

    if (ptr != 0) {
        delete reinterpret_cast<EtsLiveFormExtensionContext*>(ptr);
        ptr = 0;
    }
}

void EtsLiveFormExtensionContext::StartAbilityByLiveForm(ani_env *env, ani_object aniObj,
    ani_object aniWant, ani_string aniFormId, ani_object callback)
{
    HILOG_INFO("called");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    auto etsContext = GetEtsLiveFormExtensionContext(env, aniObj);
    if (etsContext == nullptr) {
        HILOG_ERROR("null etsContext");
        return;
    }
    etsContext->OnStartAbilityByLiveForm(env, aniWant, aniFormId, callback);
    return;
}

void EtsLiveFormExtensionContext::OnStartAbilityByLiveForm(ani_env *env, ani_object aniWant,
    ani_string aniFormId, ani_object callback)
{
    HILOG_INFO("called");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    if (context_.lock() == nullptr) {
        HILOG_ERROR("Context is nullptr");
        EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR));
        return;
    }
    AAFwk::Want want;
    AppExecFwk::UnwrapWant(env, aniWant, want);

    std::string formId;
    if (!AppExecFwk::GetStdString(env, aniFormId, formId)) {
        HILOG_ERROR("parse param failed");
        EtsErrorUtil::ThrowError(env,
            static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR));
        return;
    }

    auto contextPtr = context_.lock();
    if (!contextPtr) {
        HILOG_ERROR("Context is nullptr");
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)),
            nullptr);
        return;
    }
    ErrCode errCode = contextPtr->StartAbilityByFms(want, formId);
    if (errCode == ERR_OK) {
        AsyncCallback(env, callback, EtsFormErrorUtil::CreateError(env, errCode), nullptr);
    }
    if (errCode == ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED || errCode == ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME) {
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED), nullptr);
    } else {
        AsyncCallback(env, callback,
            EtsFormErrorUtil::CreateError(env, ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR), nullptr);
    }
    return;
}
} // namespace AbilityRuntime
} // namespace OHOS