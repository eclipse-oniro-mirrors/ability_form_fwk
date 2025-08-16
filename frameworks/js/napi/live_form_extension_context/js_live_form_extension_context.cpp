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

#include "js_live_form_extension_context.h"
#include "js_ui_extension_context.h"
#include "js_error_utils.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "element_name.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_errors.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
namespace {
constexpr size_t ARGC_TWO = 2;
} // namespace

void JsLiveFormExtensionContext::Finalizer(napi_env env, void *data, void *hint)
{
    HILOG_DEBUG("called");
    std::unique_ptr<JsLiveFormExtensionContext>(static_cast<JsLiveFormExtensionContext *>(data));
}

napi_value JsLiveFormExtensionContext::CreateJsLiveFormExtensionContext(
    napi_env env, std::shared_ptr<LiveFormExtensionContext> context)
{
    HILOG_DEBUG("begin");
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }

    napi_value objValue = JsUIExtensionContext::CreateJsUIExtensionContext(env, context);
    std::unique_ptr<JsLiveFormExtensionContext> jsContext = std::make_unique<JsLiveFormExtensionContext>(context);
    napi_status status = napi_wrap(env, objValue, jsContext.release(), Finalizer, nullptr, nullptr);
    if (status != napi_ok) {
        HILOG_ERROR("Failed to do napi wrap");
    }

    const char *moduleName = "JsLiveFormExtensionContext";
    BindNativeFunction(env, objValue, "setWindowBackgroundColor", moduleName, SetWindowBackgroundColor);
    BindNativeFunction(env, objValue, "startAbilityByLiveForm", moduleName, StartAbilityByLiveForm);

    return objValue;
}

napi_value JsLiveFormExtensionContext::SetWindowBackgroundColor(napi_env env, napi_callback_info info)
{
    HILOG_DEBUG("called");
    GET_NAPI_INFO_AND_CALL(env, info, JsLiveFormExtensionContext, OnSetWindowBackgroundColor);
}

napi_value JsLiveFormExtensionContext::StartAbilityByLiveForm(napi_env env, napi_callback_info info)
{
    HILOG_DEBUG("called");
    GET_NAPI_INFO_AND_CALL(env, info, JsLiveFormExtensionContext, OnStartAbilityByLiveForm);
}

napi_value JsLiveFormExtensionContext::OnSetWindowBackgroundColor(napi_env env, NapiCallbackInfo &info)
{
    HILOG_DEBUG("called");
    NapiAsyncTask::CompleteCallback complete =
        [weak = context_](napi_env env, NapiAsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnSetWindowBackgroundColor begin");
        auto context = weak.lock();
        if (!context) {
            HILOG_ERROR("null context");
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
            return;
        }

        bool isSuccess = context->SetWindowBackgroundColor();
        if (!isSuccess) {
            HILOG_ERROR("SetWindowBackgroundColor failed");
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
            return;
        }

        task.ResolveWithNoError(env, CreateJsUndefined(env));
    };

    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("JsLiveFormExtensionContext OnSetWindowBackgroundColor", env,
        CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsLiveFormExtensionContext::OnStartAbilityByLiveForm(napi_env env, NapiCallbackInfo &info)
{
    HILOG_DEBUG("called: param size: %{public}d", static_cast<int32_t>(info.argc));
    if (info.argc != ARGC_TWO) {
        HILOG_ERROR("argc is not two");
        ThrowError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR));
        return CreateJsUndefined(env);
    }
 
    auto context = context_.lock();
    if (context == nullptr) {
        HILOG_ERROR("Context is nullptr");
        ThrowError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
            FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR));
        return CreateJsUndefined(env);
    }
 
    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, info.argv[0], want);
    std::string formId;
    if (!AppExecFwk::UnwrapStringFromJS2(env, info.argv[1], formId)) {
        HILOG_ERROR("parse param failed");
        return CreateJsUndefined(env);
    }
    NapiAsyncTask::CompleteCallback complete =
        [weak = context_, want, formId](napi_env env, NapiAsyncTask &task, int32_t status) {
        HILOG_DEBUG("OnStartAbilityByLiveForm begin");
        auto context = weak.lock();
        if (!context) {
            HILOG_ERROR("Context is nullptr");
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
            return;
        }
 
        ErrCode errCode = context->StartAbilityByFms(want, formId);
        if (errCode != ERR_OK) {
            HILOG_ERROR("StartAbilityByFms failed");
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR),
                FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR)));
            return;
        }
 
        task.ResolveWithNoError(env, CreateJsUndefined(env));
    };
 
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("JsLiveFormExtensionContext OnStartAbilityByLiveForm", env,
        CreateAsyncTaskWithLastParam(env, nullptr, nullptr, std::move(complete), &result));
 
    return result;
}
} // namespace AbilityRuntime
} // namespace OHOS