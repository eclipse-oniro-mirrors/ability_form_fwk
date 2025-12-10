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

#include "js_form_edit_extension_context.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "form_constants.h"
#include "form_errors.h"
#include "element_name.h"
#include "js_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr int32_t INDEX_ZERO = 0;
constexpr const char *ERR_MSG_PARAMS_ERROR = "Params error";
constexpr const char *ERR_MSG_INTERNAL_ERROR = "Internal error";
constexpr const char *ERR_MSG_CONTEXT_RELEASED = "context has released";
constexpr const char *ERR_MSG_PARSE_WANT_FAILED = "Parse param want failed, want must be Want";
constexpr int32_t INDEX_ONE = 1;
} // namespace
using namespace OHOS::AppExecFwk;

void JsFormEditExtensionContext::Finalizer(napi_env env, void *data, void *hint)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    std::unique_ptr<JsFormEditExtensionContext>(static_cast<JsFormEditExtensionContext *>(data));
}

napi_value JsFormEditExtensionContext::CreateJsFormEditExtensionContext(
    napi_env env, std::shared_ptr<FormEditExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "begin");
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    if (context) {
        abilityInfo = context->GetAbilityInfo();
    }

    napi_value objValue = CreateJsExtensionContext(env, context, abilityInfo);
    std::unique_ptr<JsFormEditExtensionContext> jsContext = std::make_unique<JsFormEditExtensionContext>(context);
    napi_status status = napi_wrap(env, objValue, jsContext.release(), Finalizer, nullptr, nullptr);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to do napi wrap");
    }

    const char *moduleName = "JsFormEditExtensionContext";
    BindNativeFunction(env, objValue, "startSecondPage", moduleName, StartSecondPage);
    BindNativeFunction(env, objValue, "startUIAbility", moduleName, StartUIAbility);

    return objValue;
}

napi_value JsFormEditExtensionContext::StartSecondPage(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "called");
    GET_NAPI_INFO_AND_CALL(env, info, JsFormEditExtensionContext, OnStartSecondPage);
}

napi_value JsFormEditExtensionContext::StartUIAbility(napi_env env, napi_callback_info info)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StartUIAbility called");
    GET_NAPI_INFO_AND_CALL(env, info, JsFormEditExtensionContext, OnStartUIAbility);
}

napi_value JsFormEditExtensionContext::OnStartSecondPage(napi_env env, NapiCallbackInfo &info)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called: param size: %{public}d", static_cast<int32_t>(info.argc));
    if (info.argc != ARGC_TWO) {
        ThrowError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_PARAM_ERROR), ERR_MSG_PARAMS_ERROR);
        return CreateJsUndefined(env);
    }

    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
        ThrowError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR), ERR_MSG_INTERNAL_ERROR);
        return CreateJsUndefined(env);
    }

    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, info.argv[0], want);
    NapiAsyncTask::CompleteCallback complete = [weak = context_, want](napi_env env, NapiAsyncTask &task,
                                                                      int32_t status) {
        TAG_LOGD(AAFwkTag::UI_EXT, "OnStartSecondPage begin");
        auto context = weak.lock();
        if (!context) {
            TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR)));
            return;
        }

        ErrCode errCode = context->StartAbilityByFms(want);
        napi_value abilityResult = AppExecFwk::WrapAbilityResult(env, static_cast<int>(errCode), want);
        if (abilityResult == nullptr) {
            TAG_LOGE(AAFwkTag::UI_EXT, "Wrap abilityResult failed");
            task.Reject(env, CreateJsError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR)));
            return;
        }

        task.Resolve(env, abilityResult);
    };

    napi_value lastParam = (info.argc > INDEX_ONE) ? info.argv[INDEX_ONE] : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("JsFormEditExtensionContext OnStartSecondPage", env,
        CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsFormEditExtensionContext::OnStartUIAbility(napi_env env, NapiCallbackInfo &info)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    if (info.argc < ARGC_ONE) {
        TAG_LOGE(AAFwkTag::UI_EXT, "invalid argc");
        ThrowError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_PARAM_ERROR), ERR_MSG_PARAMS_ERROR);
        return CreateJsUndefined(env);
    }

    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, info.argv[INDEX_ZERO], want)) {
        ThrowError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_PARAM_ERROR), ERR_MSG_PARSE_WANT_FAILED);
        return CreateJsUndefined(env);
    }

    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
        ThrowError(env, static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR), ERR_MSG_CONTEXT_RELEASED);
        return CreateJsUndefined(env);
    }

    NapiAsyncTask::CompleteCallback complete =
        [weak = context_, want](napi_env env, NapiAsyncTask &task, int32_t status) {
            auto context = weak.lock();
            TAG_LOGD(AAFwkTag::UI_EXT, "OnStartUIAbility begin");
            if (!context) {
                TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
                task.Reject(env,
                    CreateJsError(env,
                        static_cast<int32_t>(FormEditErrorCode::ERROR_CODE_INTERNAL_ERROR),
                        ERR_MSG_CONTEXT_RELEASED));
                return;
            }
            auto innerErrCode = context->StartUIAbilityByFms(want);
            if (innerErrCode == ERR_OK) {
                task.Resolve(env, CreateJsUndefined(env));
                return;
            }
            auto externalErrCode = FormErrors::GetInstance().QueryExternalErrorCode(innerErrCode);
            auto errorMsg = FormErrors::GetInstance().QueryExternalErrorMessage(innerErrCode, externalErrCode);
            task.Reject(env, CreateJsError(env, externalErrCode, errorMsg));
        };

    napi_value lastParam = (info.argc > ARGC_ONE) ? info.argv[INDEX_ONE] : nullptr;
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleHighQos("JsFormEditExtensionContext OnStartUIAbility",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}
} // namespace AbilityRuntime
} // namespace OHOS