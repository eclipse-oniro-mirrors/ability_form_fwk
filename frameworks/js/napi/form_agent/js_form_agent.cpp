/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "js_form_agent.h"

#include <cinttypes>
#include <vector>

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_mgr.h"
#include "form_histogram_utils.h"
#include "ipc_skeleton.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_form_util.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
namespace {
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr bool HISTOGRAM_BOOLEAN_SAMPLE = true;
const std::string IS_FORM_AGENT = "isFormAgent";
}

void JsFormAgent::Finalizer(napi_env env, void *data, void *hint)
{
    HILOG_INFO("call");
    std::unique_ptr<JsFormAgent>(static_cast<JsFormAgent *>(data));
}

napi_value JsFormAgent::RequestPublishForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormAgent, OnRequestPublishForm);
}

napi_value JsFormAgent::OnRequestPublishForm(napi_env env, size_t argc, napi_value* argv)
{
    FormHistogramUtils::ReportHistogramBoolean("Form.Agent.requestPublishForm", HISTOGRAM_BOOLEAN_SAMPLE);
    HILOG_INFO("call");
    if (env == nullptr || argc < ARGS_SIZE_ONE || argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("invalid argc");
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
        return CreateJsUndefined(env);
    }

    auto asyncCallbackInfo = std::make_shared<RequestPublishFormCallbackInfo>();
    decltype(argc) convertArgc = 0;
    napi_valuetype paramZeroType = napi_undefined;
    napi_typeof(env, argv[0], &paramZeroType);
    if (paramZeroType != napi_object) {
        HILOG_ERROR("formId not napi_object");
        NapiFormUtil::ThrowParamTypeError(env, "want", "Want");
        return CreateJsUndefined(env);
    }

    if (!AppExecFwk::UnwrapWant(env, argv[PARAM0], asyncCallbackInfo->want)) {
        HILOG_ERROR("fail convert want");
        NapiFormUtil::ThrowParamError(env, "Failed to convert want.");
        return CreateJsUndefined(env);
    }

    convertArgc++;
    auto apiResult = std::make_shared<int32_t>();
    auto formId = std::make_shared<int64_t>();
    NapiAsyncTask::ExecuteCallback execute = [asyncCallbackInfo, cardId = formId, ret = apiResult]() {
        asyncCallbackInfo->want.SetParam(IS_FORM_AGENT, true);
        *ret = FormMgr::GetInstance().RequestPublishForm(asyncCallbackInfo->want, false,
            asyncCallbackInfo->formProviderData, *cardId, asyncCallbackInfo->formDataProxies);
        if (*ret != ERR_OK) {
            HILOG_ERROR("fail RequestPublishForm startAbility");
            return;
        }
        *ret = FormMgr::GetInstance().AcquireAddFormResult(*cardId);
    };

    NapiAsyncTask::CompleteCallback complete =
        [formId, ret = apiResult](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*ret == ERR_OK) {
            HILOG_INFO("Sucess");
            task.ResolveWithNoError(env, CreateJsValue(env, std::to_string(*formId)));
        } else {
            HILOG_ERROR("fail");
            task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
        }
    };
    napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormAgent::OnRequestPublishForm",
        env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
    return result;
}

napi_value JsFormAgent::UpdateFormCrossBundle(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormAgent, OnUpdateFormCrossBundle);
}

napi_value JsFormAgent::OnUpdateFormCrossBundle(napi_env env, size_t argc, napi_value* argv)
{
    FormHistogramUtils::ReportHistogramBoolean("Form.Agent.updateFormCrossBundle", HISTOGRAM_BOOLEAN_SAMPLE);
    HILOG_INFO("call");
    if (env == nullptr || argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("invalid argc");
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "2");
        return CreateJsUndefined(env);
    }

    auto asyncCallbackInfo = std::make_shared<UpdateFormCrossBundleCallbackInfo>();

    // 1. parse formId
    std::string formIdStr;
    if (!ConvertFromJsValue(env, argv[0], formIdStr) || formIdStr.empty()) {
        HILOG_ERROR("formId is invalid");
        NapiFormUtil::ThrowParamError(env, "formId is invalid");
        return CreateJsUndefined(env);
    }
    asyncCallbackInfo->formId = std::atoll(formIdStr.c_str());

    // 2. parse FormBindingData: accept either plain JSON string or { data: string } object
    std::string formDataStr;
    napi_valuetype secondType = napi_undefined;
    napi_typeof(env, argv[1], &secondType);
    if (secondType == napi_string) {
        if (!ConvertFromJsValue(env, argv[1], formDataStr)) {
            NapiFormUtil::ThrowParamError(env, "formBindingData is invalid");
            return CreateJsUndefined(env);
        }
    } else if (secondType == napi_object) {
        napi_value dataValue = nullptr;
        napi_get_named_property(env, argv[1], "data", &dataValue);
        napi_valuetype dataType = napi_undefined;
        if (dataValue != nullptr) {
            napi_typeof(env, dataValue, &dataType);
        }
        if (dataType == napi_string) {
            ConvertFromJsValue(env, dataValue, formDataStr);
        } else if (dataType == napi_object) {
            napi_value globalValue = nullptr;
            napi_get_global(env, &globalValue);
            napi_value jsonValue = nullptr;
            napi_get_named_property(env, globalValue, "JSON", &jsonValue);
            napi_value stringifyValue = nullptr;
            napi_get_named_property(env, jsonValue, "stringify", &stringifyValue);
            napi_value funcArgv[1] = { dataValue };
            napi_value transValue = nullptr;
            napi_call_function(env, jsonValue, stringifyValue, 1, funcArgv, &transValue);
            ConvertFromJsValue(env, transValue, formDataStr);
        } else {
            NapiFormUtil::ThrowParamError(env, "formBindingData.data is invalid");
            return CreateJsUndefined(env);
        }
    } else {
        NapiFormUtil::ThrowParamError(env, "formBindingData type invalid");
        return CreateJsUndefined(env);
    }
    asyncCallbackInfo->formBindingData =
        std::make_shared<OHOS::AppExecFwk::FormProviderData>(formDataStr);

    // 3. async dispatch
    auto apiResult = std::make_shared<int32_t>();
    NapiAsyncTask::ExecuteCallback execute = [asyncCallbackInfo, ret = apiResult]() {
        *ret = FormMgr::GetInstance().UpdateFormCrossBundle(
            asyncCallbackInfo->formId, *asyncCallbackInfo->formBindingData);
    };

    NapiAsyncTask::CompleteCallback complete =
        [ret = apiResult](napi_env env, NapiAsyncTask &task, int32_t /*status*/) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            HILOG_ERROR("null scope");
            return;
        }
        if (*ret == ERR_OK) {
            task.ResolveWithNoError(env, CreateJsUndefined(env));
        } else {
            task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
        }
        napi_close_handle_scope(env, scope);
    };

    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormAgent::OnUpdateFormCrossBundle",
        env, CreateAsyncTask(env, std::move(execute), std::move(complete), &result));
    return result;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
