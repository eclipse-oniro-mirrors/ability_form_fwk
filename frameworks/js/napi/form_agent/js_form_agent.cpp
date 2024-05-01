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
#include "ipc_skeleton.h"
#include "js_form_info_util.h"
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
const std::string IS_FORM_AGENT = "isFormAgent";
}

void JsFormAgent::Finalizer(napi_env env, void *data, void *hint)
{
    HILOG_INFO("JsFormAgent::Finalizer is called");
    std::unique_ptr<JsFormAgent>(static_cast<JsFormAgent *>(data));
}

napi_value JsFormAgent::RequestPublishForm(napi_env env, napi_callback_info info)
{
    GET_CB_INFO_AND_CALL(env, info, JsFormAgent, OnRequestPublishForm);
}

napi_value JsFormAgent::OnRequestPublishForm(napi_env env, size_t argc, napi_value* argv)
{
    HILOG_INFO("OnRequestPublishForm is called");
    if (env == nullptr || argc < ARGS_SIZE_ONE || argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("wrong number of arguments.");
        NapiFormUtil::ThrowParamNumError(env, std::to_string(argc), "1 or 2");
        return CreateJsUndefined(env);
    }

    auto asyncCallbackInfo = std::make_shared<RequestPublishFormCallbackInfo>();
    decltype(argc) convertArgc = 0;
    napi_valuetype paramZeroType = napi_undefined;
    napi_typeof(env, argv[0], &paramZeroType);
    if (paramZeroType != napi_object) {
        HILOG_ERROR("formId is not napi_object.");
        NapiFormUtil::ThrowParamTypeError(env, "want", "Want");
        return CreateJsUndefined(env);
    }

    if (!AppExecFwk::UnwrapWant(env, argv[PARAM0], asyncCallbackInfo->want)) {
        HILOG_ERROR("Failed to convert want.");
        NapiFormUtil::ThrowParamError(env, "Failed to convert want.");
        return CreateJsUndefined(env);
    }

    convertArgc++;
    auto apiResult = std::make_shared<int32_t>();
    auto formId = std::make_shared<int64_t>();
    NapiAsyncTask::ExecuteCallback execute = [asyncCallbackInfo, cardId = formId, ret = apiResult]() {
        *ret = FormMgr::GetInstance().RequestPublishForm(asyncCallbackInfo->want, false,
            asyncCallbackInfo->formProviderData, *cardId, asyncCallbackInfo->formDataProxies);
        if (*ret != ERR_OK) {
            HILOG_ERROR("Failed to RequestPublishForm startAbility.");
            return;
        }
        *ret = FormMgr::GetInstance().AcquireAddFormResult(*cardId);
    };

    NapiAsyncTask::CompleteCallback complete =
        [formId, ret = apiResult](napi_env env, NapiAsyncTask &task, int32_t status) {
        if (*ret == ERR_OK) {
            HILOG_INFO("Sucess to RequestPublishForm.");
            task.ResolveWithNoError(env, CreateJsValue(env, std::to_string(*formId)));
        } else {
            HILOG_ERROR("Failed to RequestPublishForm.");
            task.Reject(env, NapiFormUtil::CreateErrorByInternalErrorCode(env, *ret));
        }
    };
    napi_value lastParam = (argc <= convertArgc) ? nullptr : argv[convertArgc];
    napi_value result = nullptr;
    NapiAsyncTask::ScheduleWithDefaultQos("JsFormAgent::OnRequestPublishForm",
        env, CreateAsyncTaskWithLastParam(env, lastParam, std::move(execute), std::move(complete), &result));
    return result;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
