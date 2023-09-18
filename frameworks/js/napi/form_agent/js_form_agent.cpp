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
#include "tokenid_kit.h"

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

void JsFormAgent::Finalizer(NativeEngine *engine, void *data, void *hint)
{
    HILOG_INFO("JsFormAgent::Finalizer is called");
    std::unique_ptr<JsFormAgent>(static_cast<JsFormAgent *>(data));
}

NativeValue *JsFormAgent::RequestPublishForm(NativeEngine *engine, NativeCallbackInfo *info)
{
    JsFormAgent *me = CheckParamsAndGetThis<JsFormAgent>(engine, info);
    return (me != nullptr) ? me->OnRequestPublishForm(*engine, *info) : nullptr;
}

NativeValue *JsFormAgent::OnRequestPublishForm(NativeEngine &engine, NativeCallbackInfo &info)
{
    HILOG_INFO("OnRequestPublishForm is called");
    auto env = reinterpret_cast<napi_env>(&engine);
    if (env == nullptr || info.argc < ARGS_SIZE_ONE || info.argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("wrong number of arguments.");
        NapiFormUtil::ThrowParamNumError(engine, std::to_string(info.argc), "1, 2 or 3");
        return engine.CreateUndefined();
    }

    auto asyncCallbackInfo = std::make_shared<RequestPublishFormCallbackInfo>();
    decltype(info.argc) convertArgc = 0;
    if (info.argv[PARAM0]->TypeOf() != NATIVE_OBJECT) {
        HILOG_ERROR("formId is not napi_object.");
        NapiFormUtil::ThrowParamTypeError(engine, "want", "Want");
        return engine.CreateUndefined();
    }

    if (!AppExecFwk::UnwrapWant(env, reinterpret_cast<napi_value>(info.argv[PARAM0]), asyncCallbackInfo->want)) {
        HILOG_ERROR("Failed to convert want.");
        NapiFormUtil::ThrowParamError(engine, "Failed to convert want.");
        return engine.CreateUndefined();
    }

    convertArgc++;
    AsyncTask::CompleteCallback complete = [asyncCallbackInfo](NativeEngine &engine, AsyncTask &task, int32_t status) {
        int64_t formId = 0;
        asyncCallbackInfo->want.SetParam(IS_FORM_AGENT, true);
        ErrCode ret = FormMgr::GetInstance().RequestPublishForm(asyncCallbackInfo->want, false,
            asyncCallbackInfo->formProviderData, formId, asyncCallbackInfo->formDataProxies);
        if (ret != ERR_OK) {
            task.Reject(engine, NapiFormUtil::CreateErrorByInternalErrorCode(engine, ret));
            return;
        }

        std::string formIdStr = std::to_string(formId);
        task.ResolveWithNoError(engine, engine.CreateString(formIdStr.c_str(), formIdStr.size()));
    };
    NativeValue *lastParam = (info.argc <= convertArgc) ? nullptr : info.argv[convertArgc];
    NativeValue *result = nullptr;
    AsyncTask::ScheduleWithDefaultQos("JsFormAgent::OnRequestPublishForm",
        engine, CreateAsyncTaskWithLastParam(engine, lastParam, nullptr, std::move(complete), &result));
    return result;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
