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

#include <cinttypes>
#include <vector>

#include "ability.h"
#include "ani_common_want.h"
#include "ani_form_common_util.h"
#include "ani_form_error_util.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_mgr.h"
#include "form_provider_data.h"
#include "form_provider_info.h"
#include "form_histogram_utils.h"
#include "ipc_skeleton.h"
#include "nlohmann/json.hpp"
#include "runtime.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using FormMgr = AppExecFwk::FormMgr;
namespace {
const std::string IS_FORM_AGENT = "isFormAgent";
constexpr const char *ETS_FORM_AGENT_NAME = "@ohos.app.form.formAgent.formAgent";
constexpr const char *AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER = "@ohos.app.form.formAgent.AsyncCallbackWrapper";
constexpr bool HISTOGRAM_BOOLEAN_SAMPLE = true;
struct RequestPublishFormCallbackInfo {
    Want want {};
    bool withFormBindingData = false;
    std::unique_ptr<OHOS::AppExecFwk::FormProviderData> formProviderData = nullptr;
    std::vector<AppExecFwk::FormDataProxy> formDataProxies;
};

void RequestPublishForm(ani_env *env, ani_object aniWant, ani_object callback)
{
    FormHistogramUtils::ReportHistogramBoolean("Form.Agent.requestPublishForm", HISTOGRAM_BOOLEAN_SAMPLE);
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }

    // Capture VM + global ref BEFORE doing anything that may block so the host ArkTS
    // callback can be invoked safely on the UI thread afterwards. The callback is an
    // ArkTS closure bound to the main VM; VM ops must not happen on the taskpool worker
    // thread (CLAUDE.md S5).
    ani_vm *vm = nullptr;
    if (env->GetVM(&vm) != ANI_OK || vm == nullptr) {
        HILOG_ERROR("GetVM failed");
        return;
    }
    ani_ref callbackRef = nullptr;
    if (env->GlobalReference_Create(callback, &callbackRef) != ANI_OK) {
        HILOG_ERROR("GlobalReference_Create failed");
        return;
    }

    // UnwrapWant reads the ANI aniWant object; the resulting Want is a value copy that
    // is safe to use on the worker thread for the following IPC.
    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, aniWant, want)) {
        HILOG_ERROR("fail convert want");
        auto mainHandler = std::make_shared<AppExecFwk::EventHandler>(
            AppExecFwk::EventRunner::GetMainEventRunner());
        mainHandler->PostTask([vm, callbackRef, mainHandler]() {
            ani_env *uiEnv = FormAniUtil::GetEnvFromVm(vm);
            if (uiEnv == nullptr || callbackRef == nullptr) {
                HILOG_ERROR("get ui env failed or callback ref is null");
                return;
            }
            ani_size nr = REFERENCES_MAX_NUMBER;
            uiEnv->CreateLocalScope(nr);
            EtsFormErrorUtil::ThrowParamError(uiEnv, "Failed to convert want.");
            FormAniUtil::AsyncCallback(uiEnv, AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
                static_cast<ani_object>(callbackRef),
                EtsFormErrorUtil::CreateErrorByInternalErrorCode(
                    uiEnv, ERR_APPEXECFWK_FORM_INVALID_PARAM),
                nullptr);
            uiEnv->GlobalReference_Delete(callbackRef);
            uiEnv->DestroyLocalScope();
        }, "RequestPublishForm::ParamErrorCallback");
        return;
    }
    want.SetParam(IS_FORM_AGENT, true);

    // Worker thread: blocking IPC only, then capture POD results.
    int64_t formId = -1;
    std::unique_ptr<AppExecFwk::FormProviderData> formProviderData;
    std::vector<AppExecFwk::FormDataProxy> formDataProxies;
    ErrCode ipcRet = FormMgr::GetInstance().RequestPublishForm(
        want, false, formProviderData, formId, formDataProxies);
    ErrCode acqRet = (ipcRet == ERR_OK)
        ? FormMgr::GetInstance().AcquireAddFormResult(formId)
        : ipcRet;

    // Post VM-facing callback work to the main event runner so all ANI ops happen on
    // the UI thread (matching JsFormCrossDevicePublishCallback::OnResult pattern).
    auto mainHandler = std::make_shared<AppExecFwk::EventHandler>(
        AppExecFwk::EventRunner::GetMainEventRunner());
    mainHandler->PostTask(
        [vm, callbackRef, acqRet, formId, mainHandler]() {
            ani_env *uiEnv = FormAniUtil::GetEnvFromVm(vm);
            if (uiEnv == nullptr || callbackRef == nullptr) {
                HILOG_ERROR("get ui env failed or callback ref is null");
                return;
            }
            ani_size nr = REFERENCES_MAX_NUMBER;
            uiEnv->CreateLocalScope(nr);
            if (acqRet == ERR_OK) {
                ani_string s = FormAniUtil::GetAniString(uiEnv, std::to_string(formId));
                FormAniUtil::AsyncCallback(uiEnv, AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
                    static_cast<ani_object>(callbackRef),
                    EtsFormErrorUtil::CreateError(uiEnv, acqRet),
                    reinterpret_cast<ani_object>(s));
            } else {
                HILOG_ERROR("fail acqRet:%{public}d", acqRet);
                FormAniUtil::AsyncCallback(uiEnv, AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
                    static_cast<ani_object>(callbackRef),
                    EtsFormErrorUtil::CreateErrorByInternalErrorCode(uiEnv, acqRet),
                    nullptr);
            }
            uiEnv->GlobalReference_Delete(callbackRef);
            uiEnv->DestroyLocalScope();
        },
        "RequestPublishForm::MainCallback");
}

void CheckWantParam(ani_env *env, ani_object aniWant, ani_object callback)
{
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    auto asyncCallbackInfo = std::make_shared<RequestPublishFormCallbackInfo>();
    if (!AppExecFwk::UnwrapWant(env, aniWant, asyncCallbackInfo->want)) {
        HILOG_ERROR("fail convert want");
        EtsFormErrorUtil::ThrowParamError(env, "Failed to convert want.");
        return;
    }
}

void UpdateFormCrossBundle(ani_env *env, ani_string aniFormId, ani_string dataObjStr, ani_object callback)
{
    FormHistogramUtils::ReportHistogramBoolean("Form.Agent.updateFormCrossBundle", HISTOGRAM_BOOLEAN_SAMPLE);
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    if (FormAniUtil::IsRefUndefined(env, aniFormId) || FormAniUtil::IsRefUndefined(env, dataObjStr)) {
        FormAniUtil::InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }

    int64_t formId = FormAniUtil::FormIdAniStrtoInt64(env, aniFormId);
    auto formProviderData = AppExecFwk::FormProviderData(FormAniUtil::AniStringToStdString(env, dataObjStr));
    int32_t ret = FormMgr::GetInstance().UpdateFormCrossBundle(formId, formProviderData);
    if (ret != ERR_OK) {
        HILOG_ERROR("UpdateFormCrossBundle failed, error code: %{public}d", static_cast<int32_t>(ret));
    }
    FormAniUtil::InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
}

} // anonymous namespace

void EtsFormAgentInit(ani_env* env)
{
    HILOG_INFO("EtsFormAgentInit Call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_namespace ns;
    status = env->FindNamespace(ETS_FORM_AGENT_NAME, &ns);
    if (status != ANI_OK) {
        HILOG_ERROR("FindNamespace application failed status: %{public}d", status);
        return;
    }
    std::array methods = {
        ani_native_function {
            "nativeRequestPublishForm", nullptr, reinterpret_cast<void *>(RequestPublishForm)},
        ani_native_function {
            "nativeUpdateFormCrossBundle", nullptr, reinterpret_cast<void *>(UpdateFormCrossBundle)},
        ani_native_function {
            "checkWantParam", nullptr, reinterpret_cast<void *>(CheckWantParam)},
    };
    status = env->Namespace_BindNativeFunctions(ns, methods.data(), methods.size());
    if (status != ANI_OK) {
        HILOG_ERROR("Namespace_BindNativeFunctions failed status: %{public}d", status);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    HILOG_INFO("in EtsFormAgent.ANI_Constructor");
    if (vm == nullptr || result == nullptr) {
        HILOG_ERROR("null vm or result");
        return ANI_INVALID_ARGS;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        HILOG_ERROR("GetEnv failed, status: %{public}d", status);
        return ANI_NOT_FOUND;
    }
    EtsFormAgentInit(env);
    *result = ANI_VERSION_1;
    HILOG_INFO("EtsFormAgent.ANI_Constructor finished");
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS