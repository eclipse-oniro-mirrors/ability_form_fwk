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
    auto asyncCallbackInfo = std::make_shared<RequestPublishFormCallbackInfo>();
    if (!AppExecFwk::UnwrapWant(env, aniWant, asyncCallbackInfo->want)) {
        HILOG_ERROR("fail convert want");
        EtsFormErrorUtil::ThrowParamError(env, "Failed to convert want.");
        return;
    }
    asyncCallbackInfo->want.SetParam(IS_FORM_AGENT, true);
    int64_t formId = -1;
    ErrCode ret = FormMgr::GetInstance().RequestPublishForm(
        asyncCallbackInfo->want, false, asyncCallbackInfo->formProviderData,
        formId, asyncCallbackInfo->formDataProxies);
    if (ret != ERR_OK) {
        HILOG_ERROR("fail RequestPublishForm startAbility");
        FormAniUtil::AsyncCallback(env, AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER,
            callback, EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret),
            nullptr);
        return;
    }
    ret = FormMgr::GetInstance().AcquireAddFormResult(formId);
    if (ret == ERR_OK) {
        HILOG_INFO("Sucess");
        ani_string aniStrformId = FormAniUtil::GetAniString(env, std::to_string(formId));
        FormAniUtil::AsyncCallback(env, AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback,
            EtsFormErrorUtil::CreateError(env, ret), reinterpret_cast<ani_object>(aniStrformId));
    } else {
        HILOG_ERROR("fail");
        FormAniUtil::AsyncCallback(env, AGENT_CLASSNAME_ASYNC_CALLBACK_WRAPPER, callback,
            EtsFormErrorUtil::CreateErrorByInternalErrorCode(env, ret), nullptr);
    }
    return;
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

void UpdateFormCrossBundle(ani_env *env, ani_string aniFormId, ani_object aniFormBindingData,
    ani_object callback)
{
    FormHistogramUtils::ReportHistogramBoolean("Form.Agent.updateFormCrossBundle", HISTOGRAM_BOOLEAN_SAMPLE);
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    std::string formIdStr = (aniFormId != nullptr) ? FormAniUtil::AniStringToStdString(env, aniFormId) : "";
    if (formIdStr.empty()) {
        HILOG_ERROR("formId is invalid");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }
    int64_t formId = std::atoll(formIdStr.c_str());

    // Use FormAniUtil::UnwrapFormBindingData if available, otherwise parse the 'data' field via reflection.
    std::string formDataStr;
    if (aniFormBindingData != nullptr) {
        constexpr const char *FB_CLASS_NAME = "@ohos.app.form.formBindingData.FormBindingDataInner";
        constexpr const char *FB_GET_DATA_METHOD = "getData";
        constexpr const char *FB_GET_DATA_SIGNATURE = ":C{std.core.Object}";
        ani_class dataCls = nullptr;
        ani_method dataMethod = nullptr;
        if (env->FindClass(FB_CLASS_NAME, &dataCls) == ANI_OK && dataCls != nullptr
            && env->Class_FindMethod(dataCls, FB_GET_DATA_METHOD, FB_GET_DATA_SIGNATURE, &dataMethod) == ANI_OK
            && dataMethod != nullptr) {
            ani_ref dataRef = nullptr;
            if (env->Object_CallMethod_Ref(aniFormBindingData, dataMethod, &dataRef) == ANI_OK
                && dataRef != nullptr) {
                ani_string dataAniStr = static_cast<ani_string>(dataRef);
                formDataStr = FormAniUtil::AniStringToStdString(env, dataAniStr);
            }
        }
    }
    if (formDataStr.empty()) {
        HILOG_ERROR("formBindingData is invalid");
        InvokeAsyncWithBusinessError(env, callback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_PROVIDER_DATA_EMPTY), nullptr);
        return;
    }

    auto formProviderData = std::make_unique<OHOS::AppExecFwk::FormProviderData>(formDataStr);
    int32_t ret = FormMgr::GetInstance().UpdateFormCrossBundle(formId, *formProviderData);
    if (ret != ERR_OK) {
        HILOG_ERROR("UpdateFormCrossBundle failed, error code: %{public}d", static_cast<int32_t>(ret));
        InvokeAsyncWithBusinessError(env, callback, ret, nullptr);
        return;
    }
    InvokeAsyncWithBusinessError(env, callback, ERR_OK, nullptr);
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