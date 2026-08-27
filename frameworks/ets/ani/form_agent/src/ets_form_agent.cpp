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
#include "form_cross_device_request.h"
#include "form_cross_device_publish_callback_stub.h"
#include "peer_form_service_info.h"
#include "ipc_skeleton.h"
#include "nlohmann/json.hpp"
#include "runtime.h"
#include "want.h"
#include "event_handler.h"

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
constexpr ani_size REFERENCES_MAX_NUMBER = 16;
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

// Forward declaration
ani_object CreateCrossDeviceResultAniObject(ani_env *env, const PublishFormCrossDeviceResult &result);

// ANI callback stub for cross-device publish result.
// Holds a self-reference and a global ref to the AsyncCallbackWrapper.
// OnResult dispatches to the main thread to invoke the callback wrapper.
class JsFormCrossDevicePublishCallback : public FormCrossDevicePublishCallbackStub {
public:
    JsFormCrossDevicePublishCallback(ani_env *env, ani_object callback)
    {
        vm_ = nullptr;
        ani_status status = env->GetVM(&vm_);
        if (status != ANI_OK || vm_ == nullptr) {
            HILOG_ERROR("GetVM failed");
            return;
        }
        if (env->GlobalReference_Create(callback, &callbackRef_) != ANI_OK) {
            HILOG_ERROR("GlobalReference_Create failed");
        }
    }
    ~JsFormCrossDevicePublishCallback() override
    {
        if (vm_ != nullptr && callbackRef_ != nullptr) {
            ani_env *env = FormAniUtil::GetEnvFromVm(vm_);
            if (env != nullptr) {
                env->GlobalReference_Delete(callbackRef_);
            }
            callbackRef_ = nullptr;
        }
    }

    void HoldSelfRef(const sptr<IRemoteObject> &ref)
    {
        selfRef_ = ref;
    }

    void ReleaseSelfRef()
    {
        selfRef_ = nullptr;
    }

    void OnResult(const PublishFormCrossDeviceResult &result) override
    {
        bool expected = false;
        if (!done_.compare_exchange_strong(expected, true)) {
            return; // prevent duplicate callback
        }
        auto resultPtr = std::make_shared<PublishFormCrossDeviceResult>(result);
        auto mainHandler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
        mainHandler->PostTask([this, resultPtr, mainHandler]() {
            ani_env *env = FormAniUtil::GetEnvFromVm(vm_);
            if (env == nullptr || callbackRef_ == nullptr) {
                selfRef_ = nullptr;
                return;
            }
            ani_size nr_refs = REFERENCES_MAX_NUMBER;
            env->CreateLocalScope(nr_refs);
            if (resultPtr->errCode == ERR_OK) {
                ani_object resultObj = CreateCrossDeviceResultAniObject(env, *resultPtr);
                FormAniUtil::InvokeAsyncWithBusinessError(env,
                    static_cast<ani_object>(callbackRef_), ERR_OK, resultObj);
            } else {
                FormAniUtil::InvokeAsyncWithBusinessError(env,
                    static_cast<ani_object>(callbackRef_), resultPtr->errCode, nullptr);
            }
            env->DestroyLocalScope();
            selfRef_ = nullptr; // release self-reference after callback invoked
            },
            "JsFormCrossDevicePublishCallback::OnResult");
    }

private:
    ani_vm *vm_ = nullptr;
    ani_ref callbackRef_ = nullptr;
    std::atomic<bool> done_{false};
    sptr<IRemoteObject> selfRef_;
};

ani_object CreateCrossDeviceResultAniObject(ani_env *env, const PublishFormCrossDeviceResult &result)
{
    ani_object obj = FormAniUtil::CreateAniObject(env,
        "@ohos.app.form.formInfo.formInfo.PublishFormCrossDeviceResultInner");
    if (obj == nullptr) {
        HILOG_ERROR("CreateAniObject failed");
        return nullptr;
    }
    FormAniUtil::SetPropertyStringByName(env, obj, "formId", std::to_string(result.formId));
    return obj;
}

ani_object CreatePeerFormHostServiceInfoObj(ani_env *env, const AppExecFwk::PeerFormHostServiceInfo &service)
{
    ani_object obj = FormAniUtil::CreateAniObject(env, "@ohos.app.form.formInfo.formInfo.PeerFormHostServiceInfoInner");
    if (obj == nullptr) {
        HILOG_ERROR("CreateAniObject failed");
        return nullptr;
    }
    FormAniUtil::SetPropertyStringByName(env, obj, "serviceName", service.serviceName);
    FormAniUtil::SetPropertyStringByName(env, obj, "serviceDisplayName", service.serviceDisplayName);
    FormAniUtil::SetPropertyStringByName(env, obj, "displayId", service.displayId);
    FormAniUtil::SetPropertyStringByName(env, obj, "customData", service.customData);
    FormAniUtil::SetPropertyStringByName(env, obj, "deviceId", service.deviceId);
    FormAniUtil::SetPropertyStringByName(env, obj, "networkId", service.networkId);
    FormAniUtil::SetPropertyStringByName(env, obj, "serviceId", service.serviceId);
    return obj;
}

void FillFormHostServicesArray(ani_env *env, ani_array arrayObj,
    const std::vector<AppExecFwk::PeerFormHostServiceInfo> &services)
{
    for (size_t i = 0; i < services.size(); ++i) {
        ani_object item = CreatePeerFormHostServiceInfoObj(env, services[i]);
        if (item == nullptr) {
            continue;
        }
        env->Array_Set(arrayObj, i, static_cast<ani_ref>(item));
    }
}

void GetAvailableFormHostServices(ani_env *env, ani_object asyncCallback)
{
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    std::vector<AppExecFwk::PeerFormHostServiceInfo> services;
    auto retCode = FormMgr::GetInstance().GetAvailableFormHostServices(services);
    if (retCode != ERR_OK) {
        FormAniUtil::InvokeAsyncWithBusinessError(env, asyncCallback, retCode, nullptr);
        return;
    }
    ani_object arrayObj = FormAniUtil::GetAniArray(env, services.size());
    if (arrayObj != nullptr) {
        FillFormHostServicesArray(env, static_cast<ani_array>(arrayObj), services);
    }
    FormAniUtil::InvokeAsyncWithBusinessError(env, asyncCallback, ERR_OK, arrayObj);
}

bool ParsePeerFormHostServiceInfoObj(ani_env *env, ani_object serviceObj, AppExecFwk::PeerFormHostServiceInfo &service)
{
    HILOG_DEBUG("call");
    if (env == nullptr || serviceObj == nullptr) {
        HILOG_ERROR("null env or serviceObj");
        return false;
    }
    std::string serviceName;
    if (!FormAniUtil::GetStringProperty(env, serviceObj, "serviceName", serviceName) || serviceName.empty()) {
        HILOG_ERROR("serviceName missing or empty");
        return false;
    }
    service.serviceName = serviceName;
    FormAniUtil::GetStringProperty(env, serviceObj, "serviceDisplayName", service.serviceDisplayName);
    FormAniUtil::GetStringProperty(env, serviceObj, "displayId", service.displayId);
    FormAniUtil::GetStringProperty(env, serviceObj, "customData", service.customData);
    FormAniUtil::GetStringProperty(env, serviceObj, "deviceId", service.deviceId);
    FormAniUtil::GetStringProperty(env, serviceObj, "networkId", service.networkId);
    FormAniUtil::GetStringProperty(env, serviceObj, "serviceId", service.serviceId);
    return true;
}

void RequestPublishFormCrossDevice(ani_env *env, ani_object peerServiceInfoObj, ani_object aniWant,
    ani_string aniFormBindingDataStr, ani_object asyncCallback)
{
    HILOG_INFO("call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    AppExecFwk::PeerFormHostServiceInfo peerServiceInfo;
    if (!ParsePeerFormHostServiceInfoObj(env, peerServiceInfoObj, peerServiceInfo)) {
        HILOG_ERROR("parse peerServiceInfo failed");
        FormAniUtil::InvokeAsyncWithBusinessError(env, asyncCallback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }
    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, aniWant, want)) {
        HILOG_ERROR("parse want failed");
        FormAniUtil::InvokeAsyncWithBusinessError(env, asyncCallback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
        return;
    }
    std::string formProviderDataStr = FormAniUtil::AniStringToStdString(env, aniFormBindingDataStr);

    FormCrossDeviceRequest req;
    req.peerNetworkId = peerServiceInfo.networkId;
    if (!peerServiceInfo.serviceId.empty()) {
        if (!FormAniUtil::ConvertStringToInt64(peerServiceInfo.serviceId, req.peerServiceId)) {
            HILOG_ERROR("peerServiceId is not numeric");
            FormAniUtil::InvokeAsyncWithBusinessError(env, asyncCallback,
                static_cast<int32_t>(ERR_APPEXECFWK_FORM_INVALID_PARAM), nullptr);
            return;
        }
    }
    req.want = want;
    req.formProviderData = formProviderDataStr;

    // IPC callback: OnResult will be invoked on the main thread and call the AsyncCallbackWrapper
    sptr<JsFormCrossDevicePublishCallback> cb = new (std::nothrow)
        JsFormCrossDevicePublishCallback(env, asyncCallback);
    if (cb == nullptr) {
        FormAniUtil::InvokeAsyncWithBusinessError(env, asyncCallback,
            static_cast<int32_t>(ERR_APPEXECFWK_FORM_COMMON_CODE), nullptr);
        return;
    }
    cb->HoldSelfRef(cb);
    sptr<IRemoteObject> callerToken = IPCSkeleton::GetContextObject();
    ErrCode ret = FormMgr::GetInstance().RequestPublishFormCrossDevice(req, callerToken, cb);
    if (ret != ERR_OK) {
        FormAniUtil::InvokeAsyncWithBusinessError(env, asyncCallback, ret, nullptr);
        cb->ReleaseSelfRef();
    }
}

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
            "nativeGetAvailableFormHostServices", nullptr, reinterpret_cast<void *>(GetAvailableFormHostServices)},
        ani_native_function {
            "nativeRequestPublishFormCrossDevice", nullptr, reinterpret_cast<void *>(RequestPublishFormCrossDevice)},
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