/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_JS_FORM_HOST_H
#define OHOS_FORM_FWK_JS_FORM_HOST_H

#include "event_handler.h"
#include "form_host_delegate_stub.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_common_want.h"
#include "form_instance.h"

namespace OHOS {
namespace AbilityRuntime {
napi_value JsFormHostInit(napi_env env, napi_value exportObj);

class FormRouterProxyCallbackClient : public std::enable_shared_from_this<FormRouterProxyCallbackClient> {
public:
    FormRouterProxyCallbackClient(napi_env env, napi_ref callbackRef);

    ~FormRouterProxyCallbackClient();

    void ProcessFormRouterProxy(const OHOS::AAFwk::Want &want);

private:
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    napi_ref callbackRef_ = nullptr;
    napi_env env_;
};

class JsFormRouterProxyMgr : public AppExecFwk::FormHostDelegateStub {
public:
    JsFormRouterProxyMgr() = default;

    virtual ~JsFormRouterProxyMgr() = default;

    static sptr<JsFormRouterProxyMgr> GetInstance();

    void AddFormRouterProxyCallback(napi_env env, napi_value callback, const std::vector<int64_t> &formIds);

    void RemoveFormRouterProxyCallback(const std::vector<int64_t> &formIds);

    ErrCode RouterEvent(const int64_t formId, const OHOS::AAFwk::Want &want);
    
    bool RegisterOverflowListener(napi_env env, napi_ref callback);

    bool UnregisterOverflowListener();
    
    bool RegisterChangeSceneAnimationStateListener(napi_env env, napi_ref callback);

    bool UnregisterChangeSceneAnimationStateListener();

    bool RegisterGetFormRectListener(napi_env env, napi_ref callback);

    bool UnregisterGetFormRectListener();

    bool RegisterGetLiveFormStatusListener(napi_env env, napi_ref callback);

    bool UnregisterGetLiveFormStatusListener();
private:
    static std::mutex mutex_;
    static sptr<JsFormRouterProxyMgr> instance_;
    mutable std::mutex FormRouterProxyCallbackMutex_;

    std::map<int64_t, std::shared_ptr<FormRouterProxyCallbackClient>> formRouterProxyCallbackMap_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    DISALLOW_COPY_AND_MOVE(JsFormRouterProxyMgr);
    napi_ref overflowRegisterCallback_ = nullptr;
    napi_env overflowEnv_;
    napi_ref changeSceneAnimationStateRigisterCallback_ = nullptr;
    napi_env changeSceneAnimationStateEnv_;
    ErrCode RequestOverflow(const int64_t formId, const AppExecFwk::OverflowInfo &overflowInfo, bool isOverflow = true);
    void CreateFormOverflowInfo(napi_env env, AppExecFwk::OverflowInfo &overflowInfo, napi_value* result);
    void RequestOverflowInner(std::shared_ptr<LiveFormInterfaceParam> dataParam);
    ErrCode ChangeSceneAnimationState(const int64_t formId, int32_t state);
    void ChangeSceneAnimationStateInner(std::shared_ptr<LiveFormInterfaceParam> dataParam);
    napi_ref getFormRectCallbackRef_ = nullptr;
    napi_env getFormRectEnv_;
    ErrCode GetFormRect(const int64_t formId, AppExecFwk::Rect &rect);
    void GetFormRectInner(std::shared_ptr<LiveFormInterfaceParam> dataParam);
    void CallPromise(napi_value funcResult, std::shared_ptr<LiveFormInterfaceParam> liveFormInterfaceParam);
    static napi_value PromiseCallback(napi_env env, napi_callback_info info);
    static bool ConvertFunctionResult(napi_env env, napi_value funcResult, AppExecFwk::Rect &rect);

    napi_ref getLiveFormStatusCallbackRef_ = nullptr;
    napi_env getLiveFormStatusEnv_;
    ErrCode GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap);
    void GetLiveFormStatusInner(LiveFormInterfaceParam *dataParam);
    bool ConvertNapiValueToMap(napi_env env, napi_value value, std::unordered_map<std::string, std::string> &uMap);
};

class PromiseCallbackInfo {
public:
    static PromiseCallbackInfo* Create(std::shared_ptr<LiveFormInterfaceParam> liveFormInterfaceParam);
 
    static void Destroy(PromiseCallbackInfo* callbackInfo);
 
    std::shared_ptr<LiveFormInterfaceParam> GetJsCallBackParam();
 
private:
    explicit PromiseCallbackInfo(std::shared_ptr<LiveFormInterfaceParam> liveFormInterfaceParam);
 
    ~PromiseCallbackInfo();
 
    std::shared_ptr<LiveFormInterfaceParam> liveFormInterfaceParam_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif /* OHOS_FORM_FWK_JS_FORM_HOST_H */

