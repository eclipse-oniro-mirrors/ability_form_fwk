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

private:
    static std::mutex mutex_;
    static sptr<JsFormRouterProxyMgr> instance_;
    mutable std::mutex FormRouterProxyCallbackMutex_;

    std::map<int64_t, std::shared_ptr<FormRouterProxyCallbackClient>> formRouterProxyCallbackMap_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    DISALLOW_COPY_AND_MOVE(JsFormRouterProxyMgr);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif /* OHOS_FORM_FWK_JS_FORM_HOST_H */

