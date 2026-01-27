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

#ifndef OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_H
#define OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_H

#include <map>
#include <mutex>
#include <vector>
#include <singleton.h>
#include "event_handler.h"
#include "form_mgr_interface.h"
#include "form_mgr.h"
#include "js_form_state_observer_stub.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "running_form_info.h"

namespace OHOS {
namespace AbilityRuntime {
class FormEventCallbackList : public std::enable_shared_from_this<FormEventCallbackList> {
public:
    FormEventCallbackList(const std::string &bundle, const std::string &type, napi_env env)
        : bindHostBundleName(bundle), eventType_(type), env_(env)
    {}
    ~FormEventCallbackList();
    bool ContainEqualCallback(napi_value callback) const;

    bool IsEmpty() const
    {
        return callbacks_.empty();
    }
    void PushCallback(napi_value call);

    void RemoveCallback(napi_value call);

    void HandleFormEvent(const AppExecFwk::RunningFormInfo &runningFormInfo) const;

    std::string BindHostBundleName() const
    {
        return bindHostBundleName;
    }

    std::string BindFormEventType() const
    {
        return eventType_;
    }

private:
    std::string bindHostBundleName;
    std::string eventType_;
    std::vector<napi_ref> callbacks_;
    napi_env env_ = nullptr;
};

class FormAddCallbackClient : public std::enable_shared_from_this<FormAddCallbackClient> {
public:
    FormAddCallbackClient(napi_env env, napi_ref callbackRef);

    ~FormAddCallbackClient();

    void ProcessFormAdd(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    bool IsStrictEqual(napi_value callback);

private:
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    napi_ref callbackRef_ {};
    napi_env env_;
};

class FormRemoveCallbackClient : public std::enable_shared_from_this<FormRemoveCallbackClient> {
public:
    FormRemoveCallbackClient(napi_env env, napi_ref callbackRef);

    ~FormRemoveCallbackClient();

    void ProcessFormRemove(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    bool IsStrictEqual(napi_value callback);

private:
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    napi_ref callbackRef_ = nullptr;
    napi_env env_;
};

class JsFormStateObserver : public JsFormStateObserverStub,
                            public DelayedRefSingleton<JsFormStateObserver> {
public:
    JsFormStateObserver() = default;

    virtual ~JsFormStateObserver() = default;

    static sptr<JsFormStateObserver> GetInstance();

    std::shared_ptr<AppExecFwk::EventHandler> GetMainEventRunner();

    bool RegisterFormAddCallback(const napi_env env, const std::string &bundleName, const napi_value callback);

    bool RegisterFormRemoveCallback(const napi_env env, const std::string &bundleName, const napi_value callback);

    void ClearFormAddCallbackByBundle(const std::string &bundleName);

    void DelFormAddCallbackByBundle(const napi_value callback, const std::string &bundleName);

    void ClearFormRemoveCallbackByBundle(const std::string &bundleName);

    void DelFormRemoveCallbackByBundle(const napi_value callback, const std::string &bundleName);

    int32_t OnAddForm(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    int32_t OnRemoveForm(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    bool CheckMapSize(const std::string &type, const std::string &bundleName);

    int RegisterFormInstanceCallback(napi_env env, napi_value jsObserverObject,
        bool isVisibility, std::string &bundleName, sptr<JsFormStateObserver> &formObserver);

    int32_t NotifyWhetherFormsVisible(const AppExecFwk::FormVisibilityType visibleType, const std::string &bundleName,
        std::vector<AppExecFwk::FormInstance> &runningFormInfos);

    ErrCode ClearFormNotifyVisibleCallbackByBundle(const std::string bundleName, bool isVisibility,
        sptr<JsFormStateObserver> &formObserver);

    ErrCode DelFormNotifyVisibleCallbackByBundle(const std::string bundleName, bool isVisibility,
        napi_value jsObserverObject, sptr<JsFormStateObserver> &formObserver);

    ErrCode OnFormClickEvent(const std::string &bundleName, const std::string &callType,
        const AppExecFwk::RunningFormInfo &runningFormInfo);

    ErrCode RegisterClickEventCallback(const napi_env env, const std::string &bundleName,
        const napi_value callback, const std::string &type);

    ErrCode ClearFormClickCallbackByBundleName(const std::string &type, const std::string &bundleName);

    ErrCode ClearFormClickCallback(const std::string &type, const std::string &bundleName, const napi_value &callback);

private:
    static std::mutex mutex_;
    static sptr<JsFormStateObserver> instance_;
    mutable std::mutex addFormCallbackMutex_;
    mutable std::mutex removeFormCallbackMutex_;
    mutable std::mutex formIsvisibleCallbackMutex_;
    mutable std::mutex formEventMapMutex_;
    mutable std::mutex handlerMutex_;

    std::map<std::string, std::vector<std::shared_ptr<FormAddCallbackClient>>> formAddCallbackMap_;
    std::map<std::string, std::vector<std::shared_ptr<FormRemoveCallbackClient>>> formRemoveCallbackMap_;
    std::map<std::string, std::shared_ptr<NativeReference>> formVisibleCallbackMap_;
    std::map<std::string, std::shared_ptr<NativeReference>> formInvisibleCallbackMap_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<FormEventCallbackList>>> formEventMap_;;
    napi_env env_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_JS_FORM_STATE_OBSERVER_H
