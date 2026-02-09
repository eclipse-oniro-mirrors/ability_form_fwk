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

#ifndef OHOS_FORM_FWK_ETS_FORM_STATE_OBSERVER_H
#define OHOS_FORM_FWK_ETS_FORM_STATE_OBSERVER_H

#include <map>
#include <mutex>
#include <vector>
#include <singleton.h>

#include "ani.h"
#include "ets_native_reference.h"
#include "event_handler.h"
#include "form_mgr_interface.h"
#include "form_mgr.h"
#include "js_form_state_observer_stub.h"
#include "running_form_info.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsFormEventCallbackList : public std::enable_shared_from_this<EtsFormEventCallbackList> {
public:
    EtsFormEventCallbackList(const std::string &bundle, const std::string &type, ani_env* env)
        : bindHostBundleName(bundle), eventType_(type), env_(env)
    {}
    ~EtsFormEventCallbackList();
    bool ContainEqualCallback(ani_object callback) const;

    bool IsEmpty() const
    {
        return callbacks_.empty();
    }
    void PushCallback(ani_object call);

    void RemoveCallback(ani_object call);

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
    std::vector<ani_ref> callbacks_;
    ani_env* env_ = nullptr;
};

class EtsFormAddCallbackClient : public std::enable_shared_from_this<EtsFormAddCallbackClient> {
public:
    EtsFormAddCallbackClient(ani_env* env, ani_ref callbackRef);

    ~EtsFormAddCallbackClient();

    void ProcessFormAdd(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    bool IsStrictEqual(ani_object callback);

private:
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    ani_ref callbackRef_ = nullptr;
    ani_env* env_ = nullptr;
};

class EtsFormRemoveCallbackClient : public std::enable_shared_from_this<EtsFormRemoveCallbackClient> {
public:
    EtsFormRemoveCallbackClient(ani_env* env, ani_ref callbackRef);

    ~EtsFormRemoveCallbackClient();

    void ProcessFormRemove(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    bool IsStrictEqual(ani_object callback);

private:
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    ani_ref callbackRef_ = nullptr;
    ani_env* env_;
};

class EtsFormStateObserver : public JsFormStateObserverStub,
                            public DelayedRefSingleton<EtsFormStateObserver> {
public:
    EtsFormStateObserver() = default;

    virtual ~EtsFormStateObserver() = default;

    static sptr<EtsFormStateObserver> GetInstance();

    std::shared_ptr<AppExecFwk::EventHandler> GetMainEventRunner();

    bool RegisterFormAddCallback(ani_vm* ani_vm, const std::string &bundleName, const ani_object callback);

    bool RegisterFormRemoveCallback(ani_vm* ani_vm, const std::string &bundleName, const ani_object callback);

    void ClearFormAddCallbackByBundle(const std::string &bundleName);

    void DelFormAddCallbackByBundle(const ani_object callback, const std::string &bundleName);

    void ClearFormRemoveCallbackByBundle(const std::string &bundleName);

    void DelFormRemoveCallbackByBundle(const ani_object callback, const std::string &bundleName);

    int32_t OnAddForm(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    int32_t OnRemoveForm(const std::string &bundleName, const AppExecFwk::RunningFormInfo &runningFormInfo);

    bool CheckMapSize(const std::string &type, const std::string &bundleName);

    int RegisterFormInstanceCallback(ani_vm* ani_vm, ani_object etsObserverObject,
        bool isVisibility, std::string &bundleName, sptr<EtsFormStateObserver> &formObserver);

    int32_t NotifyWhetherFormsVisible(const AppExecFwk::FormVisibilityType visibleType, const std::string &bundleName,
        std::vector<AppExecFwk::FormInstance> &runningFormInfos);

    ErrCode ClearFormNotifyVisibleCallbackByBundle(const std::string bundleName, bool isVisibility,
        sptr<EtsFormStateObserver> &formObserver);

    ErrCode DelFormNotifyVisibleCallbackByBundle(const std::string bundleName, bool isVisibility,
        ani_object etsObserverObject, sptr<EtsFormStateObserver> &formObserver);

    ErrCode OnFormClickEvent(const std::string &bundleName, const std::string &callType,
        const AppExecFwk::RunningFormInfo &runningFormInfo);

    ErrCode RegisterClickEventCallback(ani_vm* ani_vm, const std::string &bundleName,
        const ani_object callback, const std::string &type);

    ErrCode ClearFormClickCallbackByBundleName(const std::string &type, const std::string &bundleName);

    ErrCode ClearFormClickCallback(const std::string &type, const std::string &bundleName, const ani_object &callback);

private:
    static std::mutex mutex_;
    static sptr<EtsFormStateObserver> instance_;
    mutable std::mutex addFormCallbackMutex_;
    mutable std::mutex removeFormCallbackMutex_;
    mutable std::mutex formIsvisibleCallbackMutex_;
    mutable std::mutex formEventMapMutex_;
    mutable std::mutex aniVmMutex_;
    mutable std::mutex handlerMutex_;

    std::map<std::string, std::vector<std::shared_ptr<EtsFormAddCallbackClient>>> formAddCallbackMap_;
    std::map<std::string, std::vector<std::shared_ptr<EtsFormRemoveCallbackClient>>> formRemoveCallbackMap_;
    std::map<std::string, std::shared_ptr<AppExecFwk::ETSNativeReference>> formVisibleCallbackMap_;
    std::map<std::string, std::shared_ptr<AppExecFwk::ETSNativeReference>> formInvisibleCallbackMap_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<EtsFormEventCallbackList>>> formEventMap_;;
    ani_vm* ani_vm_ = nullptr;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;

    ani_env* GetAniEnv(ani_vm* ani_vm);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_FORM_FWK_ETS_FORM_STATE_OBSERVER_H