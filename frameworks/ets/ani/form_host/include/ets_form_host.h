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

#ifndef OHOS_FORM_FWK_ETS_FORM_HOST_H
#define OHOS_FORM_FWK_ETS_FORM_HOST_H

#include "ani.h"
#include "ani_common_want.h"
#include "ani_form_common_util.h"
#include "ani_form_error_util.h"
#include "ani_form_util.h"
#include "ani_helpers.h"
#include "event_handler.h"
#include "form_host_delegate_stub.h"
#include "form_instance.h"
#include "form_mgr.h"
#include "fms_log_wrapper.h"
#include "template_form_detail_info.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AbilityRuntime::FormAniHelpers;

class FormRouterProxyCallbackClient : public std::enable_shared_from_this<FormRouterProxyCallbackClient> {
public:
    FormRouterProxyCallbackClient(ani_vm* vm, ani_ref callback): m_vm(vm), m_callback(callback)
    {
        m_handler = std::make_shared<AppExecFwk::EventHandler>(AppExecFwk::EventRunner::GetMainEventRunner());
    }

    ~FormRouterProxyCallbackClient()
    {
        ani_env *env = GetEnvFromVm(m_vm);
        if (env == nullptr) {
            HILOG_ERROR("Env is null");
            return;
        }
        env->Reference_Delete(m_callback);
    }

    void ProcessFormRouterProxy(const Want &want)
    {
        HILOG_INFO("Call");
        if (m_handler == nullptr) {
            HILOG_ERROR("null Handler");
            return;
        }

        m_handler->PostSyncTask([thisWeakPtr = weak_from_this(), want]() {
            auto sharedThis = thisWeakPtr.lock();
            if (sharedThis == nullptr) {
                HILOG_ERROR("null SharedThis");
                return;
            }

            ani_env *env = GetEnvFromVm(sharedThis->m_vm);
            if (env == nullptr) {
                HILOG_ERROR("Env is null");
                return;
            }

            ani_object aniWant = AppExecFwk::WrapWant(env, want);
            auto res = InvokeCallback(env, static_cast<ani_object>(sharedThis->m_callback), aniWant);
            if (!res) {
                HILOG_ERROR("Cannot call callback");
                return;
            }
        });
    }

private:
    std::shared_ptr<AppExecFwk::EventHandler> m_handler = nullptr;
    ani_vm* m_vm;
    ani_ref m_callback = nullptr;
};

class EtsFormRouterProxyMgr : public AppExecFwk::FormHostDelegateStub {
public:
    EtsFormRouterProxyMgr() = default;

    virtual ~EtsFormRouterProxyMgr() = default;

    static sptr<EtsFormRouterProxyMgr> GetInstance();

    void RegisterOverflowListener(ani_vm* ani_vm, ani_object callback);

    void UnregisterOverflowListener();

    void RegisterChangeSceneAnimationStateListener(ani_vm* ani_vm, ani_object callback);

    void UnregisterChangeSceneAnimationStateListener();

    void RegisterGetFormRectListener(ani_vm *ani_vm, ani_object callback);

    void UnregisterGetFormRectListener();

    void RegisterGetLiveFormStatusListener(ani_vm *ani_vm, ani_object callback);

    void UnregisterGetLiveFormStatusListener();
    
    void RegisterTemplateFormDetailInfoChange(ani_vm* ani_vm, ani_object callback);

    void UnregisterTemplateFormDetailInfoChange();

    void RemoveFormRouterProxyCallback(const std::vector<int64_t> &formIds);

    void AddFormRouterProxyCallback(ani_env* env, ani_object callback,
        const std::vector<int64_t> &formIds);

    ErrCode RouterEvent(const int64_t formId, const OHOS::AAFwk::Want &want);
private:
    static std::mutex mutex_;
    static sptr<EtsFormRouterProxyMgr> instance_;
    mutable std::mutex FormRouterProxyCallbackMutex_;
    std::map<int64_t, std::shared_ptr<FormRouterProxyCallbackClient>> formRouterProxyCallbackMap_;
    ani_ref overflowRegisterCallback_ = nullptr;
    ani_vm* ani_vm_ = nullptr;
    ani_ref changeSceneAnimationStateRigisterCallback_ = nullptr;
    ani_ref getFormRectCallbackRef_ = nullptr;
    ani_ref getLiveFormStatusCallbackRef_ = nullptr;
    DISALLOW_COPY_AND_MOVE(EtsFormRouterProxyMgr);

    ErrCode RequestOverflow(const int64_t formId, const AppExecFwk::OverflowInfo &overflowInfo, bool isOverflow = true);
    void RequestOverflowInner(LiveFormInterfaceParam* dataParam);
    ani_object CreateFormOverflowInfo(ani_env* env, AppExecFwk::OverflowInfo &overflowInfo);
    ErrCode ChangeSceneAnimationState(const int64_t formId, int32_t state);
    void ChangeSceneAnimationStateInner(std::shared_ptr<LiveFormInterfaceParam> dataParam);
    ErrCode GetFormRect(const int64_t formId, AppExecFwk::Rect &rect);
    void GetFormRectInner(LiveFormInterfaceParam *dataParam);
    ErrCode GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap);
    void GetLiveFormStatusInner(LiveFormInterfaceParam *dataParam);
    ani_env* GetAniEnv();
    bool bindNativeMethod(ani_env* env, ani_class cls, LiveFormInterfaceParam *dataParam);
    void CallPromise(ani_env* env, ani_class cls, ani_object callbackObj, ani_object retObj,
        LiveFormInterfaceParam *params);
    static void GetFormRectPromiseCallback(ani_env *env, ani_object aniObj, ani_object obj);
    static bool ConvertFunctionResult(ani_env* env, ani_object retObj, Rect &item);
    mutable std::mutex registerOverflowProxyMutex_;
    mutable std::mutex registerChangeSceneAnimationStateProxyMutex_;
    mutable std::mutex registerGetFormRectProxyMutex_;

    mutable std::mutex registerTemplateFormDetailInfoChangeMutex_;
    ani_ref templateFormDetailInfoChangeCallbackRef_ = nullptr;
    ani_vm* templateFormDetailInfoChangeVM;
    ani_env* GetTemplateFormDetailInfoChangeEnv();
    void SetTemplateFormDetailInfoChangeVM(ani_vm* ani_vm);

    ErrCode TemplateFormDetailInfoChange(const std::vector<AppExecFwk::TemplateFormDetailInfo> &templateFormInfo);
    void TemplateFormDetailInfoChangeInner(
        const std::vector<AppExecFwk::TemplateFormDetailInfo> &templateFormInfo);
    void GetTemplateFormInfoArray(ani_env* env,
        const std::vector<AppExecFwk::TemplateFormDetailInfo> &templateFormInfo,
        ani_array &templateFormInfoArray);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif /* OHOS_FORM_FWK_ETS_FORM_HOST_H */