/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_CALLBACK_ADAPTER_H
#define OHOS_FORM_FWK_FORM_CALLBACK_ADAPTER_H

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <singleton.h>

#include "form_info.h"
#include "form_provider_data.h"
#include "iremote_object.h"
#include "ipc_skeleton.h"
#include "template_form_detail_info.h"
#include "want.h"

#include "app_mgr_interface.h"
#include "form_mgr_errors.h"
#include "form_publish_interceptor_interface.h"
#include "fms_log_wrapper.h"
#include "common/util/form_proxy_registry.h"
#include "common/util/form_util.h"
#include "data_center/form_cust_config_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_record/form_record.h"
#include "feature/bundle_lock/form_bundle_lock_mgr.h"
#include "feature/route_proxy/form_router_proxy_mgr.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

class FormCommonAdapter;

class FormCallbackAdapter final : public DelayedRefSingleton<FormCallbackAdapter> {
    DECLARE_DELAYED_REF_SINGLETON(FormCallbackAdapter)
public:

    ErrCode RegisterFormRouterProxy(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterFormRouterProxy(const std::vector<int64_t> &formIds);

    ErrCode RegisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback);

    ErrCode UnregisterPublishFormInterceptor(const sptr<IRemoteObject> &interceptorCallback);

    ErrCode RegisterOverflowProxy(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterOverflowProxy();

    ErrCode RequestOverflow(const int64_t formId, const int32_t callingUid,
        const OverflowInfo &overflowInfo, bool isOverflow);

    ErrCode RegisterChangeSceneAnimationStateProxy(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterChangeSceneAnimationStateProxy();

    ErrCode ChangeSceneAnimationState(const int64_t formId, const int32_t callingUid, int32_t state);

    ErrCode RegisterGetFormRectProxy(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterGetFormRectProxy();

    ErrCode GetFormRect(const int64_t formId, const int32_t callingUid, Rect &rect);

    ErrCode RegisterGetLiveFormStatusProxy(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterGetLiveFormStatusProxy();

    ErrCode GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap);

    ErrCode StartAbilityByFms(const Want &want);

    ErrCode RegisterPublishFormCrossBundleControl(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterPublishFormCrossBundleControl();

    bool PublishFormCrossBundleControl(const PublishFormCrossBundleInfo &bundleInfo);

    ErrCode RegisterTemplateFormDetailInfoChange(const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterTemplateFormDetailInfoChange();

    ErrCode UpdateTemplateFormDetailInfo(const std::vector<TemplateFormDetailInfo> &templateFormInfo);

    ErrCode RegisterFormWantCallback(int32_t callingUid, const sptr<IRemoteObject> &callerToken);

    ErrCode UnregisterFormWantCallback(int32_t callingUid);

    ErrCode GetWantCallbackProxy(int32_t callingUid, sptr<IRemoteObject> &proxy);

    void SetFormPublishInterceptor(const sptr<IFormPublishInterceptor> &interceptor);

    sptr<IFormPublishInterceptor> GetFormPublishInterceptor();

private:
    ErrCode CallerCheck(const int64_t formId, const int32_t callingUid);

    ErrCode SceneAnimationCheck(const int64_t formId, const int32_t callingUid);

    bool IsForegroundApp();

    FormProxyRegistry overflowRegistry_{"Overflow"};
    FormProxyRegistry sceneAnimationRegistry_{"SceneAnimation"};
    FormProxyRegistry formRectRegistry_{"FormRect"};
    FormProxyRegistry liveFormStatusRegistry_{"LiveFormStatus"};
    FormProxyRegistry crossBundleControlRegistry_{"CrossBundleControl"};
    FormProxyRegistry templateFormDetailInfoRegistry_{"TemplateFormDetailInfo"};
    FormProxyRegistry wantCallbackRegistry_{"WantCallback"};
    sptr<IFormPublishInterceptor> formPublishInterceptor_ = nullptr;

    mutable std::mutex formPublishInterceptorMutex_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_CALLBACK_ADAPTER_H
