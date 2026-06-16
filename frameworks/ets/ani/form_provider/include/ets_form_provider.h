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

#ifndef OHOS_FORM_FWK_ETS_FORM_PROVIDER_H
#define OHOS_FORM_FWK_ETS_FORM_PROVIDER_H

#include "ani.h"
#include "ani_base_context.h"
#include "form_instance.h"
#include "form_provider_delegate_stub.h"

namespace OHOS {
namespace AbilityRuntime {
struct PublishFormCrossBundleControlParam {
    AppExecFwk::PublishFormCrossBundleInfo bundleInfo;
    bool isCanOpen = false;
};

class EtsFormProviderProxyMgr : public AppExecFwk::FormProviderDelegateStub {
public:
    EtsFormProviderProxyMgr() = default;

    virtual ~EtsFormProviderProxyMgr() = default;

    static sptr<EtsFormProviderProxyMgr> GetInstance();

    void RegisterPublishFormCrossBundleControl(ani_env *env, ani_object callback);

    void UnregisterPublishFormCrossBundleControl();
private:
    static std::mutex mutex_;
    static sptr<EtsFormProviderProxyMgr> instance_;
    ani_ref crossBundleControlCallback_ = nullptr;
    ani_vm* crossBundleControlVm_;
    
    ani_env* GetCrossBundleControlEnv();
    mutable std::mutex crossBundleControlMutex_;
    ErrCode PublishFormCrossBundleControl(const AppExecFwk::PublishFormCrossBundleInfo &bundleInfo, bool &isCanOpen);
    void PublishFormCrossBundleControlInner(std::shared_ptr<PublishFormCrossBundleControlParam> dataParam);
};

} // namespace AbilityRuntime
} // namespace OHOS
#endif /* OHOS_FORM_FWK_ETS_FORM_PROVIDER_H */