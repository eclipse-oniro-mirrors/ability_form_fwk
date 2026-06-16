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

#ifndef OHOS_FORM_FWK_FORM_EVENT_ADAPTER_H
#define OHOS_FORM_FWK_FORM_EVENT_ADAPTER_H

#include <memory>

#include "singleton.h"

#include "form_constants.h"
#include "common/util/form_util.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_data_mgr.h"
#include "feature/route_proxy/form_router_proxy_mgr.h"
#include "form_host/form_host_record.h"
#include "form_observer/form_observer_record.h"
#include "form_provider/form_provider_mgr.h"

namespace OHOS {
namespace AppExecFwk {

class FormCommonAdapter;

/**
 * @class FormEventAdapter
 * @brief Adapter for handling form events (message, router, background events)
 *
 * This adapter uses FormCommonAdapter through composition for shared functionality.
 */
class FormEventAdapter final : public DelayedRefSingleton<FormEventAdapter> {
    DECLARE_DELAYED_REF_SINGLETON(FormEventAdapter)
public:

    int MessageEvent(const int64_t formId, const Want &want,
        const sptr<IRemoteObject> &callerToken);

    int RouterEvent(const int64_t formId, Want &want,
        const sptr<IRemoteObject> &callerToken);

    int BackgroundEvent(const int64_t formId, Want &want,
        const sptr<IRemoteObject> &callerToken);

    void SetFreeInstallFlag(const FormRecord &record, Want &want);

    bool OpenByOpenType(const int32_t openType, const FormRecord &record,
        const sptr<IRemoteObject> &callerToken, Want &want, int32_t &openResult);

private:
    void NotifyFormClickEvent(int64_t formId, const std::string &formClickType, const int32_t userId);

    /**
     * @brief Check if the app has permission to keep background running
     * @param iBundleMgr Bundle manager interface
     * @param bundleName Bundle name of the app
     * @return true if the app has permission, false otherwise
     */
    bool CheckKeepBackgroundRunningPermission(const sptr<IBundleMgr> &iBundleMgr,
        const std::string &bundleName);
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_EVENT_ADAPTER_H
