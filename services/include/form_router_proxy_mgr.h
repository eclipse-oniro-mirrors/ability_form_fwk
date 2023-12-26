/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#ifndef OHOS_FORM_FWK_FORM_ROUTER_PROXY_MGR_H
#define OHOS_FORM_FWK_FORM_ROUTER_PROXY_MGR_H

#include <singleton.h>
#include <vector>

#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
/**
 * @class FormRouterProxyMgr
 * Form router proxy manager.
 */
class FormRouterProxyMgr : public DelayedRefSingleton<FormRouterProxyMgr> {
public:

    /**
     * @brief Set value of router proxies.
     * @param formIds the form ids of Router proxy.
     * @param callerToken Router proxy caller token.
     */
    ErrCode SetFormRouterProxy(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Remove value of router proxies.
     * @param formIds the form ids of Router proxy.
     */
    ErrCode RemoveFormRouterProxy(const std::vector<int64_t> &formIds);

    /**
     * @brief Get the router proxy of the current form id.
     * @param formId the form id of router proxy.
     */
    bool HasRouterProxy(int64_t formId);

    /**
     * @brief Trigger the router event info of this form id.
     * @param formId the form id of router proxy.
     * @param want the want info for router event.
     */
    void OnFormRouterEvent(int64_t formId, const Want &want);

    /**
     * @brief when form proxy died clean the resource.
     * @param remote remote object.
     */
    void CleanResource(const wptr<IRemoteObject> &remote);

private:
    /**
     * @brief Set value of deathRecipient_.
     * @param callerToken Caller ability token.
     * @param deathRecipient DeathRecipient object.
     */
    void SetDeathRecipient(const sptr<IRemoteObject> &callerToken,
        const sptr<IRemoteObject::DeathRecipient> &deathRecipient);

    mutable std::mutex formRouterProxyMutex_;
    mutable std::mutex deathRecipientsMutex_;
    std::map<int64_t, sptr<IRemoteObject>> formRouterProxyMap_;
    std::map<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> deathRecipients_;

    /**
     * @class ClientDeathRecipient
     * notices IRemoteBroker died.
     */
    class ClientDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        /**
         * @brief Constructor
         */
        ClientDeathRecipient() = default;
        virtual ~ClientDeathRecipient() = default;
        /**
         * @brief handle remote object died event.
         * @param remote remote object.
         */
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_ROUTER_PROXY_MGR_H
