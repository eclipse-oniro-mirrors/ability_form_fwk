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

#ifndef OHOS_FORM_FWK_FORM_OBSERVER_RECORD_H
#define OHOS_FORM_FWK_FORM_OBSERVER_RECORD_H

#include <map>
#include <singleton.h>
#include <vector>

#include "fms_log_wrapper.h"
#include "iremote_object.h"
#include "running_form_info.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormObserverRecord
 * Form observer record.
 */
class FormObserverRecord : public DelayedRefSingleton<FormObserverRecord> {
public:
    /**
     * @brief Set value of deathRecipient_.
     * @param callerToken Caller ability token.
     * @param deathRecipient DeathRecipient object.
     */
    void SetDeathRecipient(const sptr<IRemoteObject> &callerToken,
        const sptr<IRemoteObject::DeathRecipient> &deathRecipient);

    /**
     * @brief set form add observer.
     * @param bundleName BundleName of the form host.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK if this function is successfully called; returns others failed.
     */
    ErrCode SetFormAddObserver(const std::string bundleName, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief set form remove observer.
     * @param bundleName BundleName of the form host.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK if this function is successfully called; returns others failed.
     */
    ErrCode SetFormRemoveObserver(const std::string bundleName, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief send form add message to form observer.
     * @param bundleName BundleName of the form host.
     */
    void onFormAdd(const std::string bundleName, RunningFormInfo &runningFormInfo);

    /**
     * @brief send form remove message to form observer.
     * @param bundleName BundleName of the form host.
     */
    void onFormRemove(const std::string bundleName, const RunningFormInfo runningFormInfo);

    /**
     * @brief when form observer died clean the resource.
     * @param remote remote object.
     */
    void CleanResource(const wptr<IRemoteObject> &remote);

private:
    mutable std::mutex formAddObserverMutex_;
    mutable std::mutex formRemoveObserverMutex_;
    mutable std::mutex deathRecipientsMutex_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> formAddObservers_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> formRemoveObservers_;
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

#endif // OHOS_FORM_FWK_FORM_OBSERVER_RECORD_H
