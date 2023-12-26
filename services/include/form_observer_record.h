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
enum class FormEventId {
    FORM_EVENT_NON,
    FORM_EVENT_CALL,
    FORM_EVENT_MESSAGE,
    FORM_EVENT_ROUTER,
    FORM_EVENT_FORM_ADD,
    FORM_EVENT_FORM_REMOVE
};

class FormObserverRecordInner final {
public:
    FormObserverRecordInner(const sptr<IRemoteObject> &remote) : remote_(remote) {}
    ~FormObserverRecordInner() {}
    bool IsFollowEvents(FormEventId type) const;
    void PushEvent(FormEventId type);
    void RemoveEvent(FormEventId type);

    sptr<IRemoteObject> GetRemote() const
    {
        return remote_;
    };

    bool NonFollowEvents()
    {
        return eventGroup_.empty();
    }

    std::string BindHostBundle() const
    {
        return bindHostBundle;
    }

    void SetBindHostBundle(const std::string &hostBundleName)
    {
        bindHostBundle = hostBundleName;
    }

    bool operator==(const FormObserverRecordInner &other)
    {
        return (remote_ == other.GetRemote() && bindHostBundle == other.BindHostBundle());
    }
private:
    std::string bindHostBundle;
    sptr<IRemoteObject> remote_ {nullptr};
    std::vector<FormEventId> eventGroup_;
};

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

    /**
     * @brief Notify form event.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param runningFormInfo Current form data.
     * @return Returns ERR_OK on success, others on failure.
     */
    void HandleFormEvent(
        const std::string &bundleName, const std::string &formEventType, RunningFormInfo &runningFormInfo);

    /**
     * @brief Register form event callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SetFormEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Remove form event callback observer.
     * @param bundleName BundleName of the form host.
     * @param formEventType Form event type.
     * @param callerToken Caller ability token.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RemoveFormEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &callerToken);

private:
    FormEventId ConvertToFormEventId(const std::string &formEventType);

    void NotifyFormEvent(
        const FormObserverRecordInner &recordInner, FormEventId formEventId, RunningFormInfo &runningFormInfo,
        const std::string &formEventType);

    ErrCode SetFormEventObserverLocked(
        const std::string &bundleName, FormEventId formEventType, const sptr<IRemoteObject> &callerToken);

    ErrCode RemoveFormEventObserverLocked(
        const std::string &bundleName, FormEventId formEventType, const sptr<IRemoteObject> &callerToken);

    void ClearDeathRemoteObserver(const wptr<IRemoteObject> &remote);

private:
    mutable std::mutex formAddObserverMutex_;
    mutable std::mutex formRemoveObserverMutex_;
    mutable std::mutex deathRecipientsMutex_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> formAddObservers_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> formRemoveObservers_;
    std::map<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> deathRecipients_;
    mutable std::mutex formEventObserversMutex_;
    std::unordered_map<std::string, std::vector<FormObserverRecordInner>> formEventObservers_;

    const std::unordered_map<std::string, FormEventId> formEventMap = {
        {"call", FormEventId::FORM_EVENT_CALL},
        {"message", FormEventId::FORM_EVENT_MESSAGE},
        {"router", FormEventId::FORM_EVENT_ROUTER},
        {"formAdd", FormEventId::FORM_EVENT_FORM_ADD},
        {"formRemove", FormEventId::FORM_EVENT_FORM_REMOVE},
    };

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
