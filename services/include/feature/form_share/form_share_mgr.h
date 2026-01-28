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

#ifndef FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_MGR_H
#define FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_MGR_H

#include <map>
#include <shared_mutex>
#include <singleton.h>
#include "ability_info.h"
#include "fms_log_wrapper.h"
#include "feature/form_share/form_distributed_client.h"
#include "common/event/form_event_handler.h"
#include "feature/form_share/form_free_install_operator.h"
#include "data_center/form_info/form_item_info.h"
#include "common/util/form_serial_queue.h"
#include "form_share_info.h"

namespace OHOS {
namespace AppExecFwk {
using WantParams = OHOS::AAFwk::WantParams;
/**
 * @class FormShareMgr
 * Form share manager.
 */
class FormShareMgr final : public std::enable_shared_from_this<FormShareMgr>,
                           public FormEventTimeoutObserver {
public:
    DISALLOW_COPY_AND_MOVE(FormShareMgr);

    void SetEventHandler(const std::shared_ptr<FormEventHandler> &handler)
    {
        if (eventHandler_ != nullptr || handler == nullptr) {
            return;
        }
        eventHandler_ = handler;
        eventHandler_->RegisterEventTimeoutObserver(shared_from_this());
    }

    void SetSerialQueue(const std::shared_ptr<FormSerialQueue> &serialQueue)
    {
        if (serialQueue == nullptr) {
            return;
        }
        serialQueue_ = serialQueue;
    }

    /**
     * @brief Share form by formID and deviceID.
     * @param formId Indicates the unique id of form.
     * @param deviceId Indicates the remote device ID.
     * @param callerToken Indicates the host client.
     * @param requestCode The request code of this share form.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t ShareForm(int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken,
        int64_t requestCode);

    /**
     * @brief Receive form sharing information from remote.
     * @param info Indicates form sharing information.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info, const int32_t userId);

    /**
     * @brief Acquire share form data from form provider.
     * @param formId The Id of the from.
     * @param remoteDeviceId Indicates the remote device ID.
     * @param want Indicates the want containing information about sharing information and sharing data.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId, const Want &want,
        const sptr<IRemoteObject> &remoteObject);

    /**
     * @brief Handle data shared by provider.
     * @param formId The Id of the from.
     * @param remoteDeviceId Indicates the remote device ID.
     * @param wantParams Indicates the data shared by the provider.
     * @param requestCode The request code of this share form.
     * @param result Indicates the result of parsing the shared data.
     */
    void HandleProviderShareData(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result);

    /**
     * @brief Add provider data.
     * @param want The want of the form to add.
     * @param wantParams WantParams of the request.
     */
    void AddProviderData(const Want &want, WantParams &wantParams);

    /**
     * @brief Handle form share timeout.
     * @param eventId Event id.
     */
    void HandleFormShareInfoTimeout(int64_t eventId);

    /**
     * @brief Handle free install timeout.
     * @param eventId Event id.
     */
    void HandleFreeInstallTimeout(int64_t eventId);

    /**
     * @brief Free install was finished.
     * @param FormFreeInstallOperator Indicates the free install operator object.
     * @param resultCode Indicates the free install results.
     * @param formShareInfoKey Indicates the form share info key.
     */
    void OnInstallFinished(const std::shared_ptr<FormFreeInstallOperator> &freeInstallOperator,
        int32_t resultCode, const std::string &formShareInfoKey, const int32_t userId);

    /**
     * @brief Send form to share asyn result.
     * @param requestCode The request code of this share form.
     * @param result Indicates form to share asyn result.
     */
    void SendResponse(int64_t requestCode, int32_t result);

    /**
     * @brief Whether the added form is a share form.
     * @param want The want of the form to add.
     * @return Returns true is a shared form, false is not.
     */
    bool IsShareForm(const Want &want);
private:
    std::string MakeFormShareInfoKey(const FormShareInfo &info);
    std::string MakeFormShareInfoKey(const Want &want);
    void RemoveFormShareInfo(const std::string &formShareInfoKey);
    void FinishFreeInstallTask(const std::shared_ptr<FormFreeInstallOperator> &freeInstallOperator);
    bool IsExistFormPackage(const std::string &bundleName, const std::string &moduleName, const int32_t userId);
    bool CheckFormShareInfo(const FormShareInfo &info);
    void StartFormUser(const FormShareInfo &info, const int32_t userId);
    int32_t HandleRecvFormShareInfoFromRemoteTask(const FormShareInfo &info, const int32_t userId);
    int32_t CheckFormPackage(const FormShareInfo &info, const std::string &formShareInfoKey, const int32_t userId);
    void OnEventTimeoutResponse(int64_t msg, int64_t eventId) override;
private:
    DECLARE_DELAYED_SINGLETON(FormShareMgr);
    std::shared_ptr<FormEventHandler> eventHandler_ = nullptr;
    std::unique_ptr<FormDistributedClient> formDmsClient_ = nullptr;
    // map for <formShareInfoKey, FormShareInfo>
    std::map<std::string, FormShareInfo> shareInfo_;
    // map for <eventId, formShareInfoKey>
    std::map<int64_t, std::string> eventMap_;
    // map for <eventId, std::shared_ptr<FormFreeInstallOperator>>
    std::map<int64_t, std::shared_ptr<FormFreeInstallOperator>> freeInstallOperatorMap_;
    // map for <requestCode, formHostClient>
    std::map<int64_t, sptr<IRemoteObject>> requestMap_;
    mutable std::shared_mutex shareInfoMapMutex_ {};
    mutable std::shared_mutex eventMapMutex_ {};
    mutable std::shared_mutex freeInstallMapMutex_ {};
    mutable std::shared_mutex requestMapMutex_ {};
    std::shared_ptr<FormSerialQueue> serialQueue_ = nullptr;
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_MGR_H
