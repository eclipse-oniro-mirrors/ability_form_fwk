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
#include "device_manager.h"
#include "event_handler.h"
#include "form_distributed_client.h"
#include "form_free_install_operator.h"
#include "form_item_info.h"
#include "form_share_info.h"

namespace OHOS {
namespace AppExecFwk {
using WantParams = OHOS::AAFwk::WantParams;
/**
 * @class FormShareMgr
 * Form share manager.
 */
class FormShareMgr final : public DelayedRefSingleton<FormShareMgr> {
private:
    DECLARE_DELAYED_REF_SINGLETON(FormShareMgr);
public:
    DISALLOW_COPY_AND_MOVE(FormShareMgr);

    void SetEventHandler(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
    {
        if (eventHandler_ == nullptr) {
            eventHandler_ = handler;
        }
    }

    /**
     * @brief Share forms by formID and deviceID.
     * @param formId Indicates the unique id of form.
     * @param deviceId Indicates the device ID to share.
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
    int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info);
    /**
     * @brief Acquire share form data from form provider.
     * @param formId The Id of the from.
     * @param remoteDeviceId The device ID to share.
     * @param want Indicates the want containing information about sharing information and sharing data.
     * @param remoteObject Form provider proxy object.
     */
    void AcquireProviderShareData(int64_t formId, const std::string &remoteDeviceId, const Want &want,
        const sptr<IRemoteObject> &remoteObject);
    void HandleProviderShareData(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result);
    bool AddProviderData(const FormItemInfo &info, WantParams &wantParams);
    void HandleFormShareInfoTimeout(int64_t eventId);
    void HandleFreeInstallTimeout(int64_t eventId);
    /**
     * @brief Free install was finished.
     * @param FormFreeInstallOperator Indicates the free install operator object.
     * @param resultCode Indicates the free install results.
     * @param formShareInfoKey Indicates the form share info key.
     */
    void OnInstallFinished(const std::shared_ptr<FormFreeInstallOperator> &freeInstallOperator,
        int32_t resultCode, const std::string &formShareInfoKey);
    void SendResponse(int64_t requestCode, int32_t result);
private:
    int32_t GetLocalDeviceInfo(const std::string &bundleName, DistributedHardware::DmDeviceInfo &deviceInfo);
    std::string MakeFormShareInfoKey(const FormItemInfo &info);
    std::string MakeFormShareInfoKey(const FormShareInfo &info);
    void RemoveFormShareInfo(const std::string &formShareInfoKey);
    void FinishFreeInstallTask(const std::shared_ptr<FormFreeInstallOperator> &freeInstallOperator);
    bool IsExistFormPackage(const std::string &bundleName, const std::string &moduleName);
    bool CheckFormShareInfo(const FormShareInfo &info);
    void StartFormUser(const FormShareInfo &info);
    int32_t HandleRecvFormShareInfoFromRemoteTask(const FormShareInfo &info);
    int32_t CheckFormPackage(const FormShareInfo &info, const std::string &formShareInfoKey);
    bool GetAbilityInfoByAction(const std::string action, AppExecFwk::AbilityInfo &abilityInfo,
        AppExecFwk::ExtensionAbilityInfo &extensionAbilityInfo);
private:
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_ = nullptr;
    std::shared_ptr<FormDistributedClient> formDmsClient_ = nullptr;
    // map for <formShareInfoKey, FormShareInfo>
    std::map<std::string, FormShareInfo> shareInfo_;
    // map for <eventId, formShareInfoKey>
    std::map<int64_t, std::string> eventMap_;
    // map for <eventId, std::shared_ptr<FormFreeInstallOperator>>
    std::map<int64_t, std::shared_ptr<FormFreeInstallOperator>> freeInstallOperatorMap_;
    // map for <requestCode, formHostClient>
    std::map<int64_t, sptr<IRemoteObject>> requestMap_;
    mutable std::shared_mutex mapMutex_ {};
};

class MyDmInitCallback final : public OHOS::DistributedHardware::DmInitCallback {
    void OnRemoteDied() override
    {}
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_SHARE_MGR_H
