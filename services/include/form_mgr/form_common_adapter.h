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

#ifndef OHOS_FORM_FWK_FORM_COMMON_ADAPTER_H
#define OHOS_FORM_FWK_FORM_COMMON_ADAPTER_H

#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <singleton.h>
#include "app_mgr_interface.h"
#include "bundle_info.h"
#include "form_info.h"
#include "hap_module_info.h"
#include "iremote_object.h"
#include "ipc_skeleton.h"
#include "want.h"

#include "form_constants.h"
#include "form_major_info.h"
#include "form_mgr_errors.h"
#include "form_provider_data.h"
#include "fms_log_wrapper.h"
#include "common/util/form_util.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_info/form_info_mgr.h"
#include "data_center/form_info/form_item_info.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
enum class AddFormResultErrorCodes : int8_t {
    UNKNOWN = 0,
    SUCCESS,
    FAILED,
    TIMEOUT
};

/**
 * @class FormCommonAdapter
 * @brief Shared adapter class that provides shared functionality and data across all sub-adapters
 * 
 * This class is used by other adapters through **member variable composition** instead of inheritance
 * This design is more flexible and avoids deep class hierarchies
 */
class FormCommonAdapter  final : public DelayedRefSingleton<FormCommonAdapter> {
DECLARE_DELAYED_REF_SINGLETON(FormCommonAdapter)
public:
    /**
     * @brief Get form config info
     * @param want The want of the request
     * @param formItemInfo Form config info
     * @return Returns ERR_OK on success, others on failure
     */
    virtual ErrCode GetFormConfigInfo(const Want& want, FormItemInfo &formItemInfo);

    /**
     * @brief Get bundle info
     * @param want The want of the request
     * @param bundleInfo Bundle info
     * @param packageName Package name
     * @return Returns ERR_OK on success, others on failure
     */
    virtual ErrCode GetBundleInfo(const AAFwk::Want &want, BundleInfo &bundleInfo, std::string &packageName);

    /**
     * @brief Get form info
     * @param want The want of the request
     * @param formInfo Form info
     * @return Returns ERR_OK on success, others on failure
     */
    virtual ErrCode GetFormInfo(const AAFwk::Want &want, FormInfo &formInfo);

    /**
     * @brief Create form item info
     * @param bundleInfo Bundle info
     * @param formInfo Form info
     * @param itemInfo Form item info
     * @return Returns ERR_OK on success, others on failure
     */
    virtual ErrCode CreateFormItemInfo(const BundleInfo& bundleInfo, const FormInfo& formInfo, FormItemInfo& itemInfo);

    /**
     * @brief Get form item info
     * @param want The want of request
     * @param bundleInfo Bundle info
     * @param formInfo Form info
     * @param formItemInfo Form item info
     * @return Returns ERR_OK on success, others on failure
     */
    virtual ErrCode GetFormItemInfo(const AAFwk::Want &want, const BundleInfo &bundleInfo,
                                   const FormInfo &formInfo, FormItemInfo &formItemInfo);

    /**
     * @brief Set form item info params
     * @param bundleInfo Bundle info
     * @param formInfo Form info
     * @param itemInfo Form item info
     */
    virtual void SetFormItemInfoParams(const BundleInfo& bundleInfo, const FormInfo& formInfo, FormItemInfo& itemInfo);

    /**
     * @brief Set form item module info
     * @param hapModuleInfo Hap module info
     * @param formInfo Form info
     * @param itemInfo Form item info
     */
    virtual void SetFormItemModuleInfo(const HapModuleInfo& hapModuleInfo, const FormInfo& formInfo, FormItemInfo& itemInfo);

    /**
     * @brief Set host bundle name
     * @param want The want of the request
     * @param itemInfo Form item info
     * @return Returns ERR_OK on success, others on failure
     */
    virtual ErrCode SetHostBundleName(const AAFwk::Want &want, FormItemInfo &itemInfo);

    /**
     * @brief Validate dimension
     * @param formInfo Form info
     * @param dimensionId Dimension id
     * @return Returns true on success, false on failure
     */
    virtual bool IsDimensionValid(const FormInfo &formInfo, int dimensionId) const;

    /**
     * @brief Get form info by record
     * @param record The record of the form
     * @param formInfo Form info
     * @return Returns ERR_OK on success, others on failure
     */
    virtual ErrCode GetFormInfoByFormRecord(const FormRecord &record, FormInfo &formInfo);

    /**
     * @brief Register add observer
     * @param bundleName BundleName of the form host
     * @param callerToken Caller ability token
     * @return Returns ERR_OK on success, others on failure
     */
    virtual ErrCode RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Register remove observer
     * @ @param bundleName BundleName of the form host
     * @param callerToken Caller ability token
     * @return Returns ERR_OK on success, others on failure
     */
    virtual ErrCode RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken);

    /**
     * @brief Clean resource
     * @param remote remote object
     */
    virtual void CleanResource(const wptr<IRemoteObject> &remote);

    /**
     * @brief Set death recipient
     * @param callerToken Caller ability token
     * @param deathRecipient DeathRecipient object
     */
    virtual void SetDeathRecipient(const sptr<IRemoteObject> &callerToken,
                               const sptr<IRemoteObject::DeathRecipient> &deathRecipient);

    /**
     * @brief Get caller type
     * @param bundleName caller's bundle name
     */
    virtual int32_t GetCallerType(std::string bundleName);

    /**
     * @brief Get calling user ID
     * @return Returns user ID
     */
    virtual int32_t GetCallingUserId();

    /**
     * @brief Get application manager service proxy
     * @return Returns IAppMgr proxy on success, nullptr on failure
     */
    virtual sptr<OHOS::AppExecFwk::IAppMgr> GetAppMgr();

    void SetFormEnableAndLockState(FormInfo &formInfo, FormItemInfo &formConfigInfo, int formLocation);

    void SetLockFormStateOfFormItemInfo(FormInfo &formInfo, FormItemInfo &formConfigInfo);

    /**
     * @brief Check update form record
     * @param formId Form id
     * @param info Form item info
     * @param record Form record
     */
    void CheckUpdateFormRecord(const int64_t formId, const FormItemInfo &info, FormRecord &record);

    /**
     * @brief Check form due control
     * @param formMajorInfo Form major info
     * @param isDisablePolicy Is disable policy
     * @return Returns ERR_OK if no control, ERR_APPEXECFWK_FORM_DUE_REMOVE if due control
     */
    ErrCode CheckFormDueControl(const FormMajorInfo &formMajorInfo, const bool isDisablePolicy);

    /**
     * @brief Handle form add observer
     * @param formId Form id
     * @return Returns ERR_OK on success, others on failure
     */
    ErrCode HandleFormAddObserver(const int64_t formId);

    /**
     * @brief Add form timer
     * @param formRecord Form record
     * @return Returns ERR_OK on success, others on failure
     */
    ErrCode AddFormTimer(const FormRecord &formRecord);

    /**
     * @brief Get valid form update duration
     * @param formId Form id
     * @param updateDuration Update duration output
     * @return Returns true on success, false on failure
     */
    bool GetValidFormUpdateDuration(const int64_t formId, int64_t &updateDuration) const;

    /**
     * @brief Update form cloud update duration
     * @param bundleName Bundle name
     */
    void UpdateFormCloudUpdateDuration(const std::string &bundleName);

protected:
    /**
     * @brief Client death notification recipient
     * @class ClientDeathRecipient
     * @brief notices IRemoteBroker died.
     */
    class ClientDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        ClientDeathRecipient() = default;
        virtual ~ClientDeathRecipient() = default;
        /**
         * @brief Handle remote object died event
         * @param remote remote object
         */
        void OnRemoteDied(const wptr<IRemoteObject> &remote) override;
    };

    // Core service pointers
    FormDataMgr* formDataMgr_;
    FormInfoMgr* formInfoMgr_;

    // Observer related member variables
    mutable std::mutex formObserversMutex_;
    mutable std::mutex deathRecipientsMutex_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> formObservers_;
    std::map<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> deathRecipients_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_COMMON_ADAPTER_H
