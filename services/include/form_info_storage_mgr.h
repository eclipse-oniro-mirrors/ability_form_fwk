/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_INFO_STORAGE_MGR_H
#define OHOS_FORM_FWK_FORM_INFO_STORAGE_MGR_H

#include <singleton.h>
#include <string>
#include "distributed_kv_data_manager.h"
#include "form_db_info.h"
#include "kvstore_death_recipient.h"

namespace OHOS {
namespace AppExecFwk {
class KvStoreDeathRecipientCallbackFormInfoStorage : public DistributedKv::KvStoreDeathRecipient {
public:
    KvStoreDeathRecipientCallbackFormInfoStorage();

    virtual ~KvStoreDeathRecipientCallbackFormInfoStorage();

    virtual void OnRemoteDied() override;
};

/**
 * @class FormInfoStorageMgr
 * Form info storage.
 */
class FormInfoStorageMgr final : public DelayedRefSingleton<FormInfoStorageMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormInfoStorageMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormInfoStorageMgr);

    ErrCode LoadFormInfos(std::vector<std::pair<std::string, std::string>> &formInfoStorages);

    ErrCode RemoveBundleFormInfos(const std::string &bundleName);

    ErrCode UpdateBundleFormInfos(const std::string &bundleName, const std::string &formInfoStorages);

    bool ResetKvStore();

    /**
     * @brief Load all form data from DB to innerFormInfos.
     * @param innerFormInfos Storage all form data.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode LoadFormData(std::vector<InnerFormInfo> &innerFormInfos);

    /**
     * @brief Get form data from DB to innerFormInfo with formId.
     * @param formId Indicates the form ID.
     * @param innerFormInfo Storage form data.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetStorageFormInfoById(const std::string &formId, InnerFormInfo &innerFormInfo);

    /**
     * @brief Save or update the form data in DB.
     * @param innerFormInfo Indicates the InnerFormInfo object to be save.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SaveStorageFormInfo(const InnerFormInfo &innerFormInfo);

    /**
     * @brief Modify the form data in DB.
     * @param innerFormInfo Indicates the InnerFormInfo object to be Modify.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ModifyStorageFormInfo(const InnerFormInfo &innerFormInfo);

    /**
     * @brief Delete the form data in DB.
     * @param formId The form data Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteStorageFormInfo(const std::string &formId);

private:
    void RegisterKvStoreDeathListener();
    DistributedKv::Status GetKvStore();
    bool CheckKvStore();
    DistributedKv::Status GetEntries(const std::string &keyPrefix, std::vector<DistributedKv::Entry> &allEntries);
    void SaveEntries(const std::vector<DistributedKv::Entry> &allEntries, std::vector<InnerFormInfo> &innerFormInfos);
    void TryTwice(const std::function<DistributedKv::Status()> &func);

    const DistributedKv::AppId appId_ {"form_storage"};
    const DistributedKv::StoreId storeId_ {"form_infos"};
    DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
    mutable std::mutex kvStorePtrMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_INFO_STORAGE_MGR_H
