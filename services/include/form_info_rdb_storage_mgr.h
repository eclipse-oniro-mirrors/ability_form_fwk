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

#ifndef OHOS_FORM_FWK_FORM_INFO_RDB_STORAGE_MGR_H
#define OHOS_FORM_FWK_FORM_INFO_RDB_STORAGE_MGR_H

#include <singleton.h>
#include <string>
#include "form_db_info.h"
#include "form_rdb_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormInfoRdbStorageMgr
 * Form info storage.
 */
class FormInfoRdbStorageMgr final : public DelayedRefSingleton<FormInfoRdbStorageMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormInfoRdbStorageMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormInfoRdbStorageMgr);

    /**
     * @brief Load all form info from DB to formInfoStorages.
     * @param formInfoStorages Storage all form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode LoadFormInfos(std::vector<std::pair<std::string, std::string>> &formInfoStorages);

    /**
     * @brief Delete the form info in DB.
     * @param bundleName The form info bundleName.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode RemoveBundleFormInfos(const std::string &bundleName);

    /**
     * @brief Save or update the form info in DB.
     * @param bundleName The form info bundleName @param formInfoStorages The form info.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateBundleFormInfos(const std::string &bundleName, const std::string &formInfoStorages);

    /**
     * @brief Load all form data from DB to innerFormInfos.
     * @param innerFormInfos Storage all form data.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode LoadFormData(std::vector<InnerFormInfo> &innerFormInfos);

    /**
     * @brief Save or update the form data in DB.
     * @param innerFormInfo Indicates the InnerFormInfo object to be save.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SaveStorageFormData(const InnerFormInfo &innerFormInfo);

    /**
     * @brief Modify the form data in DB.
     * @param innerFormInfo Indicates the InnerFormInfo object to be Modify.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ModifyStorageFormData(const InnerFormInfo &innerFormInfo);

    /**
     * @brief Delete the form data in DB.
     * @param formId The form data Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteStorageFormData(const std::string &formId);

private:
    void SaveEntries(const std::unordered_map<std::string, std::string> &value, std::vector<InnerFormInfo> &innerFormInfos);
    bool CheckRdbStore();
    std::shared_ptr<FormRdbDataMgr> rdbDataManager_;
    mutable std::mutex rdbStorePtrMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_INFO_RDB_STORAGE_MGR_H
