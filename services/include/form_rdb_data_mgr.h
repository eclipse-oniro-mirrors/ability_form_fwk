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

#ifndef OHOS_FORM_FWK_FORM_RDB_DATA_MGR_H
#define OHOS_FORM_FWK_FORM_RDB_DATA_MGR_H

#include <vector>
#include <unordered_map>
#include <singleton.h>
#include <string>
#include "form_constants.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_open_callback.h"
#include "rdb_store_config.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {
struct FormRdbConfig {
    std::string dbPath { Constants::FORM_MANAGER_SERVICE_PATH };
    std::string dbName { Constants::FORM_RDB_NAME };
    std::string tableName { Constants::FORM_RDB_TABLE_NAME };
    std::string journalMode { Constants::FORM_JOURNAL_MODE };
    std::string syncMode { Constants::FORM_SYNC_MODE };
    int32_t version { Constants::FORM_RDB_VERSION };
    std::string databaseFileType { Constants::FORM_RDB_FILE_TYPE };
};
class RdbStoreDataCallBackFormInfoStorage : public NativeRdb::RdbOpenCallback {
public:
    RdbStoreDataCallBackFormInfoStorage(const FormRdbConfig &formRdbConfig);

    virtual ~RdbStoreDataCallBackFormInfoStorage();

    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;

    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;

    int32_t OnDowngrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;

    int32_t OnOpen(NativeRdb::RdbStore &rdbStore) override;

    int32_t onCorruption(std::string databaseFile) override;
private:
    FormRdbConfig formRdbConfig_;
    bool hasTableInit_ = false;
};

/**
 * @class FormRdbDataMgr
 * Form Rdb Data Manager.
 */
class FormRdbDataMgr {
public:

    explicit FormRdbDataMgr(const FormRdbConfig &formRdbConfig);

    ErrCode Init();

    /**
     * @brief Insert the form data in DB.
     * @param key The data Key.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode InsertData(const std::string &key, const std::string &value);

    /**
     * @brief Delete the form data in DB.
     * @param key The data Key.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteData(const std::string &key);

    /**
     * @brief Query the form data in DB.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QueryData(const std::string &key, std::unordered_map<std::string, std::string> &values);

    /**
     * @brief Query all the form data in DB.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QueryAllData(std::unordered_map<std::string, std::string> &values);

private:
    FormRdbConfig formRdbConfig_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_RDB_DATA_MGR_H
