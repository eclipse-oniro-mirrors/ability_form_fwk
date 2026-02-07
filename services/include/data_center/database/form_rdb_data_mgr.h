/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include <shared_mutex>
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
struct FormRdbTableConfig {
    std::string tableName { Constants::FORM_RDB_TABLE_NAME };
    std::string createTableSql;
};
class RdbStoreDataCallBackFormInfoStorage : public NativeRdb::RdbOpenCallback {
public:
    RdbStoreDataCallBackFormInfoStorage(const std::string &rdbPath);

    virtual ~RdbStoreDataCallBackFormInfoStorage();

    int32_t OnCreate(NativeRdb::RdbStore &rdbStore) override;

    int32_t OnUpgrade(NativeRdb::RdbStore &rdbStore, int32_t oldVersion, int32_t newVersion) override;

    int32_t OnDowngrade(NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion) override;

    int32_t OnOpen(NativeRdb::RdbStore &rdbStore) override;

    int32_t onCorruption(std::string databaseFile) override;

private:
    std::string rdbPath_;
};

/**
 * @class FormRdbDataMgr
 * Form Rdb Data Manager.
 */
class FormRdbDataMgr final : public DelayedRefSingleton<FormRdbDataMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormRdbDataMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormRdbDataMgr);

    ErrCode InitFormRdbTable(const FormRdbTableConfig &formRdbTableConfig);

    /**
     * @brief Insert the form data in DB.
     * @param tableName The name of table to be inserted
     * @param key The data's Key.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode InsertData(const std::string &tableName, const std::string &key);

    /**
     * @brief Insert the form data in DB.
     * @param tableName The name of table to be inserted
     * @param key The data's key.
     * @param value the data's value
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode InsertData(const std::string &tableName, const std::string &key, const std::string &value);

    /**
     * @brief Delete the form data in DB.
     * @param tableName The name of table to be excute deleted action.
     * @param key The data's Key.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteData(const std::string &tableName, const std::string &key);

    /**
     * @brief Query the form data in DB.
     * @param tableName The name of table to be query.
     * @param key The data's Key.
     * @param values The map of data's values
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QueryData(const std::string &tableName, const std::string &key,
        std::unordered_map<std::string, std::string> &values);

    /**
     * @brief Query all the form data in DB.
     * @param tableName The name of table to be query.
     * @param datas The map of data's values
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QueryAllData(const std::string &tableName, std::unordered_map<std::string, std::string> &datas);

    /**
     * @brief Query all key in DB.
     * @param tableName The name of table to be query.
     * @param datas All keys of data
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QueryAllKeys(const std::string &tableName, std::set<std::string> &datas);

    /**
     * @brief Excute sql in DB.
     * @param sql The sql to be excute.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode ExecuteSql(const std::string &sql);

    /**
     * @brief Query data in DB.
     * @param tableName The name of table to be query.
     * @param key The data's Key.
     * @param value The data's value.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode QueryData(const std::string &tableName, const std::string &key, std::string &value);

    /**
     * @brief Query data in DB.
     * @param absRdbPredicates The rdb's predicates to be query.
     * @return Returns query result.
     */
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QueryData(const NativeRdb::AbsRdbPredicates &absRdbPredicates);

    /**
     * @brief Query data in DB for data over 2M.
     * @param absRdbPredicates The rdb's predicates to be query.
     * @return Returns query result.
     */
    std::shared_ptr<NativeRdb::ResultSet> QueryDataByStep(const NativeRdb::AbsRdbPredicates &absRdbPredicates);

    /**
     * @brief Query data in DB.
     * @param sql The sql to be query.
     * @return Returns query result.
     */
    std::shared_ptr<NativeRdb::AbsSharedResultSet> QuerySql(const std::string &sql);

    /**
     * @brief Insert data in DB.
     * @param tableName The name of table to be insert.
     * @param valuesBucket The bucket of values.
     * @param rowId Row's id.
     * @return Returns true for success, false for failure.
     */
    bool InsertData(
        const std::string &tableName, const NativeRdb::ValuesBucket &valuesBucket, int64_t &rowId);

    /**
     * @brief Delete data in DB.
     * @param absRdbPredicates The rdb's predicates to be delete.
     * @return Returns true for success, false for failure.
     */
    bool DeleteData(const NativeRdb::AbsRdbPredicates &absRdbPredicates);

private:
    ErrCode CheckAndRebuildRdbStore(int32_t rdbOperateRet);

    std::shared_ptr<NativeRdb::RdbStore> LoadRdbStore();

    std::shared_ptr<NativeRdb::RdbStore> GetRdbStore();

    void SetFormRdbTableCfg(const FormRdbTableConfig &formRdbTableCfg);

    bool CheckFormRdbTable(const std::string &tableName);

    void CreateFormRdbTables();

    std::map<std::string, FormRdbTableConfig> formRdbTableCfgMap_;
    std::shared_ptr<NativeRdb::RdbStore> rdbStore_;
    std::shared_mutex rdbStoreMutex_;
    std::shared_mutex formRdbTableCfgMapMutex_;
    int64_t lastRdbBuildTime_ = 0;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_RDB_DATA_MGR_H
