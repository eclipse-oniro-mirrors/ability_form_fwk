/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "data_center/database/form_rdb_data_mgr.h"

#include <cinttypes>
#include <thread>
#include <filesystem>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"
#include "common/util/scope_guard.h"
#include "form_event_report.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string FORM_KEY = "KEY";
const std::string FORM_VALUE = "VALUE";
const int32_t FORM_KEY_INDEX = 0;
const int32_t FORM_VALUE_INDEX = 1;
const int64_t MIN_FORM_RDB_REBUILD_INTERVAL = 10000; // 10s
} // namespace
RdbStoreDataCallBackFormInfoStorage::RdbStoreDataCallBackFormInfoStorage(const std::string &rdbPath)
    : rdbPath_(rdbPath)
{
    HILOG_DEBUG("Create rdb store callback instance");
}

RdbStoreDataCallBackFormInfoStorage::~RdbStoreDataCallBackFormInfoStorage()
{
    HILOG_DEBUG("Destroy rdb store callback instance");
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    HILOG_DEBUG("OnCreate");
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    HILOG_DEBUG("OnUpgrade currentVersion: %{plubic}d, targetVersion: %{plubic}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnDowngrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    HILOG_DEBUG("OnDowngrade  currentVersion: %{plubic}d, targetVersion: %{plubic}d",
        currentVersion, targetVersion);
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    HILOG_DEBUG("OnOpen");
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackFormInfoStorage::onCorruption(std::string databaseFile)
{
    FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
        static_cast<int64_t>(CallDbFailedErrorType::DATABASE_EXIT_ABNORMAL));
    return NativeRdb::E_OK;
}

FormRdbDataMgr::FormRdbDataMgr()
{
    HILOG_INFO("Create");
}

FormRdbDataMgr::~FormRdbDataMgr()
{
    HILOG_INFO("Destruct");
}

ErrCode FormRdbDataMgr::InitFormRdbTable(const FormRdbTableConfig &formRdbTableConfig)
{
    HILOG_INFO("Init");
    if (formRdbTableConfig.tableName.empty()) {
        HILOG_ERROR("empty FormRdbTableName");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto formRdbTableCfgIter = formRdbTableCfgMap_.find(formRdbTableConfig.tableName);
    if (formRdbTableCfgIter != formRdbTableCfgMap_.end()) {
        formRdbTableCfgMap_[formRdbTableConfig.tableName] = formRdbTableConfig;
    } else {
        formRdbTableCfgMap_.emplace(formRdbTableConfig.tableName, formRdbTableConfig);
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    std::string createTableSql = !formRdbTableConfig.createTableSql.empty() ? formRdbTableConfig.createTableSql
        : "CREATE TABLE IF NOT EXISTS " + formRdbTableConfig.tableName
            + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";

    int32_t ret = rdbStore->ExecuteSql(createTableSql);
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("Create rdb table failed, ret:%{public}" PRId32 "", ret);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    return ERR_OK;
}

ErrCode FormRdbDataMgr::ExecuteSql(const std::string &sql)
{
    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    int32_t ret = rdbStore->ExecuteSql(sql);
    if (ret == NativeRdb::E_OK) {
        if (rdbStore->IsSlaveDiffFromMaster()) {
            auto backupRet = rdbStore->Backup("");
            HILOG_WARN("rdb slave corrupt, backup from master, ret=%{public}" PRId32, backupRet);
        }
    } else {
        if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
            HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
            rdbStore = GetRdbStore();
            if (rdbStore == nullptr) {
                HILOG_ERROR("null FormInfoRdbStore");
                return ERR_APPEXECFWK_FORM_COMMON_CODE;
            }
            ret = rdbStore->ExecuteSql(sql);
        }
    }

    if (ret == NativeRdb::E_OK) {
        return ERR_OK;
    }

    HILOG_WARN("ExecuteSql failed, ret=%{public}" PRId32, ret);
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::InsertData(const std::string &tableName, const std::string &key)
{
    HILOG_DEBUG("InsertData start");
    if (formRdbTableCfgMap_.find(tableName) == formRdbTableCfgMap_.end()) {
        HILOG_ERROR("Form rdb hasn't initialized this table:%{public}s", tableName.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(FORM_KEY, key);
    int32_t ret = NativeRdb::E_OK;
    int64_t rowId = -1;
    ret = rdbStore->InsertWithConflictResolution(rowId, tableName, valuesBucket,
            NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    if (ret == NativeRdb::E_OK) {
        if (rdbStore->IsSlaveDiffFromMaster()) {
            auto backupRet = rdbStore->Backup("");
            HILOG_WARN("rdb slave corrupt, backup from master, ret=%{public}" PRId32, backupRet);
        }
    } else {
        if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
            HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
            int64_t rowId = -1;
            rdbStore = GetRdbStore();
            if (rdbStore == nullptr) {
                HILOG_ERROR("null FormInfoRdbStore");
                return ERR_APPEXECFWK_FORM_COMMON_CODE;
            }
            ret = rdbStore->InsertWithConflictResolution(rowId, tableName, valuesBucket,
                NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
        }
    }

    if (ret == NativeRdb::E_OK) {
        return ERR_OK;
    }
    HILOG_WARN("Insert operation failed, key=%{public}s, ret=%{public}" PRId32, key.c_str(), ret);
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::InsertData(const std::string &tableName, const std::string &key, const std::string &value)
{
    HILOG_DEBUG("InsertData start");
    if (formRdbTableCfgMap_.find(tableName) == formRdbTableCfgMap_.end()) {
        HILOG_ERROR("Form rdb hasn't initialized this table:%{public}s", tableName.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(FORM_KEY, key);
    valuesBucket.PutString(FORM_VALUE, value);
    int32_t ret = NativeRdb::E_OK;
    int64_t rowId = -1;
    ret = rdbStore->InsertWithConflictResolution(rowId, tableName, valuesBucket,
        NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    if (ret == NativeRdb::E_OK) {
        if (rdbStore->IsSlaveDiffFromMaster()) {
            auto backupRet = rdbStore->Backup("");
            HILOG_WARN("rdb slave corrupt, backup from master, ret=%{public}" PRId32, backupRet);
        }
    } else {
        if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
            HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
            int64_t rowId = -1;
            rdbStore = GetRdbStore();
            if (rdbStore == nullptr) {
                HILOG_ERROR("null FormInfoRdbStore");
                return ERR_APPEXECFWK_FORM_COMMON_CODE;
            }
            ret = rdbStore->InsertWithConflictResolution(rowId, tableName, valuesBucket,
                NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
        }
    }

    if (ret == NativeRdb::E_OK) {
        return ERR_OK;
    }

    HILOG_WARN("Insert operation failed, key=%{public}s, ret=%{public}" PRId32, key.c_str(), ret);
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::DeleteData(const std::string &tableName, const std::string &key)
{
    HILOG_DEBUG("DeleteData start");
    if (formRdbTableCfgMap_.find(tableName) == formRdbTableCfgMap_.end()) {
        HILOG_ERROR("Form rdb hasn't initialized this table:%{public}s", tableName.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    absRdbPredicates.EqualTo(FORM_KEY, key);
    int32_t ret = NativeRdb::E_OK;
    int32_t rowId = -1;
    ret = rdbStore->Delete(rowId, absRdbPredicates);

    if (ret == NativeRdb::E_OK) {
        if (rdbStore->IsSlaveDiffFromMaster()) {
            auto backupRet = rdbStore->Backup("");
            HILOG_WARN("rdb slave corrupt, backup from master, ret=%{public}" PRId32, backupRet);
        }
    } else {
        if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
            HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
            int32_t rowId = -1;
            rdbStore = GetRdbStore();
            if (rdbStore == nullptr) {
                HILOG_ERROR("null FormInfoRdbStore");
                return ERR_APPEXECFWK_FORM_COMMON_CODE;
            }
            ret = rdbStore->Delete(rowId, absRdbPredicates);
        }
    }

    if (ret == NativeRdb::E_OK) {
        return ERR_OK;
    }

    HILOG_WARN("Delete operation failed, key=%{public}s, ret=%{public}" PRId32, key.c_str(), ret);
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::QueryData(const std::string &tableName, const std::string &key,
    std::string &value)
{
    HILOG_DEBUG("QueryData start");
    if (formRdbTableCfgMap_.find(tableName) == formRdbTableCfgMap_.end()) {
        HILOG_ERROR("Form rdb hasn't initialized this table:%{public}s", tableName.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    absRdbPredicates.EqualTo(FORM_KEY, key);
    auto absSharedResultSet = rdbStore->Query(absRdbPredicates, std::vector<std::string>());

    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("null absSharedResultSet");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });
    if (!absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet has no block");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("GoToFirstRow failed, ret:%{public}" PRId32 "", ret);
    } else {
        ret = absSharedResultSet->GetString(FORM_VALUE_INDEX, value);
    }
    absSharedResultSet->Close();

    if (ret == NativeRdb::E_OK) {
        return ERR_OK;
    }

    HILOG_WARN("Query operation failed, key=%{public}s", key.c_str());
    if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
        HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::QueryData(const std::string &tableName, const std::string &key,
    std::unordered_map<std::string, std::string> &values)
{
    if (formRdbTableCfgMap_.find(tableName) == formRdbTableCfgMap_.end()) {
        HILOG_ERROR("Form rdb hasn't initialized this table:%{public}s", tableName.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    absRdbPredicates.BeginsWith(FORM_KEY, key);
    auto absSharedResultSet = rdbStore->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("null absSharedResultSet");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });

    if (!absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet has no block");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_OK) {
        do {
            std::string resultKey;
            ret = absSharedResultSet->GetString(FORM_KEY_INDEX, resultKey);
            if (ret != NativeRdb::E_OK) {
                HILOG_ERROR("GetString key failed");
                break;
            }

            std::string resultValue;
            ret = absSharedResultSet->GetString(FORM_VALUE_INDEX, resultValue);
            if (ret != NativeRdb::E_OK) {
                HILOG_ERROR("GetString value failed");
                break;
            }

            values.emplace(resultKey, resultValue);
        } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    }
    absSharedResultSet->Close();
    if (ret == NativeRdb::E_OK) {
        return ERR_OK;
    }

    HILOG_WARN("Query operation failed, key=%{public}s", key.c_str());
    if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
        HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::QueryAllData(const std::string &tableName,
    std::unordered_map<std::string, std::string> &datas)
{
    HILOG_DEBUG("QueryAllData start");
    if (formRdbTableCfgMap_.find(tableName) == formRdbTableCfgMap_.end()) {
        HILOG_ERROR("Form rdb hasn't initialized this table:%{public}s", tableName.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    auto absSharedResultSet = rdbStore->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("null absSharedResultSet");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });
    if (!absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet has no block");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_OK) {
        do {
            std::string resultKey;
            ret = absSharedResultSet->GetString(FORM_KEY_INDEX, resultKey);
            if (ret != NativeRdb::E_OK) {
                HILOG_ERROR("GetString key failed");
                break;
            }

            std::string resultValue;
            ret = absSharedResultSet->GetString(FORM_VALUE_INDEX, resultValue);
            if (ret != NativeRdb::E_OK) {
                HILOG_ERROR("GetString value failed");
                break;
            }

            datas.emplace(resultKey, resultValue);
        } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    }
    absSharedResultSet->Close();

    if (ret == NativeRdb::E_OK) {
        return ERR_OK;
    }

    HILOG_WARN("Query all data operation failed");
    if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
        HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::QueryAllKeys(const std::string &tableName, std::set<std::string> &datas)
{
    HILOG_DEBUG("QueryAllKeys start");
    if (formRdbTableCfgMap_.find(tableName) == formRdbTableCfgMap_.end()) {
        HILOG_ERROR("Form rdb hasn't initialized this table:%{public}s", tableName.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(tableName);
    auto absSharedResultSet = rdbStore->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("null absSharedResultSet");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });

    if (!absSharedResultSet->HasBlock()) {
        HILOG_ERROR("HasBlock failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_OK) {
        do {
            std::string resultKey;
            ret = absSharedResultSet->GetString(FORM_KEY_INDEX, resultKey);
            if (ret != NativeRdb::E_OK) {
                HILOG_ERROR("GetString key failed");
                break;
            }
            datas.insert(resultKey);
        } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    }
    absSharedResultSet->Close();

    if (ret == NativeRdb::E_OK) {
        return ERR_OK;
    }

    HILOG_WARN("Query all keys operation failed");
    if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
        HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> FormRdbDataMgr::QueryData(
    const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    HILOG_DEBUG("QueryData start");
    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return nullptr;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return nullptr;
    }

    return rdbStore->Query(absRdbPredicates, std::vector<std::string>());
}

std::shared_ptr<NativeRdb::ResultSet> FormRdbDataMgr::QueryDataByStep(
    const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    HILOG_DEBUG("QueryDataByStep start");
    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return nullptr;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return nullptr;
    }

    return rdbStore->QueryByStep(absRdbPredicates, std::vector<std::string>());
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> FormRdbDataMgr::QuerySql(const std::string &sql)
{
    HILOG_DEBUG("QuerySql start");
    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return nullptr;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return nullptr;
    }

    return rdbStore->QuerySql(sql, std::vector<std::string>());
}

bool FormRdbDataMgr::InsertData(
    const std::string &tableName, const NativeRdb::ValuesBucket &valuesBucket, int64_t &rowId)
{
    HILOG_DEBUG("InsertData start");
    if (formRdbTableCfgMap_.find(tableName) == formRdbTableCfgMap_.end()) {
        HILOG_ERROR("Form rdb hasn't initialized this table:%{public}s", tableName.c_str());
        return false;
    }

    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return false;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return false;
    }

    int32_t ret = NativeRdb::E_OK;
    ret = rdbStore->InsertWithConflictResolution(
        rowId, tableName, valuesBucket, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    if (ret == NativeRdb::E_OK) {
        if (rdbStore->IsSlaveDiffFromMaster()) {
            auto backupRet = rdbStore->Backup("");
            HILOG_WARN("rdb slave corrupt, backup from master, ret=%{public}" PRId32, backupRet);
        }
    } else {
        if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
            HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
            rdbStore = GetRdbStore();
            if (rdbStore == nullptr) {
                HILOG_ERROR("null FormInfoRdbStore");
                return false;
            }
            ret = rdbStore->InsertWithConflictResolution(
                rowId, tableName, valuesBucket, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
        }
    }

    if (ret == NativeRdb::E_OK) {
        return true;
    }

    HILOG_WARN("Insert operation failed, ret=%{public}" PRId32, ret);
    return false;
}

bool FormRdbDataMgr::DeleteData(const NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    if (!IsFormRdbLoaded()) {
        HILOG_ERROR("null FormInfoRdbStore");
        return false;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return false;
    }

    int32_t ret = NativeRdb::E_OK;
    int32_t rowId = -1;
    ret = rdbStore->Delete(rowId, absRdbPredicates);
    if (ret == NativeRdb::E_OK) {
        if (rdbStore->IsSlaveDiffFromMaster()) {
            auto backupRet = rdbStore->Backup("");
            HILOG_WARN("rdb slave corrupt, backup from master, ret=%{public}" PRId32, backupRet);
        }
    } else {
        if (CheckAndRebuildRdbStore(ret) == ERR_OK) {
            HILOG_WARN("Check rdb corrupt,rebuild form rdb successfully");
            int32_t rowId = -1;
            rdbStore = GetRdbStore();
            if (rdbStore == nullptr) {
                HILOG_ERROR("null FormInfoRdbStore");
                return false;
            }
            ret = rdbStore->Delete(rowId, absRdbPredicates);
        }
    }

    if (ret == NativeRdb::E_OK) {
        return true;
    }

    HILOG_WARN("Delete operation failed, ret=%{public}" PRId32, ret);
    return false;
}

bool FormRdbDataMgr::IsFormRdbLoaded()
{
    auto rdbStore = GetRdbStore();

    if (rdbStore != nullptr) {
        return true;
    } else {
        return false;
    }

    for (auto iter = formRdbTableCfgMap_.begin(); iter != formRdbTableCfgMap_.end(); iter++) {
        std::string createTableSql = !iter->second.createTableSql.empty() ? iter->second.createTableSql
            : "CREATE TABLE IF NOT EXISTS " + iter->second.tableName
            + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";
        int32_t ret = rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            HILOG_ERROR("Recreate form rdb table failed, ret:%{public}" PRId32 ", name is %{public}s",
                ret, iter->first.c_str());
        }
    }
    return true;
}

ErrCode FormRdbDataMgr::CheckAndRebuildRdbStore(int32_t rdbOperateRet)
{
    if (rdbOperateRet != NativeRdb::E_SQLITE_CORRUPT) {
        HILOG_INFO("errorCode:%{public}" PRId32, rdbOperateRet);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    auto rdbStore = GetRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("null FormInfoRdbStore");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    int64_t curTime = FormUtil::GetCurrentMillisecond();
    if ((curTime - lastRdbBuildTime_) <= MIN_FORM_RDB_REBUILD_INTERVAL) {
        return ERR_APPEXECFWK_FORM_RDB_REPEATED_BUILD;
    }

    // 用备库恢复主库
    auto restoreRet = rdbStore->Restore("");
    if (restoreRet == NativeRdb::E_OK) {
        HILOG_INFO("Restore rdb succeeded");
    } else {
        HILOG_WARN("Restore rdb failed, errorCode:%{public}" PRId32, restoreRet);
        if (restoreRet == NativeRdb::E_SQLITE_CORRUPT) {
            // 删库，避免拿到缓存的开库信息
            HILOG_WARN("Need rdb clear cache, delete db");
            std::string rdbPath = Constants::FORM_MANAGER_SERVICE_PATH + Constants::FORM_RDB_NAME;
            NativeRdb::RdbHelper::DeleteRdbStore(rdbPath);
        }
    }

    rdbStore = LoadRdbStore();
    if (rdbStore == nullptr) {
        HILOG_ERROR("Reload form rdb failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    lastRdbBuildTime_ = curTime;

    if (restoreRet != NativeRdb::E_OK) {
        //fallback restoration if Restore() did not work
        for (auto iter = formRdbTableCfgMap_.begin(); iter != formRdbTableCfgMap_.end(); iter++) {
            std::string createTableSql = !iter->second.createTableSql.empty() ? iter->second.createTableSql
                : "CREATE TABLE IF NOT EXISTS " + iter->second.tableName
                + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";
            int32_t result = rdbStore->ExecuteSql(createTableSql);
            if (result != NativeRdb::E_OK) {
                HILOG_ERROR("Recreate form rdb table failed, ret:%{public}" PRId32 ", name is %{public}s",
                    result, iter->first.c_str());
            }
        }
    }
    return ERR_OK;
}

std::shared_ptr<NativeRdb::RdbStore> FormRdbDataMgr::LoadRdbStore()
{
    std::unique_lock<std::shared_mutex> lock(rdbStoreMutex_);
    std::string rdbPath = Constants::FORM_MANAGER_SERVICE_PATH + Constants::FORM_RDB_NAME;
    NativeRdb::RdbStoreConfig rdbStoreConfig(
        rdbPath,
        NativeRdb::StorageMode::MODE_DISK,
        false,
        std::vector<uint8_t>(),
        Constants::FORM_JOURNAL_MODE,
        Constants::FORM_SYNC_MODE,
        "",
        NativeRdb::SecurityLevel::S1);
    rdbStoreConfig.SetAllowRebuild(true);
    rdbStoreConfig.SetHaMode(NativeRdb::HAMode::MAIN_REPLICA);
    int32_t errCode = NativeRdb::E_OK;
    RdbStoreDataCallBackFormInfoStorage rdbDataCallBack(rdbPath);

    rdbStore_ = nullptr;
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, Constants::FORM_RDB_VERSION,
        rdbDataCallBack, errCode);
    if (errCode != NativeRdb::E_OK) {
        HILOG_ERROR("Form rdb store init fail, err code is %{public}" PRId32 "", errCode);
        FormEventReport::SendFormFailedEvent(FormEventName::CALLEN_DB_FAILED, HiSysEventType::FAULT,
            static_cast<int64_t>(CallDbFailedErrorType::DATABASE_RESET_CONNECT_FAILED));
        rdbStore_ = nullptr;
    }
    return rdbStore_;
}

std::shared_ptr<NativeRdb::RdbStore> FormRdbDataMgr::GetRdbStore()
{
    std::shared_ptr<NativeRdb::RdbStore> rdbStore = nullptr;
    {
        std::shared_lock<std::shared_mutex> lock(rdbStoreMutex_);
        rdbStore = rdbStore_;
    }
    if (rdbStore == nullptr) {
        return LoadRdbStore();
    }
    return rdbStore;
}
} // namespace AppExecFwk
} // namespace OHOS