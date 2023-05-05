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
#include "form_rdb_data_mgr.h"

#include <cinttypes>
#include <thread>
#include <filesystem>
#include <sstream>
#include <sys/stat.h>
#include <unistd.h>
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string FORM_KEY = "KEY";
const std::string FORM_VALUE = "VALUE";
const int32_t FORM_KEY_INDEX = 0;
const int32_t FORM_VALUE_INDEX = 1;
} // namespace
RdbStoreDataCallBackFormInfoStorage::RdbStoreDataCallBackFormInfoStorage(const FormRdbConfig &formRdbConfig)
    : formRdbConfig_(formRdbConfig)
{
    HILOG_DEBUG("create rdb store callback instance");
}

RdbStoreDataCallBackFormInfoStorage::~RdbStoreDataCallBackFormInfoStorage()
{
    HILOG_DEBUG("destroy rdb store callback instance");
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    HILOG_DEBUG("OnCreate");
    int ret = NativeRdb::E_OK;
    if (hasTableInit_) {
        return ret;
    }
    std::string createTableSql = "CREATE TABLE IF NOT EXISTS " + formRdbConfig_.tableName
        + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";
    ret = rdbStore.ExecuteSql(createTableSql);
    if (ret == NativeRdb::E_OK) {
        hasTableInit_ = true;
    }
    return ret;
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
    return NativeRdb::E_OK;
}

FormRdbDataMgr::FormRdbDataMgr(const FormRdbConfig &formRdbConfig)
    : formRdbConfig_(formRdbConfig) 
{
    HILOG_DEBUG("create form rdb data manager");
}

ErrCode FormRdbDataMgr::Init()
{
    HILOG_DEBUG("Create rdbStore");

    if (rdbStore_ != nullptr) {
        HILOG_DEBUG("FormInfoRdbStore has existed");
        return ERR_OK;
    }

    NativeRdb::RdbStoreConfig rdbStoreConfig(
        formRdbConfig_.dbPath + formRdbConfig_.dbName,
        NativeRdb::StorageMode::MODE_DISK,
        false,
        std::vector<uint8_t>(),
        formRdbConfig_.journalMode,
        formRdbConfig_.syncMode,
        "",
        NativeRdb::SecurityLevel::S1);
    int32_t errCode = NativeRdb::E_OK;
    RdbStoreDataCallBackFormInfoStorage rdbDataCallBack_(formRdbConfig_);
    rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, formRdbConfig_.version, rdbDataCallBack_, errCode);
    if (rdbStore_ == nullptr) {
        HILOG_ERROR("FormInfoRdbStore init fail");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormRdbDataMgr::InsertData(const std::string &key, const std::string &value)
{
    HILOG_DEBUG("InsertData start");
    if (rdbStore_ == nullptr) {
        HILOG_ERROR("FormInfoRdbStore is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    int64_t rowId = -1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(FORM_KEY, key);
    valuesBucket.PutString(FORM_VALUE, value);
    auto ret = rdbStore_->InsertWithConflictResolution(
        rowId, formRdbConfig_.tableName, valuesBucket, NativeRdb::ConflictResolution::ON_CONFLICT_REPLACE);
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("Insert operation failed, result: %{public}d, key=%{public}s.", ret, key.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormRdbDataMgr::DeleteData(const std::string &key)
{
    HILOG_DEBUG("DeleteData start");
    if (rdbStore_ == nullptr) {
        HILOG_ERROR("FormInfoRdbStore is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    int32_t rowId = -1;
    NativeRdb::AbsRdbPredicates absRdbPredicates(formRdbConfig_.tableName);
    absRdbPredicates.EqualTo(FORM_KEY, key);
    auto ret = rdbStore_->Delete(rowId, absRdbPredicates);
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("Delete operation failed, result: %{public}d, key=%{public}s.",
            ret, key.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormRdbDataMgr::QueryData(const std::string &key, std::unordered_map<std::string, std::string> &values)
{
    HILOG_DEBUG("QueryData start");
    if (rdbStore_ == nullptr) {
        HILOG_ERROR("FormInfoRdbStore is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(formRdbConfig_.tableName);
    absRdbPredicates.BeginsWith(FORM_KEY, key);
    auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (absSharedResultSet->GoToFirstRow() != NativeRdb::E_OK) {
        HILOG_ERROR("GoToFirstRow failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    do {
        std::string resultKey;
        if (absSharedResultSet->GetString(FORM_KEY_INDEX, resultKey) != NativeRdb::E_OK) {
            HILOG_ERROR("GetString key failed");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        std::string resultValue;
        if (absSharedResultSet->GetString(FORM_VALUE_INDEX, resultValue) != NativeRdb::E_OK) {
            HILOG_ERROR("GetString value failed");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        values.emplace(resultKey, resultValue);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();
    return ERR_OK;
}

ErrCode FormRdbDataMgr::QueryAllData(std::unordered_map<std::string, std::string> &datas)
{
    HILOG_DEBUG("QueryAllData start");
    if (rdbStore_ == nullptr) {
        HILOG_ERROR("FormInfoRdbStore is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    NativeRdb::AbsRdbPredicates absRdbPredicates(formRdbConfig_.tableName);
    auto absSharedResultSet = rdbStore_->Query(absRdbPredicates, std::vector<std::string>());
    if (absSharedResultSet == nullptr || !absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (absSharedResultSet->GoToFirstRow() != NativeRdb::E_OK) {
        HILOG_ERROR("GoToFirstRow failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    do {
        std::string resultKey;
        if (absSharedResultSet->GetString(FORM_KEY_INDEX, resultKey) != NativeRdb::E_OK) {
            HILOG_ERROR("GetString key failed");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        std::string resultValue;
        if (absSharedResultSet->GetString(FORM_VALUE_INDEX, resultValue) != NativeRdb::E_OK) {
            HILOG_ERROR("GetString value failed");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        datas.emplace(resultKey, resultValue);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    absSharedResultSet->Close();
    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS