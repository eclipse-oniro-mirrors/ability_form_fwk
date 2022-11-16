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
    HILOG_INFO("create rdb store callback instance");
}

RdbStoreDataCallBackFormInfoStorage::~RdbStoreDataCallBackFormInfoStorage()
{
    HILOG_INFO("destroy rdb store callback instance");
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnCreate(NativeRdb::RdbStore &store)
{
    HILOG_INFO("Create table.");
    std::string CREATE_TABLE_SQL = "CREATE TABLE IF NOT EXISTS " + formRdbConfig_.tableName
        + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";
    return store.ExecuteSql(CREATE_TABLE_SQL);
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnUpgrade(
    NativeRdb::RdbStore &store, int32_t oldVersion, int32_t newVersion)
{
    return NativeRdb::E_OK;
}

FormRdbDataMgr::FormRdbDataMgr(const FormRdbConfig &formRdbConfig)
    : formRdbConfig_(formRdbConfig) 
{
    HILOG_INFO("create form rdb data manager");
}

ErrCode FormRdbDataMgr::Init()
{
    HILOG_INFO("Create rdbStore");
    int32_t errCode(NativeRdb::E_OK);

    if (rdbStore_ != nullptr) {
        HILOG_INFO("FormInfoRdbStore has existed");
        return ERR_OK;
    }

    NativeRdb::RdbStoreConfig rdbStoreConfig(
            formRdbConfig_.dbPath + formRdbConfig_.dbName,
            NativeRdb::StorageMode::MODE_DISK,
            false,
            std::vector<uint8_t>(),
            formRdbConfig_.journalMode,
            formRdbConfig_.syncMode);
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
    HILOG_INFO("InsertData start");
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

ErrCode FormRdbDataMgr::UpdateData(const std::string &key, const std::string &value)
{
    HILOG_INFO("UpdateData start");
    if (rdbStore_ == nullptr) {
        HILOG_ERROR("FormInfoRdbStore is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    int32_t rowId = -1;
    NativeRdb::AbsRdbPredicates absRdbPredicates(formRdbConfig_.tableName);
    absRdbPredicates.EqualTo(FORM_KEY, key);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(FORM_KEY, key);
    valuesBucket.PutString(FORM_VALUE, value);
    auto ret = rdbStore_->Update(rowId, valuesBucket, absRdbPredicates);
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("Update operation failed, result: %{public}d, updated rows: %{public}d, key=%{public}s.",
            ret, rowId, key.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormRdbDataMgr::DeleteData(const std::string &key)
{
    HILOG_INFO("DeleteData start");
    if (rdbStore_ == nullptr) {
        HILOG_ERROR("FormInfoRdbStore is null");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    int32_t rowId = -1;
    NativeRdb::AbsRdbPredicates absRdbPredicates(formRdbConfig_.tableName);
    absRdbPredicates.EqualTo(FORM_KEY, key);
    auto ret = rdbStore_->Delete(rowId, absRdbPredicates);
    if ((ret != NativeRdb::E_OK) || (rowId <= 0)) {
        HILOG_ERROR("Delete operation failed, result: %{public}d, key=%{public}s.",
            ret, key.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormRdbDataMgr::QueryData(const std::string &key, std::map<std::string, std::string> &values)
{
    HILOG_INFO("QueryData start");
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
        std::string key;
        if (absSharedResultSet->GetString(FORM_KEY_INDEX, key) != NativeRdb::E_OK) {
            HILOG_ERROR("GetString key failed");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        std::string value;
        if (absSharedResultSet->GetString(FORM_VALUE_INDEX, value) != NativeRdb::E_OK) {
            HILOG_ERROR("GetString value failed");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }

        values.emplace(key, value);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);

    return ERR_OK;
}

ErrCode FormRdbDataMgr::QueryAllData(std::map<std::string, std::string> &datas)
{
    HILOG_INFO("QueryAllData start");
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
        std::string key;
        if (absSharedResultSet->GetString(FORM_KEY_INDEX, key) != NativeRdb::E_OK) {
            HILOG_INFO("GetString key failed");
            return false;
        }

        std::string value;
        if (absSharedResultSet->GetString(FORM_VALUE_INDEX, value) != NativeRdb::E_OK) {
            HILOG_INFO("GetString value failed");
            return false;
        }

        datas.emplace(key, value);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return ERR_OK;
}
}
}