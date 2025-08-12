/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "feature/bundle_distributed/form_distributed_mgr.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "common/util/scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string DISTRIBUTED_FORM_BUNDLE_TABLE = "distributed_form_bundle_table";
    constexpr int32_t KEY_INDEX = 0;
    constexpr int32_t USERID_INDEX = 1;
    constexpr int32_t ENTRYMODULE_INDEX = 2;
    constexpr int32_t UIMODULE_INDEX = 3;
    constexpr int32_t VALUE_INDEX = 4;
    constexpr const char* KEY = "KEY"; // KEY = BUNDLENAME + USERID
    constexpr const char* USERID = "USERID";
    constexpr const char* ENTRYMODULE = "ENTRYMODULE";
    constexpr const char* UIMODULE = "UIMODULE";
    constexpr const char* VALUE = "VALUE";
}

FormDistributedMgr::FormDistributedMgr()
{
    HILOG_INFO("Create");
}

FormDistributedMgr::~FormDistributedMgr()
{
    HILOG_INFO("Destroy");
}

const static std::map<std::string, std::string> tableExtraColumns_ = {
    { USERID, "INTEGER" },
    { ENTRYMODULE, "TEXT" },
    { UIMODULE, "TEXT" },
    { VALUE, "TEXT" },
};

void FormDistributedMgr::Start()
{
    HILOG_INFO("Start");
    Init();
}

bool FormDistributedMgr::Init()
{
    FormRdbTableConfig formRdbTableConfig;
    formRdbTableConfig.tableName = DISTRIBUTED_FORM_BUNDLE_TABLE;
    formRdbTableConfig.createTableSql = "CREATE TABLE IF NOT EXISTS " + formRdbTableConfig.tableName
        + " (KEY TEXT NOT NULL PRIMARY KEY, USERID INTEGER, ENTRYMODULE TEXT, UIMODULE TEXT, VALUE TEXT);";
    if (FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig) != ERR_OK) {
        HILOG_ERROR("Form bundle distributed mgr init form rdb table fail");
        return false;
    }

    AlterTableAddColumn();

    LoadDataFromDb();

    isInitialized_ = true;
    HILOG_INFO("initialized");
    return true;
}

bool FormDistributedMgr::IsBundleDistributed(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty() || userId == Constants::INVALID_USER_ID) {
        HILOG_ERROR("invalid bundleName or userId, userId:%{public}d", userId);
        return false;
    }

    if (!IsBundleDistributedInit()) {
        HILOG_ERROR("distributed mgr init failed, get status error");
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleDistributedMapMutex_);
    auto iter = distributedBundleMap_.find(bundleName + std::to_string(userId));
    return iter != distributedBundleMap_.end();
}

void FormDistributedMgr::SetBundleDistributedStatus(
    const std::string &bundleName, bool isDistributed, const DistributedModule &distributedModule)
{
    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return;
    }

    if (!isInitialized_ && !Init()) {
        HILOG_ERROR("Form bundle distributed mgr not init");
        return;
    }

    std::unique_lock<std::shared_mutex> lock(bundleDistributedMapMutex_);
    HILOG_INFO("set bundle: %{public}s distributed status: %{public}d, userId:%{public}d",
        bundleName.c_str(), isDistributed, distributedModule.userId);
    std::string key = bundleName + std::to_string(distributedModule.userId);
    auto iter = distributedBundleMap_.find(key);
    if (isDistributed && distributedModule.userId != Constants::INVALID_USER_ID) {
        distributedBundleMap_[key] = distributedModule;
        SaveDataToDb(bundleName, distributedModule);
    } else if (!isDistributed && iter != distributedBundleMap_.end()) {
        distributedBundleMap_.erase(key);
        DeleteDataInDb(bundleName, distributedModule.userId);
    }
}

bool FormDistributedMgr::IsBundleDistributedInit()
{
    std::unique_lock<std::shared_mutex> lock(bundleDistributedMapMutex_);
    if (!isInitialized_ && !Init()) {
        HILOG_ERROR("Form bundle distributed mgr not init");
        return false;
    }
    return true;
}

void FormDistributedMgr::AlterTableAddColumn()
{
    static const std::vector<std::string> columns = { USERID, ENTRYMODULE, UIMODULE, VALUE };
    std::string sql;
    for (const auto &iter : columns) {
        auto it = tableExtraColumns_.find(iter);
        if (it == tableExtraColumns_.end()) {
            return;
        }
        sql = "ALTER TABLE " + DISTRIBUTED_FORM_BUNDLE_TABLE + " ADD COLUMN " + it->first + " " + it->second;
        FormRdbDataMgr::GetInstance().ExecuteSql(sql);
    }
}

std::string FormDistributedMgr::GetUiModuleName(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty() || userId == Constants::INVALID_USER_ID) {
        HILOG_ERROR("invalid bundleName or userId, userId:%{public}d", userId);
        return "";
    }

    if (!IsBundleDistributedInit()) {
        HILOG_ERROR("distributed mgr init failed, get uiModuleName error");
        return "";
    }

    std::shared_lock<std::shared_mutex> lock(bundleDistributedMapMutex_);
    auto iter = distributedBundleMap_.find(bundleName + std::to_string(userId));
    return iter != distributedBundleMap_.end() ? iter->second.uiModule : "";
}

void FormDistributedMgr::LoadDataFromDb()
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(DISTRIBUTED_FORM_BUNDLE_TABLE);
    auto absSharedResultSet = FormRdbDataMgr::GetInstance().QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("get distributed db data failed");
        return;
    }

    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });
    if (!absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet has no block");
        return;
    }

    int32_t ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_OK) {
        do {
            std::string key;
            ret += absSharedResultSet->GetString(KEY_INDEX, key);

            DistributedModule distributedModule;
            ret += absSharedResultSet->GetInt(USERID_INDEX, distributedModule.userId);
            ret += absSharedResultSet->GetString(ENTRYMODULE_INDEX, distributedModule.entryModule);
            ret += absSharedResultSet->GetString(UIMODULE_INDEX, distributedModule.uiModule);
            ret += absSharedResultSet->GetString(VALUE_INDEX, distributedModule.extraValue);
            if (ret != NativeRdb::E_OK) {
                HILOG_ERROR("GetString field failed");
                break;
            }

            distributedBundleMap_[key] = distributedModule;
        } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    }
    absSharedResultSet->Close();

    HILOG_INFO("init distributed data size:%{public}zu", distributedBundleMap_.size());
}

void FormDistributedMgr::SaveDataToDb(const std::string &bundleName, const DistributedModule &distributedModule)
{
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(KEY, bundleName + std::to_string(distributedModule.userId));
    valuesBucket.PutInt(USERID, distributedModule.userId);
    valuesBucket.PutString(ENTRYMODULE, distributedModule.entryModule);
    valuesBucket.PutString(UIMODULE, distributedModule.uiModule);
    valuesBucket.PutString(VALUE, distributedModule.extraValue);
    int64_t rowId;
    bool ret = FormRdbDataMgr::GetInstance().InsertData(DISTRIBUTED_FORM_BUNDLE_TABLE, valuesBucket, rowId);
    HILOG_INFO("insert data ret:%{public}d, bundleName:%{public}s, userId:%{public}d",
        ret, bundleName.c_str(), distributedModule.userId);
}

void FormDistributedMgr::DeleteDataInDb(const std::string &bundleName, int32_t userId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(DISTRIBUTED_FORM_BUNDLE_TABLE);
    absRdbPredicates.EqualTo(KEY, bundleName + std::to_string(userId));
    bool ret = FormRdbDataMgr::GetInstance().DeleteData(absRdbPredicates);
    HILOG_INFO("deleta data ret:%{public}d, bundleName:%{public}s, userId:%{public}d", ret, bundleName.c_str(), userId);
}
}  // namespace AppExecFwk
}  // namespace OHOS