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
#include "common/util/json_util_form.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string DISTRIBUTED_FORM_BUNDLE_TABLE = "distributed_form_bundle_table";
    const std::string DISTRIBUTED_BUNDLE_TABLE = "distributed_bundle_table";
    const std::string DISTRIBUTED_BUNDLE_ENTRY_MODULENAME = "entryModule";
    const std::string DISTRIBUTED_BUNDLE_UI_MODULENAME = "uiModule";
}

FormDistributedMgr::FormDistributedMgr()
{
    HILOG_INFO("Create");
}

FormDistributedMgr::~FormDistributedMgr()
{
    HILOG_INFO("Destroy");
}

void FormDistributedMgr::Start()
{
    HILOG_INFO("Start");
    DeleteUnuseTableAfterReboot();
    Init();
}

bool FormDistributedMgr::Init()
{
    FormRdbTableConfig formRdbTableConfig;
    formRdbTableConfig.tableName = DISTRIBUTED_BUNDLE_TABLE;
    formRdbTableConfig.createTableSql = "CREATE TABLE IF NOT EXISTS " +
        formRdbTableConfig.tableName + " (KEY TEXT NOT NULL PRIMARY KEY, VALUE TEXT NOT NULL);";
    if (FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig) != ERR_OK) {
        HILOG_ERROR("Form bundle distributed mgr init form rdb table fail");
        return false;
    }

    std::unordered_map<std::string, std::string> value;
    FormRdbDataMgr::GetInstance().QueryAllData(DISTRIBUTED_BUNDLE_TABLE, value);
    // save resultSet to distributed module map
    SaveEntries(value);

    isInitialized_ = true;
    HILOG_INFO("initialized");
    return true;
}

bool FormDistributedMgr::IsBundleDistributed(const std::string &bundleName)
{
    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return false;
    }

    if (!IsBundleDistributedInit()) {
        HILOG_ERROR("distributed mgr init failed, get status error");
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleDistributedMapMutex_);
    auto iter = distributedBundleMap_.find(bundleName);
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
    HILOG_INFO("set bundle: %{public}s distributed status: %{public}d", bundleName.c_str(), isDistributed);
    auto iter = distributedBundleMap_.find(bundleName);
    if (isDistributed) {
        distributedBundleMap_[bundleName] = distributedModule;
        FormRdbDataMgr::GetInstance().InsertData(DISTRIBUTED_BUNDLE_TABLE, bundleName, ToString(distributedModule));
    } else if (!isDistributed && iter != distributedBundleMap_.end()) {
        distributedBundleMap_.erase(bundleName);
        FormRdbDataMgr::GetInstance().DeleteData(DISTRIBUTED_BUNDLE_TABLE, bundleName);
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

void FormDistributedMgr::DeleteUnuseTableAfterReboot()
{
    std::string sql = "DROP TABLE " + DISTRIBUTED_FORM_BUNDLE_TABLE;
    FormRdbDataMgr::GetInstance().ExecuteSql(sql);
}

std::string FormDistributedMgr::GetUiModuleName(const std::string &bundleName)
{
    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return "";
    }

    if (!IsBundleDistributedInit()) {
        HILOG_ERROR("distributed mgr init failed, get uiModuleName error");
        return "";
    }

    std::shared_lock<std::shared_mutex> lock(bundleDistributedMapMutex_);
    auto iter = distributedBundleMap_.find(bundleName);
    return iter != distributedBundleMap_.end() ? iter->second.uiModule : "";
}

std::string FormDistributedMgr::ToString(const DistributedModule &distributedModule)
{
    nlohmann::json obj;
    obj[DISTRIBUTED_BUNDLE_ENTRY_MODULENAME] = distributedModule.entryModule;
    obj[DISTRIBUTED_BUNDLE_UI_MODULENAME] = distributedModule.uiModule;
    return obj.dump();
}

bool FormDistributedMgr::TransJsonToObj(const nlohmann::json &jsonObject, DistributedModule &distributedModule)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;

    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, DISTRIBUTED_BUNDLE_ENTRY_MODULENAME,
        distributedModule.entryModule, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, DISTRIBUTED_BUNDLE_UI_MODULENAME,
        distributedModule.uiModule, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);

    return parseResult == ERR_OK;
}

void FormDistributedMgr::SaveEntries(const std::unordered_map<std::string, std::string> &value)
{
    distributedBundleMap_.clear();
    for (const auto &item : value) {
        nlohmann::json jsonObject = nlohmann::json::parse(item.second, nullptr, false);
        DistributedModule distributedModule;
        if (!TransJsonToObj(jsonObject, distributedModule)) {
            HILOG_ERROR("error key: %{public}s", item.first.c_str());
            FormRdbDataMgr::GetInstance().DeleteData(DISTRIBUTED_BUNDLE_TABLE, item.first);
            continue;
        }

        distributedBundleMap_[item.first] = distributedModule;
    }
    HILOG_INFO("init distributed data size:%{public}zu", distributedBundleMap_.size());
}
}  // namespace AppExecFwk
}  // namespace OHOS