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

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string DISTRIBUTED_FORM_BUNDLE_TABLE = "distributed_form_bundle_table";
}

FormDistributedMgr::FormDistributedMgr()
{
    HILOG_INFO("Create");
}

FormDistributedMgr::~FormDistributedMgr()
{
    HILOG_INFO("Destroy");
}

bool FormDistributedMgr::Init()
{
    FormRdbTableConfig formRdbTableConfig;
    formRdbTableConfig.tableName = DISTRIBUTED_FORM_BUNDLE_TABLE;
    formRdbTableConfig.createTableSql = "CREATE TABLE IF NOT EXISTS " +
        formRdbTableConfig.tableName + " (KEY TEXT NOT NULL PRIMARY KEY);";
    if (FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig) != ERR_OK) {
        HILOG_ERROR("Form bundle distributed mgr init form rdb table fail");
        return false;
    }

    FormRdbDataMgr::GetInstance().QueryAllKeys(DISTRIBUTED_FORM_BUNDLE_TABLE, formBundleDistributedSet_);
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
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleDistributedSetMutex_);
    auto iter = formBundleDistributedSet_.find(bundleName);
    return iter != formBundleDistributedSet_.end();
}

void FormDistributedMgr::SetBundleDistributedStatus(const std::string &bundleName, bool isDistributed)
{
    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return;
    }

    std::unique_lock<std::shared_mutex> lock(bundleDistributedSetMutex_);
    if (!isInitialized_ && !Init()) {
        HILOG_ERROR("Form bundle distributed mgr not init");
        return;
    }

    auto iter = formBundleDistributedSet_.find(bundleName);
    if (isDistributed && iter == formBundleDistributedSet_.end()) {
        formBundleDistributedSet_.insert(bundleName);
        FormRdbDataMgr::GetInstance().InsertData(DISTRIBUTED_FORM_BUNDLE_TABLE, bundleName);
    } else if (!isDistributed && iter != formBundleDistributedSet_.end()) {
        formBundleDistributedSet_.erase(bundleName);
        FormRdbDataMgr::GetInstance().DeleteData(DISTRIBUTED_FORM_BUNDLE_TABLE, bundleName);
    }
}

bool FormDistributedMgr::IsBundleDistributedInit()
{
    std::unique_lock<std::shared_mutex> lock(bundleDistributedSetMutex_);
    if (!isInitialized_ && !Init()) {
        HILOG_ERROR("Form bundle forbid mgr not init");
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS