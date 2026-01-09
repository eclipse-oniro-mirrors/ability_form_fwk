/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "feature/bundle_forbidden/form_bundle_forbid_mgr.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *FORBIDDEN_FORM_BUNDLE_TABLE = "forbidden_form_bundle_table";
}

FormBundleForbidMgr::FormBundleForbidMgr()
{
    HILOG_INFO("Create");
}

FormBundleForbidMgr::~FormBundleForbidMgr()
{
    HILOG_INFO("Destroy");
}

bool FormBundleForbidMgr::Init()
{
    FormRdbTableConfig formRdbTableConfig;
    formRdbTableConfig.tableName = FORBIDDEN_FORM_BUNDLE_TABLE;
    formRdbTableConfig.createTableSql = "CREATE TABLE IF NOT EXISTS " +
        formRdbTableConfig.tableName + " (KEY TEXT NOT NULL PRIMARY KEY);";
    if (FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig) != ERR_OK) {
        HILOG_ERROR("Form bundle forbid mgr init form rdb table fail");
        return false;
    }

    FormRdbDataMgr::GetInstance().QueryAllKeys(FORBIDDEN_FORM_BUNDLE_TABLE, formBundleForbiddenSet_);
    isInitialized_ = true;
    HILOG_INFO("initialized");
    return true;
}

bool FormBundleForbidMgr::IsBundleForbidden(const std::string &bundleName)
{
    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return false;
    }

    if (!IsBundleForbidMgrInit()) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleForbiddenSetMutex_);
    auto iter = formBundleForbiddenSet_.find(bundleName);
    return iter != formBundleForbiddenSet_.end();
}

void FormBundleForbidMgr::SetBundleForbiddenStatus(const std::string &bundleName, bool isForbidden)
{
    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return;
    }

    std::unique_lock<std::shared_mutex> lock(bundleForbiddenSetMutex_);
    if (!isInitialized_ && !Init()) {
        HILOG_ERROR("Form bundle forbid mgr not init");
        return;
    }

    auto iter = formBundleForbiddenSet_.find(bundleName);
    if (isForbidden && iter == formBundleForbiddenSet_.end()) {
        formBundleForbiddenSet_.insert(bundleName);
        FormRdbDataMgr::GetInstance().InsertData(FORBIDDEN_FORM_BUNDLE_TABLE, bundleName);
    } else if (!isForbidden && iter != formBundleForbiddenSet_.end()) {
        formBundleForbiddenSet_.erase(bundleName);
        FormRdbDataMgr::GetInstance().DeleteData(FORBIDDEN_FORM_BUNDLE_TABLE, bundleName);
    }
}

bool FormBundleForbidMgr::IsBundleForbidMgrInit()
{
    std::unique_lock<std::shared_mutex> lock(bundleForbiddenSetMutex_);
    if (!isInitialized_ && !Init()) {
        HILOG_ERROR("Form bundle forbid mgr not init");
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
