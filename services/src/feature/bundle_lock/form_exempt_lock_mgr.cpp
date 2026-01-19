/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#include "feature/bundle_lock/form_exempt_lock_mgr.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "data_center/form_data_mgr.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *LOCK_FORM_EXEMPT_TABLE = "lock_form_exempt_table";
}

FormExemptLockMgr::FormExemptLockMgr()
{
    HILOG_INFO("Create");
}

FormExemptLockMgr::~FormExemptLockMgr()
{
    HILOG_INFO("Destroy");
}

bool FormExemptLockMgr::Init()
{
    std::unique_lock<std::shared_mutex> lock(exemptLockSetMutex_);
    if (isInitialized_) {
        return true;
    }
    FormRdbTableConfig formRdbTableConfig;
    formRdbTableConfig.tableName = LOCK_FORM_EXEMPT_TABLE;
    formRdbTableConfig.createTableSql = "CREATE TABLE IF NOT EXISTS " +
        formRdbTableConfig.tableName + " (KEY TEXT NOT NULL PRIMARY KEY);";
    if (FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig) != ERR_OK) {
        HILOG_ERROR("Form exempt lock mgr init form rdb table fail");
        return false;
    }

    FormRdbDataMgr::GetInstance().QueryAllKeys(LOCK_FORM_EXEMPT_TABLE, formExemptLockSet_);
    isInitialized_ = true;
    HILOG_INFO("initialized");
    return true;
}

bool FormExemptLockMgr::IsExemptLock(int64_t formId)
{
    std::string formId_s = std::to_string(formId);
    if (!Init()) {
        HILOG_ERROR("Form exempt lock mgr not init");
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(exemptLockSetMutex_);
    auto iter = formExemptLockSet_.find(formId_s);
    return iter != formExemptLockSet_.end();
}

void FormExemptLockMgr::SetExemptLockStatus(int64_t formId, bool isExempt)
{
    std::string formId_s = std::to_string(formId);
    if (!Init()) {
        HILOG_ERROR("Form exempt lock mgr not init");
        return;
    }

    std::unique_lock<std::shared_mutex> lock(exemptLockSetMutex_);
    auto iter = formExemptLockSet_.find(formId_s);
    if (isExempt && iter == formExemptLockSet_.end()) {
        formExemptLockSet_.insert(formId_s);
        FormRdbDataMgr::GetInstance().InsertData(LOCK_FORM_EXEMPT_TABLE, formId_s);
    } else if (!isExempt && iter != formExemptLockSet_.end()) {
        formExemptLockSet_.erase(formId_s);
        FormRdbDataMgr::GetInstance().DeleteData(LOCK_FORM_EXEMPT_TABLE, formId_s);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
