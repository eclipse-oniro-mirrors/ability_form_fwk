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
#include "feature/bundle_lock/form_bundle_lock_mgr.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "data_center/form_data_mgr.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *LOCK_FORM_BUNDLE_TABLE = "lock_form_bundle_table";
constexpr int32_t DEFAULT_USER_ID = 100;
}

FormBundleLockMgr::FormBundleLockMgr()
{
    HILOG_INFO("Create");
}

FormBundleLockMgr::~FormBundleLockMgr()
{
    HILOG_INFO("Destroy");
}

bool FormBundleLockMgr::Init()
{
    FormRdbTableConfig formRdbTableConfig;
    formRdbTableConfig.tableName = LOCK_FORM_BUNDLE_TABLE;
    formRdbTableConfig.createTableSql = "CREATE TABLE IF NOT EXISTS " +
        formRdbTableConfig.tableName + " (KEY TEXT NOT NULL PRIMARY KEY);";
    if (FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig) != ERR_OK) {
        HILOG_ERROR("Form bundle lock mgr init form rdb table fail");
        return false;
    }

    FormRdbDataMgr::GetInstance().QueryAllKeys(LOCK_FORM_BUNDLE_TABLE, formBundleLockSet_);
    isInitialized_ = true;
    HILOG_INFO("initialized");
    return true;
}

bool FormBundleLockMgr::IsBundleLock(const std::string &bundleName, int64_t formId)
{
    if (FormUtil::GetCurrentAccountId() != DEFAULT_USER_ID) {
        return false;
    }

    if (formId != 0) {
        bool lockStatus = false;
        FormDataMgr::GetInstance().GetFormLock(formId, lockStatus);
        return lockStatus;
    }

    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return false;
    }

    if (!IsBundleLockMgrInit()) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleLockSetMutex_);
    auto iter = formBundleLockSet_.find(bundleName);
    return iter != formBundleLockSet_.end();
}

void FormBundleLockMgr::SetBundleLockStatus(const std::string &bundleName, bool isLock)
{
    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return;
    }

    std::unique_lock<std::shared_mutex> lock(bundleLockSetMutex_);
    if (!isInitialized_ && !Init()) {
        HILOG_ERROR("Form bundle lock mgr not init");
        return;
    }

    auto iter = formBundleLockSet_.find(bundleName);
    if (isLock && iter == formBundleLockSet_.end()) {
        formBundleLockSet_.insert(bundleName);
        FormRdbDataMgr::GetInstance().InsertData(LOCK_FORM_BUNDLE_TABLE, bundleName);
    } else if (!isLock && iter != formBundleLockSet_.end()) {
        formBundleLockSet_.erase(bundleName);
        FormRdbDataMgr::GetInstance().DeleteData(LOCK_FORM_BUNDLE_TABLE, bundleName);
    }
}

bool FormBundleLockMgr::IsBundleProtect(const std::string &bundleName, int64_t formId)
{
    if (FormUtil::GetCurrentAccountId() != DEFAULT_USER_ID) {
        return false;
    }

    bool protectStatus = false;
    if (formId != 0 && FormDataMgr::GetInstance().GetFormProtect(formId, protectStatus) == ERR_OK) {
        return protectStatus;
    }

    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleProtectSetMutex_);
    auto iter = formBundleProtectSet_.find(bundleName);
    return iter != formBundleProtectSet_.end();
}

void FormBundleLockMgr::SetBundleProtectStatus(const std::string &bundleName, bool isProtect)
{
    if (bundleName.empty()) {
        HILOG_ERROR("invalid bundleName");
        return;
    }

    std::unique_lock<std::shared_mutex> lock(bundleProtectSetMutex_);
    auto iter = formBundleProtectSet_.find(bundleName);
    if (isProtect && iter == formBundleProtectSet_.end()) {
        formBundleProtectSet_.insert(bundleName);
    } else if (!isProtect && iter != formBundleProtectSet_.end()) {
        formBundleProtectSet_.erase(bundleName);
    } else {
        HILOG_ERROR("set bundle protect status failed");
    }
}

bool FormBundleLockMgr::IsBundleLockMgrInit()
{
    std::unique_lock<std::shared_mutex> lock(bundleLockSetMutex_);
    if (!isInitialized_ && !Init()) {
        HILOG_ERROR("Form bundle lock mgr not init");
        return false;
    }
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
