/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#include "form_trust_mgr.h"

#include "fms_log_wrapper.h"
#include "form_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string UNTRUST_LIST = "untrust_list";
const int32_t UNTRUST_THRESHOLD = 3;
} // namespace

FormTrustMgr::FormTrustMgr()
{
    FormRdbConfig formRdbConfig;
    formRdbConfig.tableName = UNTRUST_LIST;
    formRdbConfig.createTableSql =
        "CREATE TABLE IF NOT EXISTS " + formRdbConfig.tableName + " (KEY TEXT NOT NULL PRIMARY KEY);";
    rdbDataManager_ = std::make_shared<FormRdbDataMgr>(formRdbConfig);
    rdbDataManager_->Init();
    HILOG_INFO("FormTrustMgr is created");
}

FormTrustMgr::~FormTrustMgr()
{
    HILOG_INFO("FormTrustMgr is deleted");
}

bool FormTrustMgr::IsTrust(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(rdbStoreMutex_);
    auto iter = unTrustList_.find(bundleName);
    if (iter == unTrustList_.end()) {
        return true;
    }

    return iter->second <= UNTRUST_THRESHOLD;
}

void FormTrustMgr::GetUntrustAppNameList(std::string &result)
{
    std::map<std::string, int32_t>::iterator it = unTrustList_.begin();
    for (; it != unTrustList_.end(); it++) {
        if (it->second > UNTRUST_THRESHOLD) {
            result += it->first + " untrusty\n";
        } else {
            result += it->first + " trusty\n";
        }
    }
}

void FormTrustMgr::MarkTrustFlag(const std::string &bundleName, bool isTrust)
{
    std::lock_guard<std::mutex> lock(rdbStoreMutex_);
    auto iter = unTrustList_.find(bundleName);
    if (isTrust && iter != unTrustList_.end()) {
        auto ret = rdbDataManager_->DeleteData(bundleName);
        if (ret != ERR_OK) {
            HILOG_ERROR("DeleteData failed, key: %{public}s", bundleName.c_str());
        }

        unTrustList_.erase(iter);
        return;
    }

    if (!isTrust) {
        if (iter == unTrustList_.end()) {
            unTrustList_[bundleName] = 1;
            return;
        }

        int32_t trustNum = iter->second;
        trustNum++;
        unTrustList_[bundleName] = trustNum;
        if (trustNum > UNTRUST_THRESHOLD) {
            auto ret = rdbDataManager_->InsertData(bundleName);
            if (ret != ERR_OK) {
                HILOG_ERROR("InsertData failed, key: %{public}s", bundleName.c_str());
            }
        }
    }
}
} // namespace AppExecFwk
} // namespace OHOS
