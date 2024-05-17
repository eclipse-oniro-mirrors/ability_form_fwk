/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "form_rdb_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
bool g_mockQueryDataRet = true;
bool g_mockInitRet = true;
bool g_mockInsertDataRet = true;
bool g_mockDeleteDataRet = true;

void MockQueryData(bool mockRet)
{
    g_mockQueryDataRet = mockRet;
}

void MockInit(bool mockRet)
{
    g_mockInitRet = mockRet;
}

void MockInsertData(bool mockRet)
{
    g_mockInsertDataRet = mockRet;
}

void MockDeleteData(bool mockRet)
{
    g_mockDeleteDataRet = mockRet;
}

}
}

namespace OHOS {
namespace AppExecFwk {
ErrCode FormRdbDataMgr::QueryData(const std::string &key, std::string &value)
{
    if (g_mockQueryDataRet) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::QueryData(const std::string &key, std::unordered_map<std::string, std::string> &values)
{
    if (g_mockQueryDataRet) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::InsertData(const std::string &key, const std::string &value)
{
    if (g_mockInsertDataRet) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

ErrCode FormRdbDataMgr::DeleteData(const std::string &key)
{
    if (g_mockDeleteDataRet) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}

RdbStoreDataCallBackFormInfoStorage::RdbStoreDataCallBackFormInfoStorage(const FormRdbConfig &formRdbConfig)
    : formRdbConfig_(formRdbConfig)
{
}

RdbStoreDataCallBackFormInfoStorage::~RdbStoreDataCallBackFormInfoStorage()
{
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnCreate(NativeRdb::RdbStore &rdbStore)
{
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnUpgrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnDowngrade(
    NativeRdb::RdbStore &rdbStore, int currentVersion, int targetVersion)
{
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackFormInfoStorage::OnOpen(NativeRdb::RdbStore &rdbStore)
{
    return NativeRdb::E_OK;
}

int32_t RdbStoreDataCallBackFormInfoStorage::onCorruption(std::string databaseFile)
{
    return NativeRdb::E_OK;
}

ErrCode FormRdbDataMgr::Init()
{
    if (g_mockInitRet) {
        if (rdbStore_ != nullptr) {
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
        OHOS::AppExecFwk::RdbStoreDataCallBackFormInfoStorage rdbDataCallBack_(formRdbConfig_);
        rdbStore_ = NativeRdb::RdbHelper::GetRdbStore(rdbStoreConfig, formRdbConfig_.version, rdbDataCallBack_,
            errCode);
        if (rdbStore_ == nullptr) {
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}
}
}