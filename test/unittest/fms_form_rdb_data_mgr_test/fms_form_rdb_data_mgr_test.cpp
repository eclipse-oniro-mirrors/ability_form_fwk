/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "appexecfwk_errors.h"
#define private public
#include "data_center/database/form_rdb_data_mgr.h"
#undef private
#include "form_mgr_errors.h"
#include "form_constants.h"
#include "common/util/form_util.h"
#include "mock_rdb_store.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
const std::string FORM_CACHE_TABLE = "form_cache";
const std::string FORM_ID = "FORM_ID";
const std::string DATA_CACHE = "DATA_CACHE";
const std::string FORM_IMAGES = "FORM_IMAGES";
const std::string CACHE_STATE = "CACHE_STATE";
const std::string TEST_TABLE = "table_test";
const std::string TEST_TABLE_COL_KEY = "KEY";
const std::string TEST_TABLE_COL_VALUE = "VALUE";
const std::string TEST_TABLE_CREATE_SQL =
    "CREATE TABLE IF NOT EXISTS " + TEST_TABLE + "(" +
    TEST_TABLE_COL_KEY + " TEXT NOT NULL PRIMARY KEY, " +
    TEST_TABLE_COL_VALUE + " TEXT);";
const std::string TEST_KEY = "testKey";
const std::string TEST_VALUE = "values";

void MockInit(bool mockRet);

class FmsFormRdbDataMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<RdbStoreDataCallBackFormInfoStorage> rdbDataCallBack_;
    static std::shared_ptr<MockRdbStore> rdbStoreMock_;
};

std::shared_ptr<MockRdbStore> FmsFormRdbDataMgrTest::rdbStoreMock_ = nullptr;

void FmsFormRdbDataMgrTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest SetUpTestCase.";
    RdbStoreConfig config(
        "",
        NativeRdb::StorageMode::MODE_DISK,
        false,
        std::vector<uint8_t>(),
        Constants::FORM_JOURNAL_MODE,
        Constants::FORM_SYNC_MODE,
        "",
        NativeRdb::SecurityLevel::S1);
    rdbStoreMock_ = std::make_shared<MockRdbStore>(config);
}

void FmsFormRdbDataMgrTest::TearDownTestCase()
{
    rdbStoreMock_ = nullptr;
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest TearDownTestCase";
}

void FmsFormRdbDataMgrTest::SetUp()
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest SetUp.";
}

void FmsFormRdbDataMgrTest::TearDown()
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest TearDown";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_001
 * @tc.desc: Test init
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_001, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_001 start";
    FormRdbTableConfig formRdbTableConfig;
    auto result = FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig);
    rdbDataCallBack_ = std::make_shared<RdbStoreDataCallBackFormInfoStorage>(
        Constants::FORM_MANAGER_SERVICE_PATH + Constants::FORM_RDB_NAME);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_001 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_002
 * @tc.desc: Test InsertData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_002, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_002 start";
    std::string key = "testKey";
    std::string value = "values";
    auto result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME,
        key, value);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_002 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_003
 * @tc.desc: Test QueryData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_003, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_003 start";
    std::string key = "testKey";
    std::unordered_map<std::string, std::string> datas;
    auto result = FormRdbDataMgr::GetInstance().QueryData(Constants::FORM_RDB_TABLE_NAME, key, datas);
    EXPECT_EQ(result, ERR_OK);
    std::string nothingkey = "nothingKey";
    result = FormRdbDataMgr::GetInstance().QueryData(Constants::FORM_RDB_TABLE_NAME, nothingkey, datas);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_003 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_004
 * @tc.desc: Test QueryAllData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_004, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_004 start";
    std::unordered_map<std::string, std::string> datas;
    auto result = FormRdbDataMgr::GetInstance().QueryAllData(Constants::FORM_RDB_TABLE_NAME, datas);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_004 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_005
 * @tc.desc: Test DeleteData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_005, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_005 start";
    std::string key = "testKey";
    auto result = FormRdbDataMgr::GetInstance().DeleteData(Constants::FORM_RDB_TABLE_NAME, key);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_005 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_006
 * @tc.desc: Verify functionName RdbStoreDataCallBackFormInfoStorage::OnCreate.
 * @tc.details: The function OnCreate runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_006, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_006 start";
    if (rdbDataCallBack_ == nullptr) {
        rdbDataCallBack_ = std::make_shared<RdbStoreDataCallBackFormInfoStorage>(
            Constants::FORM_MANAGER_SERVICE_PATH + Constants::FORM_RDB_NAME);
    }
    auto result = rdbDataCallBack_->OnCreate(*(FormRdbDataMgr::GetInstance().rdbStore_.get()));
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_006 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_007
 * @tc.desc: Verify functionName RdbStoreDataCallBackFormInfoStorage::OnUpgrade.
 * @tc.details: The function OnUpgrade runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_007, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_007 start";
    int currentVersion = 1;
    int targetVersion = 2;
    if (rdbDataCallBack_ == nullptr) {
        rdbDataCallBack_ = std::make_shared<RdbStoreDataCallBackFormInfoStorage>(
            Constants::FORM_MANAGER_SERVICE_PATH + Constants::FORM_RDB_NAME);
    }
    auto result = rdbDataCallBack_->OnUpgrade(*(FormRdbDataMgr::GetInstance().rdbStore_.get()),
        currentVersion, targetVersion);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_007 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_008
 * @tc.desc: Verify functionName RdbStoreDataCallBackFormInfoStorage::OnDowngrade.
 * @tc.details: The function OnDowngrade runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_008, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_008 start";

    int currentVersion = 2;
    int targetVersion = 1;
    if (rdbDataCallBack_ == nullptr) {
        rdbDataCallBack_ = std::make_shared<RdbStoreDataCallBackFormInfoStorage>(
            Constants::FORM_MANAGER_SERVICE_PATH + Constants::FORM_RDB_NAME);
    }
    auto result = rdbDataCallBack_->OnDowngrade(*(FormRdbDataMgr::GetInstance().rdbStore_.get()),
        currentVersion, targetVersion);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_008 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_009
 * @tc.desc: Verify functionName RdbStoreDataCallBackFormInfoStorage::onCorruption.
 * @tc.details: The function onCorruption runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_009, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_009 start";
    std::string data = "testKey";
    if (rdbDataCallBack_ == nullptr) {
        rdbDataCallBack_ = std::make_shared<RdbStoreDataCallBackFormInfoStorage>(
            Constants::FORM_MANAGER_SERVICE_PATH + Constants::FORM_RDB_NAME);
    }
    auto result = rdbDataCallBack_->onCorruption(data);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_009 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_0010
 * @tc.desc: Verify functionName FormRdbDataMgr::InsertData, this input is key.
 * @tc.details: The function InsertData runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_010, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_010 start";
    std::string data = "testKey";
    auto result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME, data);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_010 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_0011
 * @tc.desc: Verify functionName FormRdbDataMgr::QueryData, this input is key and value.
 * @tc.details: The function QueryData runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_011, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_011 start";
    std::string key = "testKey";
    std::string retValue = "";
    auto result = FormRdbDataMgr::GetInstance().QueryData(Constants::FORM_RDB_TABLE_NAME, key, retValue);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    std::string value = "values";
    result = FormRdbDataMgr::GetInstance().InsertData(Constants::FORM_RDB_TABLE_NAME, key, value);
    EXPECT_EQ(result, ERR_OK);

    result = FormRdbDataMgr::GetInstance().QueryData(Constants::FORM_RDB_TABLE_NAME, key, retValue);
    EXPECT_EQ(result, ERR_OK);

    result = FormRdbDataMgr::GetInstance().DeleteData(Constants::FORM_RDB_TABLE_NAME, key);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_011 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_0012
 * @tc.desc: Verify functionName FormRdbDataMgr::InsertData and DeleteData.
 * @tc.details: The functions runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_012, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_012 start";

    FormRdbTableConfig formRdbTableConfig;
    formRdbTableConfig.tableName = FORM_CACHE_TABLE;
    auto result = FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig);
    EXPECT_EQ(result, ERR_OK);
    
    int64_t formId = 1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(FORM_ID, std::to_string(formId));
    valuesBucket.PutString(DATA_CACHE, "dataCache");
    valuesBucket.PutString(FORM_IMAGES, "imgCache");
    valuesBucket.PutInt(CACHE_STATE, 0);
    int64_t rowId;
    bool ret = FormRdbDataMgr::GetInstance().InsertData(FORM_CACHE_TABLE, valuesBucket, rowId);
    EXPECT_EQ(ret, true);

    NativeRdb::AbsRdbPredicates absRdbPredicates(FORM_CACHE_TABLE);
    absRdbPredicates.EqualTo(FORM_ID, std::to_string(formId));
    ret = FormRdbDataMgr::GetInstance().DeleteData(absRdbPredicates);
    EXPECT_EQ(ret, true);

    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_012 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_0013
 * @tc.desc: Verify functionName FormRdbDataMgr::QueryAllKeys.
 * @tc.details: The function QueryAllData runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_013, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_013 start";
    
    std::set<std::string> datas;
    auto result = FormRdbDataMgr::GetInstance().QueryAllKeys(Constants::FORM_RDB_TABLE_NAME, datas);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_013 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_0014
 * @tc.desc: Verify functionName FormRdbDataMgr::QuerySql.
 * @tc.details: The function QuerySql runs normally and the return value meets expectations.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_014, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_014 start";
    
    std::string key = "testKey";
    auto result = FormRdbDataMgr::GetInstance().QuerySql(key);
    EXPECT_NE(result, nullptr);

    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_014 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_015
 * @tc.desc: Test onCorruption
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_015, Function | SmallTest | Level1)
{
    RdbStoreDataCallBackFormInfoStorage rdbDataCallBack_(Constants::FORM_MANAGER_SERVICE_PATH +
        Constants::FORM_RDB_NAME);
    auto result = rdbDataCallBack_.onCorruption(Constants::FORM_RDB_TABLE_NAME);
    EXPECT_EQ(result, NativeRdb::E_OK);
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_016
 * @tc.desc: Test OnOpen
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_016, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_016 start";
    if (rdbDataCallBack_ == nullptr) {
        rdbDataCallBack_ = std::make_shared<RdbStoreDataCallBackFormInfoStorage>(
        Constants::FORM_MANAGER_SERVICE_PATH + Constants::FORM_RDB_NAME);
    }
    ASSERT_NE(nullptr, rdbDataCallBack_);
    auto result = rdbDataCallBack_->OnOpen(*(FormRdbDataMgr::GetInstance().rdbStore_.get()));
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_016 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_017
 * @tc.desc: Test InitFormRdbTable
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_017, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_017 start";
    FormRdbTableConfig formRdbTableConfig;
    formRdbTableConfig.tableName = "";
    auto result = FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_017 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_018
 * @tc.desc: Test DeleteData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_018, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_018 start";
    std::string key = "testKey";
    std::string tableName = "null";
    auto result = FormRdbDataMgr::GetInstance().DeleteData(tableName, key);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_018 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_019
 * @tc.desc: Test CheckAndRebuildRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_019, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_019 start";
    auto result = FormRdbDataMgr::GetInstance().CheckAndRebuildRdbStore(NativeRdb::E_SQLITE_ERROR);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_019 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_020
 * @tc.desc: Test CheckAndRebuildRdbStore
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_020, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_020 start";
    auto result = FormRdbDataMgr::GetInstance().CheckAndRebuildRdbStore(NativeRdb::E_SQLITE_ERROR);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormRdbDataMgr::GetInstance().lastRdbBuildTime_ = FormUtil::GetCurrentMillisecond();
    result = FormRdbDataMgr::GetInstance().CheckAndRebuildRdbStore(NativeRdb::E_SQLITE_CORRUPT);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_RDB_REPEATED_BUILD);
    FormRdbDataMgr::GetInstance().lastRdbBuildTime_ = 0;
    result = FormRdbDataMgr::GetInstance().CheckAndRebuildRdbStore(NativeRdb::E_SQLITE_CORRUPT);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_020 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_021
 * @tc.desc: Test ExecuteSql
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_021, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_021 start";

    FormRdbDataMgr::GetInstance().rdbStore_ = rdbStoreMock_;
    std::string sql("SELECT COUNT(0) FROM ");
    sql.append(Constants::FORM_RDB_TABLE_NAME);
    sql.append(";");

    EXPECT_CALL(*rdbStoreMock_, ExecuteSql(_, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(0);
    auto result = FormRdbDataMgr::GetInstance().ExecuteSql(sql);
    EXPECT_EQ(result, ERR_OK);

    EXPECT_CALL(*rdbStoreMock_, ExecuteSql(_, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().ExecuteSql(sql);
    EXPECT_EQ(result, ERR_OK);

    FormRdbDataMgr::GetInstance().lastRdbBuildTime_ = 0;
    EXPECT_CALL(*rdbStoreMock_, ExecuteSql(_, _)).Times(1).WillOnce(Return(E_SQLITE_CORRUPT));
    EXPECT_CALL(*rdbStoreMock_, Restore(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().ExecuteSql(sql);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(rdbStoreMock_, FormRdbDataMgr::GetInstance().rdbStore_);

    FormRdbDataMgr::GetInstance().rdbStore_ = nullptr;
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_021 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_022
 * @tc.desc: Test InsertData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_022, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_022 start";

    FormRdbDataMgr::GetInstance().rdbStore_ = nullptr;
    FormRdbTableConfig formRdbTableConfig;
    formRdbTableConfig.tableName = TEST_TABLE;
    formRdbTableConfig.createTableSql = TEST_TABLE_CREATE_SQL;
    auto result = FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbTableConfig);
    EXPECT_EQ(result, ERR_OK);

    FormRdbDataMgr::GetInstance().rdbStore_ = rdbStoreMock_;

    EXPECT_CALL(*rdbStoreMock_, InsertWithConflictResolution(_, _, _, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(0);
    result = FormRdbDataMgr::GetInstance().InsertData(TEST_TABLE, TEST_KEY);
    EXPECT_EQ(result, ERR_OK);

    EXPECT_CALL(*rdbStoreMock_, InsertWithConflictResolution(_, _, _, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().InsertData(TEST_TABLE, TEST_KEY);
    EXPECT_EQ(result, ERR_OK);

    FormRdbDataMgr::GetInstance().lastRdbBuildTime_ = 0;
    EXPECT_CALL(*rdbStoreMock_, InsertWithConflictResolution(_, _, _, _)).Times(1).WillOnce(Return(E_SQLITE_CORRUPT));
    EXPECT_CALL(*rdbStoreMock_, Restore(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().InsertData(TEST_TABLE, TEST_KEY);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(rdbStoreMock_, FormRdbDataMgr::GetInstance().rdbStore_);
    std::unordered_map<std::string, std::string> data;
    result = FormRdbDataMgr::GetInstance().QueryData(TEST_TABLE, TEST_KEY, data);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(data.size(), 1);
    EXPECT_STREQ(data.cbegin()->first.c_str(), TEST_KEY.c_str());

    FormRdbDataMgr::GetInstance().rdbStore_ = nullptr;
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_022 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_023
 * @tc.desc: Test InsertData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_023, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_023 start";

    FormRdbDataMgr::GetInstance().rdbStore_ = rdbStoreMock_;

    EXPECT_CALL(*rdbStoreMock_, InsertWithConflictResolution(_, _, _, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(0);
    auto result = FormRdbDataMgr::GetInstance().InsertData(TEST_TABLE, TEST_KEY, TEST_VALUE);
    EXPECT_EQ(result, ERR_OK);

    EXPECT_CALL(*rdbStoreMock_, InsertWithConflictResolution(_, _, _, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().InsertData(TEST_TABLE, TEST_KEY, TEST_VALUE);
    EXPECT_EQ(result, ERR_OK);

    FormRdbDataMgr::GetInstance().lastRdbBuildTime_ = 0;
    EXPECT_CALL(*rdbStoreMock_, InsertWithConflictResolution(_, _, _, _)).Times(1).WillOnce(Return(E_SQLITE_CORRUPT));
    EXPECT_CALL(*rdbStoreMock_, Restore(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().InsertData(TEST_TABLE, TEST_KEY, TEST_VALUE);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(rdbStoreMock_, FormRdbDataMgr::GetInstance().rdbStore_);
    std::unordered_map<std::string, std::string> data;
    result = FormRdbDataMgr::GetInstance().QueryData(TEST_TABLE, TEST_KEY, data);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(data.size(), 1);
    EXPECT_STREQ(data[TEST_KEY].c_str(), TEST_VALUE.c_str());

    FormRdbDataMgr::GetInstance().rdbStore_ = nullptr;
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_023 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_024
 * @tc.desc: Test DeleteData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_024, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_024 start";

    FormRdbDataMgr::GetInstance().rdbStore_ = rdbStoreMock_;

    EXPECT_CALL(*rdbStoreMock_, Delete(_, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(0);
    auto result = FormRdbDataMgr::GetInstance().DeleteData(TEST_TABLE, TEST_KEY);
    EXPECT_EQ(result, ERR_OK);

    EXPECT_CALL(*rdbStoreMock_, Delete(_, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().DeleteData(TEST_TABLE, TEST_KEY);
    EXPECT_EQ(result, ERR_OK);

    FormRdbDataMgr::GetInstance().lastRdbBuildTime_ = 0;
    EXPECT_CALL(*rdbStoreMock_, Delete(_, _)).Times(1).WillOnce(Return(E_SQLITE_CORRUPT));
    EXPECT_CALL(*rdbStoreMock_, Restore(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().DeleteData(TEST_TABLE, TEST_KEY);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(rdbStoreMock_, FormRdbDataMgr::GetInstance().rdbStore_);
    std::unordered_map<std::string, std::string> data;
    result = FormRdbDataMgr::GetInstance().QueryData(TEST_TABLE, TEST_KEY, data);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    FormRdbDataMgr::GetInstance().rdbStore_ = nullptr;
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_024 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_025
 * @tc.desc: Test InsertData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_025, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_025 start";

    FormRdbDataMgr::GetInstance().rdbStore_ = rdbStoreMock_;

    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(TEST_TABLE_COL_KEY, TEST_KEY);
    valuesBucket.PutString(TEST_TABLE_COL_VALUE, TEST_VALUE);
    int64_t rowId;

    EXPECT_CALL(*rdbStoreMock_, InsertWithConflictResolution(_, _, _, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(0);
    auto result = FormRdbDataMgr::GetInstance().InsertData(TEST_TABLE, valuesBucket, rowId);
    EXPECT_TRUE(result);

    EXPECT_CALL(*rdbStoreMock_, InsertWithConflictResolution(_, _, _, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().InsertData(TEST_TABLE, valuesBucket, rowId);
    EXPECT_TRUE(result);

    FormRdbDataMgr::GetInstance().lastRdbBuildTime_ = 0;
    EXPECT_CALL(*rdbStoreMock_, InsertWithConflictResolution(_, _, _, _)).Times(1).WillOnce(Return(E_SQLITE_CORRUPT));
    EXPECT_CALL(*rdbStoreMock_, Restore(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().InsertData(TEST_TABLE, valuesBucket, rowId);
    EXPECT_TRUE(result);
    EXPECT_NE(rdbStoreMock_, FormRdbDataMgr::GetInstance().rdbStore_);
    std::unordered_map<std::string, std::string> data;
    result = FormRdbDataMgr::GetInstance().QueryData(TEST_TABLE, TEST_KEY, data);
    EXPECT_EQ(result, ERR_OK);
    ASSERT_EQ(data.size(), 1);
    EXPECT_STREQ(data[TEST_KEY].c_str(), TEST_VALUE.c_str());

    FormRdbDataMgr::GetInstance().rdbStore_ = nullptr;
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_025 end";
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_026
 * @tc.desc: Test DeleteData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_026, Function | SmallTest | Level1)
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_026 start";

    FormRdbDataMgr::GetInstance().rdbStore_ = rdbStoreMock_;

    NativeRdb::AbsRdbPredicates absRdbPredicates(TEST_TABLE);
    absRdbPredicates.EqualTo(TEST_TABLE_COL_KEY, TEST_KEY);

    EXPECT_CALL(*rdbStoreMock_, Delete(_, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(0);
    auto result = FormRdbDataMgr::GetInstance().DeleteData(absRdbPredicates);
    EXPECT_TRUE(result);

    EXPECT_CALL(*rdbStoreMock_, Delete(_, _)).Times(1).WillOnce(Return(E_OK));
    EXPECT_CALL(*rdbStoreMock_, IsSlaveDiffFromMaster()).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*rdbStoreMock_, Backup(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().DeleteData(absRdbPredicates);
    EXPECT_TRUE(result);

    FormRdbDataMgr::GetInstance().lastRdbBuildTime_ = 0;
    EXPECT_CALL(*rdbStoreMock_, Delete(_, _)).Times(1).WillOnce(Return(E_SQLITE_CORRUPT));
    EXPECT_CALL(*rdbStoreMock_, Restore(_, _)).Times(1).WillOnce(Return(E_OK));
    result = FormRdbDataMgr::GetInstance().DeleteData(absRdbPredicates);
    EXPECT_TRUE(result);
    EXPECT_NE(rdbStoreMock_, FormRdbDataMgr::GetInstance().rdbStore_);
    std::unordered_map<std::string, std::string> data;
    auto result2 = FormRdbDataMgr::GetInstance().QueryData(TEST_TABLE, TEST_KEY, data);
    EXPECT_EQ(result2, ERR_APPEXECFWK_FORM_COMMON_CODE);

    FormRdbDataMgr::GetInstance().rdbStore_ = nullptr;
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_026 end";
}
}
}
