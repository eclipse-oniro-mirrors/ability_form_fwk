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

#include <gtest/gtest.h>

#include "appexecfwk_errors.h"
#define private public
#include "form_rdb_data_mgr.h"
#undef private
#include "form_mgr_errors.h"
#include "form_constants.h"

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

void MockInit(bool mockRet);

class FmsFormRdbDataMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<RdbStoreDataCallBackFormInfoStorage> rdbDataCallBack_;
};

void FmsFormRdbDataMgrTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest SetUpTestCase.";
}

void FmsFormRdbDataMgrTest::TearDownTestCase()
{
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
}
}