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

class FmsFormRdbDataMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<FormRdbDataMgr> rdbDataManager_;
    std::shared_ptr<RdbStoreDataCallBackFormInfoStorage> rdbDataCallBack_;
};
void FmsFormRdbDataMgrTest::SetUpTestCase()
{}

void FmsFormRdbDataMgrTest::TearDownTestCase()
{}

void FmsFormRdbDataMgrTest::SetUp()
{
    FormRdbConfig formRdbConfig;
    rdbDataManager_ = std::make_shared<FormRdbDataMgr>(formRdbConfig);
    rdbDataManager_->Init();
    rdbDataCallBack_ = std::make_shared<RdbStoreDataCallBackFormInfoStorage>(formRdbConfig);
}

void FmsFormRdbDataMgrTest::TearDown()
{}

/**
 * @tc.name: FmsFormRdbDataMgrTest_001
 * @tc.desc: Test init
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_001, Function | SmallTest | Level1)
{
    auto result = rdbDataManager_->Init();
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_002
 * @tc.desc: Test InsertData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_002, Function | SmallTest | Level1)
{
    std::string key = "testKey";
    std::string value = "values";
    auto result = rdbDataManager_->InsertData(key, value);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_003
 * @tc.desc: Test QueryData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_003, Function | SmallTest | Level1)
{
    std::string key = "testKey";
    std::unordered_map<std::string, std::string> datas;
    auto result = rdbDataManager_->QueryData(key, datas);
    EXPECT_EQ(result, ERR_OK);

    std::string nothingkey = "nothingKey";
    result = rdbDataManager_->QueryData(nothingkey, datas);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_004
 * @tc.desc: Test QueryAllData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_004, Function | SmallTest | Level1)
{
    std::unordered_map<std::string, std::string> datas;
    auto result = rdbDataManager_->QueryAllData(datas);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormRdbDataMgrTest_005
 * @tc.desc: Test DeleteData
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRdbDataMgrTest, FmsFormRdbDataMgrTest_005, Function | SmallTest | Level1)
{
    std::string key = "testKey";
    auto result = rdbDataManager_->DeleteData(key);
    EXPECT_EQ(result, ERR_OK);
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

    auto result = rdbDataCallBack_->OnCreate(*(rdbDataManager_->rdbStore_.get()));
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
    auto result = rdbDataCallBack_->OnUpgrade(*(rdbDataManager_->rdbStore_.get()), currentVersion, targetVersion);
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
    auto result = rdbDataCallBack_->OnDowngrade(*(rdbDataManager_->rdbStore_.get()), currentVersion, targetVersion);
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
    auto result = rdbDataManager_->InsertData(data);
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
    auto result = rdbDataManager_->QueryData(key, retValue);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    std::string value = "values";
    result = rdbDataManager_->InsertData(key, value);
    EXPECT_EQ(result, ERR_OK);

    result = rdbDataManager_->QueryData(key, retValue);
    EXPECT_EQ(result, ERR_OK);

    result = rdbDataManager_->DeleteData(key);
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
    
    int64_t formId = 1;
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(FORM_ID, std::to_string(formId));
    valuesBucket.PutString(DATA_CACHE, "dataCache");
    valuesBucket.PutString(FORM_IMAGES, "imgCache");
    valuesBucket.PutInt(CACHE_STATE, 0);
    int64_t rowId;
    bool ret = rdbDataManager_->InsertData(FORM_CACHE_TABLE, valuesBucket, rowId);
    EXPECT_EQ(ret, true);

    NativeRdb::AbsRdbPredicates absRdbPredicates(FORM_CACHE_TABLE);
    absRdbPredicates.EqualTo(FORM_ID, std::to_string(formId));
    ret = rdbDataManager_->DeleteData(absRdbPredicates);
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
    auto result = rdbDataManager_->QueryAllKeys(datas);
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
    auto result = rdbDataManager_->QuerySql(key);
    EXPECT_NE(result, nullptr);

    GTEST_LOG_(INFO) << "FmsFormRdbDataMgrTest_014 end";
}
}
}