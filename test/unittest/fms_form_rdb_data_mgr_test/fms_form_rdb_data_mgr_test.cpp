/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_rdb_data_mgr.h"
#include "form_mgr_errors.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class FmsFormRdbDataMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    std::shared_ptr<FormRdbDataMgr> rdbDataManager_;
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
}
}