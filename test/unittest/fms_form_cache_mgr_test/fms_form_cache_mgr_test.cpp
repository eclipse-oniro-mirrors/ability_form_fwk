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

#define private public
#include "form_cache_mgr.h"
#undef private
#include "fms_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

static const int64_t PARAM_FORM_ID_FIRST = std::numeric_limits<int64_t>::max();

namespace {
class FmsFormCacheMgrTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    FormCacheMgr formCacheMgr_;
};


void FmsFormCacheMgrTest::SetUpTestCase()
{}

void FmsFormCacheMgrTest::TearDownTestCase()
{}

void FmsFormCacheMgrTest::SetUp()
{}

void FmsFormCacheMgrTest::TearDown()
{}

/*
 * Feature: FormCacheMgr
 * Function: GetData
 * FunctionPoints: FormCacheMgr GetData interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: invoke GetData works by input key.
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_001, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_001 start");

    std::string dataResult = "";
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    EXPECT_FALSE(formCacheMgr_.GetData(PARAM_FORM_ID_FIRST, dataResult, imageDataMap));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_001 end";
}

/*
 * Feature: FormCacheMgr
 * Function: AddData
 * FunctionPoints: FormCacheMgr AddData interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: add data by input param.
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_002, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_002 start");

    nlohmann::json dataResult = R"(
        {
            "a" : "1",
            "b" : "2"
        }
    )"_json;
    FormProviderData formProviderData;
    formProviderData.UpdateData(dataResult);
    EXPECT_TRUE(formCacheMgr_.AddData(PARAM_FORM_ID_FIRST, formProviderData));

    std::string queryResult;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    EXPECT_TRUE(formCacheMgr_.GetData(PARAM_FORM_ID_FIRST, queryResult, imageDataMap));

    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_002 end";
}

/*
 * Feature: FormCacheMgr
 * Function: AddData
 * FunctionPoints: FormCacheMgr AddData interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: cache contains data and add the new data by input param.
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_003, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_003 start");
    std::string result1 = "{\"a\":\"1\",\"b\":\"2\"}";
    std::string result2 = "{\"a\":\"2\",\"b\":\"2\"}";
    nlohmann::json dataResult1 = R"(
        {
            "a" : "1",
            "b" : "2"
        }
    )"_json;
    nlohmann::json dataResult2 = R"(
        {
            "a" : "2",
            "b" : "2"
        }
    )"_json;
    FormProviderData formProviderData;
    formProviderData.UpdateData(dataResult1);
    EXPECT_TRUE(formCacheMgr_.AddData(PARAM_FORM_ID_FIRST, formProviderData));

    std::string queryResult;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    EXPECT_TRUE(formCacheMgr_.GetData(PARAM_FORM_ID_FIRST, queryResult, imageDataMap));
    EXPECT_EQ(result1, queryResult);

    formProviderData.UpdateData(dataResult2);
    EXPECT_TRUE(formCacheMgr_.AddData(PARAM_FORM_ID_FIRST, formProviderData));
    EXPECT_TRUE(formCacheMgr_.GetData(PARAM_FORM_ID_FIRST, queryResult, imageDataMap));
    EXPECT_EQ(result2, queryResult);
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_003 end";
}

/*
 * Feature: FormCacheMgr
 * Function: DeleteData
 * FunctionPoints: FormCacheMgr DeleteData interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: delete data by input key
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_004, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_004 start");
    std::string result1 = "{\"a\":\"1\",\"b\":\"2\"}";
    nlohmann::json dataResult1 = R"(
        {
            "a" : "1",
            "b" : "2"
        }
    )"_json;
    
    FormProviderData formProviderData;
    formProviderData.UpdateData(dataResult1);
    EXPECT_TRUE(formCacheMgr_.AddData(PARAM_FORM_ID_FIRST, formProviderData));

    std::string queryResult;
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    EXPECT_TRUE(formCacheMgr_.GetData(PARAM_FORM_ID_FIRST, queryResult, imageDataMap));
    EXPECT_EQ(result1, queryResult);
    EXPECT_TRUE(formCacheMgr_.DeleteData(PARAM_FORM_ID_FIRST));
    EXPECT_FALSE(formCacheMgr_.GetData(PARAM_FORM_ID_FIRST, queryResult, imageDataMap));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_004 end";
}
}
