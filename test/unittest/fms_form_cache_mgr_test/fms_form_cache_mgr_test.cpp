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
#include "data_center/form_cache_mgr.h"
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

/*
 * Feature: FormCacheMgr
 * Function: InnerGetImageData
 * FunctionPoints: FormCacheMgr InnerGetImageData interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_005, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_005 start");
    FormCache formCache;
    formCache.imgCache = "{\"1744726509462\":21}";
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    EXPECT_FALSE(formCacheMgr_.InnerGetImageData(formCache, imageDataMap));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_005 end";
}

/*
 * Feature: FormCacheMgr
 * Function: AddData && AddImgData
 * FunctionPoints: FormCacheMgr AddData interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_006, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_006 start");
    int64_t formId = 0;
    FormProviderData formProviderData;
    EXPECT_TRUE(formCacheMgr_.AddData(formId, formProviderData));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_006 end";
}

/*
 * Feature: FormCacheMgr
 * Function: AddCacheData
 * FunctionPoints: FormCacheMgr AddCacheData interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_007, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_007 start");
    FormProviderData formProviderData;
    FormCache formCache;
    EXPECT_TRUE(formCacheMgr_.AddCacheData(formProviderData, formCache));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_007 end";
}

/*
 * Feature: FormCacheMgr
 * Function: AddImgDataToDb
 * FunctionPoints: FormCacheMgr AddImgDataToDb interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_008, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_008 start");
    FormProviderData formProviderData;
    std::string bundle = "bundle";
    sptr<FormAshmem> formAshmemPtr = new (std::nothrow) FormAshmem();
    std::pair<sptr<FormAshmem>, int32_t> loadForm = std::make_pair(formAshmemPtr, 1);
    formProviderData.imageDataMap_[bundle] = loadForm;
    nlohmann::json imgDataJson;
    EXPECT_FALSE(formCacheMgr_.AddImgDataToDb(formProviderData, imgDataJson));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_008 end";
}

/*
 * Feature: FormCacheMgr
 * Function: GetImageDataFromAshmem
 * FunctionPoints: FormCacheMgr GetImageDataFromAshmem interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_009, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_009 start");
    std::string picName = "picName";
    sptr<Ashmem> ashmem = nullptr;
    int32_t len = 1;
    std::vector<uint8_t> value;
    EXPECT_FALSE(formCacheMgr_.GetImageDataFromAshmem(picName, ashmem, len, value));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_009 end";
}

/*
 * Feature: FormCacheMgr
 * Function: SaveDataCacheToDb
 * FunctionPoints: FormCacheMgr SaveDataCacheToDb interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_010, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_010 start");
    int64_t formId = 0;
    FormCache formCache;
    EXPECT_TRUE(formCacheMgr_.SaveDataCacheToDb(formId, formCache));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_010 end";
}

/*
 * Feature: FormCacheMgr
 * Function: GetImgCacheFromDb
 * FunctionPoints: FormCacheMgr GetImgCacheFromDb interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_012, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_012 start");
    int64_t rowId = 0;
    std::vector<uint8_t> blob;
    int32_t size = 1;
    EXPECT_FALSE(formCacheMgr_.GetImgCacheFromDb(rowId, blob, size));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_012 end";
}

/*
 * Feature: FormCacheMgr
 * Function: SaveImgCacheToDb
 * FunctionPoints: FormCacheMgr SaveImgCacheToDb interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_013, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_013 start");
    std::vector<uint8_t> value;
    int32_t size = 1;
    int64_t rowId = 0;
    EXPECT_TRUE(formCacheMgr_.SaveImgCacheToDb(value, size, rowId));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_013 end";
}

/*
 * Feature: FormCacheMgr
 * Function: DeleteImgCacheInDb
 * FunctionPoints: FormCacheMgr DeleteImgCacheInDb interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_014, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_014 start");
    std::string rowId;
    EXPECT_FALSE(formCacheMgr_.DeleteImgCacheInDb(rowId));
    rowId = "rowId";
    EXPECT_TRUE(formCacheMgr_.DeleteImgCacheInDb(rowId));
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_014 end";
}

/*
 * Feature: FormCacheMgr
 * Function: IsDirtyDataCleaned
 * FunctionPoints: FormCacheMgr IsDirtyDataCleaned interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_015, TestSize.Level0)
{
    HILOG_INFO("FmsFormCacheMgrTest_015 start");
    std::string rowId;
    NativeRdb::AbsRdbPredicates absRdbPredicates("form_cache");
    absRdbPredicates.EqualTo("FORM_ID", "isDirtyDataCleaned");

    FormRdbDataMgr::GetInstance().DeleteData(absRdbPredicates);
    EXPECT_FALSE(formCacheMgr_.IsDirtyDataCleaned());
    formCacheMgr_.SetIsDirtyDataCleaned();
    EXPECT_TRUE(formCacheMgr_.IsDirtyDataCleaned());
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_015 end";
}

/*
 * Feature: FormCacheMgr
 * Function: GetFormCacheIds
 * FunctionPoints: FormCacheMgr GetFormCacheIds interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_016, TestSize.Level0)
{
    HILOG_INFO("FmsFormCacheMgrTest_016 start");
    FormProviderData formProviderData;
    nlohmann::json dataResult = R"(
        {
            "a" : "1",
            "b" : "2"
        }
    )"_json;
    formProviderData.UpdateData(dataResult);
    EXPECT_TRUE(formCacheMgr_.AddData(PARAM_FORM_ID_FIRST, formProviderData));

    std::unordered_set<int64_t> formIds;
    formCacheMgr_.GetFormCacheIds(formIds);
    EXPECT_NE(formIds.find(PARAM_FORM_ID_FIRST), formIds.end());
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_016 end";
}
}
