/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include <algorithm>

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
{
    formCacheMgr_.DeleteData(0);
}

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
    std::vector<std::string> newRowIds;
    EXPECT_FALSE(formCacheMgr_.AddImgDataToDb(formProviderData, imgDataJson, newRowIds));
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

/*
 * Feature: FormCacheMgr
 * Function: NeedAcquireProviderData
 * FunctionPoints: FormCacheMgr NeedAcquireProviderData interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_017, TestSize.Level0)
{
    HILOG_INFO("fms_form_cache_mgr_test_017 start");
    int64_t formId = 0;
    bool result = formCacheMgr_.NeedAcquireProviderData(formId);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "fms_form_cache_mgr_test_017 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_018
 * @tc.desc: Verify InnerGetImageData with empty json imgCache returns true.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_018, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_018 start");
    FormCache formCache;
    formCache.imgCache = "{}";
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    EXPECT_TRUE(formCacheMgr_.InnerGetImageData(formCache, imageDataMap));
    EXPECT_TRUE(imageDataMap.empty());
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_018 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_019
 * @tc.desc: Verify InnerGetImageData with invalid json returns false.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_019, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_019 start");
    FormCache formCache;
    formCache.imgCache = "invalid_json";
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    EXPECT_FALSE(formCacheMgr_.InnerGetImageData(formCache, imageDataMap));
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_019 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_020
 * @tc.desc: Verify AddImgData with existing imgCache enters delete branch.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_020, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_020 start");
    FormProviderData formProviderData;
    FormCache formCache;
    formCache.imgCache = "{\"test_key\":123}";
    std::vector<std::string> newRowIds;
    EXPECT_TRUE(formCacheMgr_.AddImgData(formProviderData, formCache, newRowIds));
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_020 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_021
 * @tc.desc: Verify AddImgData with invalid imgCache json returns false.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_021, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_021 start");
    FormProviderData formProviderData;
    nlohmann::json dataResult = R"({"a":"1"})"_json;
    formProviderData.UpdateData(dataResult);
    sptr<FormAshmem> formAshmemPtr = new (std::nothrow) FormAshmem();
    ASSERT_NE(formAshmemPtr, nullptr);
    formProviderData.imageDataMap_["test"] = std::make_pair(formAshmemPtr, 1);
    FormCache formCache;
    formCache.imgCache = "invalid_json";
    std::vector<std::string> newRowIds;
    EXPECT_FALSE(formCacheMgr_.AddImgData(formProviderData, formCache, newRowIds));
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_021 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_022
 * @tc.desc: Verify AddImgDataToDb with empty imageDataMap returns true.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_022, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_022 start");
    FormProviderData formProviderData;
    nlohmann::json imgDataJson;
    std::vector<std::string> newRowIds;
    EXPECT_TRUE(formCacheMgr_.AddImgDataToDb(formProviderData, imgDataJson, newRowIds));
    EXPECT_TRUE(imgDataJson.empty());
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_022 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_023
 * @tc.desc: Verify GetImageDataFromAshmem with valid ashmem and valid data.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_023, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_023 start");
    std::string picName = "test_pic";
    std::string testData = "test_data_content";
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem("test_ashmem", testData.size());
    ASSERT_NE(ashmem, nullptr);
    bool mapRet = ashmem->MapReadAndWriteAshmem();
    ASSERT_TRUE(mapRet);
    bool writeRet = ashmem->WriteToAshmem(testData.c_str(), testData.size(), 0);
    ASSERT_TRUE(writeRet);
    ashmem->UnmapAshmem();
    std::vector<uint8_t> value;
    EXPECT_TRUE(formCacheMgr_.GetImageDataFromAshmem(picName, ashmem, testData.size(), value));
    EXPECT_EQ(value.size(), testData.size());
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_023 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_024
 * @tc.desc: Verify AddImgData with empty imgCache and valid newImgDbData.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_024, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_024 start");
    FormProviderData formProviderData;
    FormCache formCache;
    formCache.imgCache = "";
    std::vector<std::string> newRowIds;
    EXPECT_TRUE(formCacheMgr_.AddImgData(formProviderData, formCache, newRowIds));
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_024 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_025
 * @tc.desc: Verify AddData with invalid json data returns false and persists nothing.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_025, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_025 start");
    int64_t formId = 10025;
    std::string invalidJson = "invalid_json";
    FormProviderData formProviderData(invalidJson);
    EXPECT_FALSE(formCacheMgr_.AddData(formId, formProviderData));
    std::unordered_set<int64_t> formIds;
    formCacheMgr_.GetFormCacheIds(formIds);
    EXPECT_EQ(formIds.find(formId), formIds.end());
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_025 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_026
 * @tc.desc: Verify AddData rolls back newly inserted image rows when AddCacheData fails.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_026, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_026 start");
    int64_t formId = 10026;
    std::vector<int64_t> imgIdsBefore;
    formCacheMgr_.GetAllImgIds(imgIdsBefore);

    FormProviderData formProviderData("invalid_json");
    std::string imgData = "image_content";
    sptr<FormAshmem> formAshmemPtr = new (std::nothrow) FormAshmem();
    ASSERT_NE(formAshmemPtr, nullptr);
    EXPECT_TRUE(formAshmemPtr->WriteToAshmem("test_pic", const_cast<char *>(imgData.c_str()), imgData.size()));
    formProviderData.imageDataMap_["test_pic"] = std::make_pair(formAshmemPtr, imgData.size());

    // AddImgDataToDb succeeds, AddCacheData fails, rollback must remove the new image row
    EXPECT_FALSE(formCacheMgr_.AddData(formId, formProviderData));
    std::vector<int64_t> imgIdsAfter;
    formCacheMgr_.GetAllImgIds(imgIdsAfter);
    EXPECT_EQ(imgIdsAfter.size(), imgIdsBefore.size());
    std::sort(imgIdsBefore.begin(), imgIdsBefore.end());
    std::sort(imgIdsAfter.begin(), imgIdsAfter.end());
    EXPECT_EQ(imgIdsAfter, imgIdsBefore);
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_026 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_027
 * @tc.desc: Verify RollbackNewImgCaches deletes the given image rows.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_027, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_027 start");
    std::vector<uint8_t> value = {1, 2, 3};
    int64_t rowId = -1;
    EXPECT_TRUE(formCacheMgr_.SaveImgCacheToDb(value, value.size(), rowId));
    ASSERT_NE(rowId, -1);
    std::vector<uint8_t> blob;
    int32_t size = 0;
    EXPECT_TRUE(formCacheMgr_.GetImgCacheFromDb(rowId, blob, size));
    EXPECT_EQ(size, static_cast<int32_t>(value.size()));
    EXPECT_EQ(blob, value);

    formCacheMgr_.RollbackNewImgCaches({std::to_string(rowId)});
    EXPECT_FALSE(formCacheMgr_.GetImgCacheFromDb(rowId, blob, size));
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_027 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_028
 * @tc.desc: Verify DeleteImgCachesInDb with empty and valid rowIds.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_028, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_028 start");
    std::vector<std::string> emptyRowIds;
    EXPECT_FALSE(formCacheMgr_.DeleteImgCachesInDb(emptyRowIds));

    std::vector<uint8_t> value = {4, 5, 6};
    int64_t rowId1 = -1;
    int64_t rowId2 = -1;
    EXPECT_TRUE(formCacheMgr_.SaveImgCacheToDb(value, value.size(), rowId1));
    EXPECT_TRUE(formCacheMgr_.SaveImgCacheToDb(value, value.size(), rowId2));
    std::vector<std::string> rowIds = {std::to_string(rowId1), std::to_string(rowId2)};
    EXPECT_TRUE(formCacheMgr_.DeleteImgCachesInDb(rowIds));

    std::vector<uint8_t> blob;
    int32_t size = 0;
    EXPECT_FALSE(formCacheMgr_.GetImgCacheFromDb(rowId1, blob, size));
    EXPECT_FALSE(formCacheMgr_.GetImgCacheFromDb(rowId2, blob, size));
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_028 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_029
 * @tc.desc: Verify ResetCacheStateAfterReboot keeps the sentinel row cleanup version.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_029, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_029 start");
    formCacheMgr_.SetIsDirtyDataCleaned();
    formCacheMgr_.ResetCacheStateAfterReboot();
    EXPECT_TRUE(formCacheMgr_.IsDirtyDataCleaned());
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_029 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_030
 * @tc.desc: Verify IsDirtyDataCleaned returns false for legacy-format sentinel row.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_030, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_030 start");
    // simulate a device cleaned by the legacy one-shot sweep (empty DATA_CACHE, legacy format)
    formCacheMgr_.SetIsDirtyDataCleaned();
    EXPECT_TRUE(FormRdbDataMgr::GetInstance().ExecuteSql(
        "UPDATE form_cache SET DATA_CACHE = '' WHERE FORM_ID = 'isDirtyDataCleaned'") == ERR_OK);
    EXPECT_FALSE(formCacheMgr_.IsDirtyDataCleaned());
    // sweep again upgrades the stored version
    formCacheMgr_.SetIsDirtyDataCleaned();
    EXPECT_TRUE(formCacheMgr_.IsDirtyDataCleaned());
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_030 end";
}

/*
 * @tc.name: FmsFormCacheMgrTest_031
 * @tc.desc: Verify DeleteInvalidImgCache removes orphan rows and keeps referenced rows.
 * @tc.type: FUNC
 * @tc.level: Level1
 */
HWTEST_F(FmsFormCacheMgrTest, FmsFormCacheMgrTest_031, TestSize.Level1)
{
    HILOG_INFO("FmsFormCacheMgrTest_031 start");
    int64_t formId = 10031;
    // referenced row
    std::vector<uint8_t> value = {7, 8, 9};
    int64_t refRowId = -1;
    EXPECT_TRUE(formCacheMgr_.SaveImgCacheToDb(value, value.size(), refRowId));
    // orphan row without any FORM_IMAGES reference
    int64_t orphanRowId = -1;
    EXPECT_TRUE(formCacheMgr_.SaveImgCacheToDb(value, value.size(), orphanRowId));

    // build a form_cache row whose FORM_IMAGES references refRowId only
    FormCache formCache;
    formCache.formId = std::to_string(formId);
    formCache.imgCache = "{\"test_pic\":" + std::to_string(refRowId) + "}";
    EXPECT_TRUE(formCacheMgr_.SaveDataCacheToDb(formId, formCache));

    std::unordered_set<int64_t> referencedIds;
    EXPECT_TRUE(formCacheMgr_.GetReferencedImgIds(referencedIds));
    EXPECT_NE(referencedIds.find(refRowId), referencedIds.end());
    std::vector<int64_t> allImgIds;
    EXPECT_TRUE(formCacheMgr_.GetAllImgIds(allImgIds));

    formCacheMgr_.DeleteInvalidImgCache();

    std::vector<uint8_t> blob;
    int32_t size = 0;
    EXPECT_FALSE(formCacheMgr_.GetImgCacheFromDb(orphanRowId, blob, size));
    EXPECT_TRUE(formCacheMgr_.GetImgCacheFromDb(refRowId, blob, size));
    // DeleteData removes the form_cache row and its referenced image rows
    EXPECT_TRUE(formCacheMgr_.DeleteData(formId));
    EXPECT_FALSE(formCacheMgr_.GetImgCacheFromDb(refRowId, blob, size));
    GTEST_LOG_(INFO) << "FmsFormCacheMgrTest_031 end";
}
}
