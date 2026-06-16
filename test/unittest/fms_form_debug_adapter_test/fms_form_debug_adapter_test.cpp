/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "gmock/gmock.h"
#include <gtest/gtest.h>

#define private public
#define protected public
#include "form_mgr/form_debug_adapter.h"
#undef private
#undef protected

#include "form_mgr_errors.h"
#include "data_center/form_record/form_record.h"
#include "data_center/database/form_db_info.h"

#include "mock_form_data_mgr.h"
#include "mock_form_info_mgr.h"
#include "mock_form_db_cache.h"
#include "mock_form_timer_mgr.h"
#include "mock_form_bms_helper.h"
#include "mock_ipc_skeleton.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int64_t TEST_FORM_ID = 123456789L;
constexpr int64_t TEST_FORM_ID_2 = 987654321L;
}

class FmsFormDebugAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormDebugAdapterTest::SetUpTestCase()
{
    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    MockFormInfoMgr::obj = std::make_shared<MockFormInfoMgr>();
    MockFormDbCache::obj = std::make_shared<MockFormDbCache>();
    MockFormTimerMgr::obj = std::make_shared<MockFormTimerMgr>();
    MockFormBmsHelper::obj = std::make_shared<MockFormBmsHelper>();
    MockIPCSkeleton::obj = new MockIPCSkeleton();
}

void FmsFormDebugAdapterTest::TearDownTestCase()
{
    MockFormDataMgr::obj = nullptr;
    MockFormInfoMgr::obj = nullptr;
    MockFormDbCache::obj = nullptr;
    MockFormTimerMgr::obj = nullptr;
    MockFormBmsHelper::obj = nullptr;
    delete MockIPCSkeleton::obj;
    MockIPCSkeleton::obj = nullptr;
}

void FmsFormDebugAdapterTest::SetUp()
{
}

void FmsFormDebugAdapterTest::TearDown()
{
}

// ========== Method 1: DumpStorageFormInfos Tests ==========

/**
 * @tc.name: DumpStorageFormInfos_001
 * @tc.desc: Verify empty DB returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpStorageFormInfos_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpStorageFormInfos_001 start";

    std::string formInfos;
    std::vector<FormDBInfo> emptyDBInfos;

    EXPECT_CALL(*MockFormDbCache::obj, GetAllFormInfo(_))
        .WillOnce(SetArgReferee<0>(emptyDBInfos));

    auto result = FormDebugAdapter::GetInstance().DumpStorageFormInfos(formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "DumpStorageFormInfos_001 end";
}

/**
 * @tc.name: DumpStorageFormInfos_002
 * @tc.desc: Verify non-empty DB returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpStorageFormInfos_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpStorageFormInfos_002 start";

    std::string formInfos;
    FormDBInfo dbInfo;
    dbInfo.formId = TEST_FORM_ID;
    std::vector<FormDBInfo> dbInfos;
    dbInfos.push_back(dbInfo);

    EXPECT_CALL(*MockFormDbCache::obj, GetAllFormInfo(_))
        .WillOnce(SetArgReferee<0>(dbInfos));

    auto result = FormDebugAdapter::GetInstance().DumpStorageFormInfos(formInfos);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DumpStorageFormInfos_002 end";
}

// ========== Method 2: DumpTemporaryFormInfos Tests ==========

/**
 * @tc.name: DumpTemporaryFormInfos_001
 * @tc.desc: Verify no temp form returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpTemporaryFormInfos_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpTemporaryFormInfos_001 start";

    std::string formInfos;

    EXPECT_CALL(*MockFormDataMgr::obj, GetTempFormRecord(_))
        .WillOnce(Return(false));

    auto result = FormDebugAdapter::GetInstance().DumpTemporaryFormInfos(formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "DumpTemporaryFormInfos_001 end";
}

/**
 * @tc.name: DumpTemporaryFormInfos_002
 * @tc.desc: Verify temp form exists returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpTemporaryFormInfos_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpTemporaryFormInfos_002 start";

    std::string formInfos;
    std::vector<FormRecord> records;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    records.push_back(record);

    EXPECT_CALL(*MockFormDataMgr::obj, GetTempFormRecord(_))
        .WillOnce(DoAll(SetArgReferee<0>(records), Return(true)));

    auto result = FormDebugAdapter::GetInstance().DumpTemporaryFormInfos(formInfos);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DumpTemporaryFormInfos_002 end";
}

// ========== Method 3: DumpStaticBundleFormInfos Tests ==========

/**
 * @tc.name: DumpStaticBundleFormInfos_001
 * @tc.desc: Verify GetAllFormsInfo failure returns ERR_APPEXECFWK_FORM_GET_INFO_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpStaticBundleFormInfos_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpStaticBundleFormInfos_001 start";

    std::string formInfos;

    EXPECT_CALL(*MockFormInfoMgr::obj, GetAllFormsInfo(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_INFO_FAILED));

    auto result = FormDebugAdapter::GetInstance().DumpStaticBundleFormInfos(formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "DumpStaticBundleFormInfos_001 end";
}

/**
 * @tc.name: DumpStaticBundleFormInfos_002
 * @tc.desc: Verify GetAllFormsInfo success returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpStaticBundleFormInfos_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpStaticBundleFormInfos_002 start";

    std::string formInfos;
    std::vector<FormInfo> formInfosList;
    FormInfo formInfo;
    formInfo.name = "widget";
    formInfosList.push_back(formInfo);

    EXPECT_CALL(*MockFormInfoMgr::obj, GetAllFormsInfo(_, _))
        .WillOnce(DoAll(SetArgReferee<0>(formInfosList), Return(ERR_OK)));

    auto result = FormDebugAdapter::GetInstance().DumpStaticBundleFormInfos(formInfos);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DumpStaticBundleFormInfos_002 end";
}

// ========== Method 4: DumpFormInfoByBundleName Tests ==========

/**
 * @tc.name: DumpFormInfoByBundleName_001
 * @tc.desc: Verify no matching form record returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormInfoByBundleName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormInfoByBundleName_001 start";

    std::string formInfos;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(Return(false));

    auto result = FormDebugAdapter::GetInstance().DumpFormInfoByBundleName("com.test.bundle", formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "DumpFormInfoByBundleName_001 end";
}

/**
 * @tc.name: DumpFormInfoByBundleName_002
 * @tc.desc: Verify existing form records with timer update returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormInfoByBundleName_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormInfoByBundleName_002 start";

    std::string formInfos;
    std::vector<FormRecord> records;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.isEnableUpdate = true;
    record.updateDuration = 3600000;
    records.push_back(record);

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(records), Return(true)));
    EXPECT_CALL(*MockFormTimerMgr::obj, GetIntervalTimer(_, _))
        .WillOnce(Return(true));

    auto result = FormDebugAdapter::GetInstance().DumpFormInfoByBundleName("com.test.bundle", formInfos);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DumpFormInfoByBundleName_002 end";
}

/**
 * @tc.name: DumpFormInfoByBundleName_003
 * @tc.desc: Verify existing form records without timer returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormInfoByBundleName_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormInfoByBundleName_003 start";

    std::string formInfos;
    std::vector<FormRecord> records;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.isEnableUpdate = false;
    records.push_back(record);

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(records), Return(true)));

    auto result = FormDebugAdapter::GetInstance().DumpFormInfoByBundleName("com.test.bundle", formInfos);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DumpFormInfoByBundleName_003 end";
}

// ========== Method 5: DumpFormInfoByFormId Tests ==========

/**
 * @tc.name: DumpFormInfoByFormId_001
 * @tc.desc: Verify non-existent formId returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormInfoByFormId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormInfoByFormId_001 start";

    std::string formInfo;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormHostRecord(_, _))
        .WillOnce(SetArgReferee<1>(std::vector<FormHostRecord>()));

    auto result = FormDebugAdapter::GetInstance().DumpFormInfoByFormId(TEST_FORM_ID, formInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "DumpFormInfoByFormId_001 end";
}

/**
 * @tc.name: DumpFormInfoByFormId_002
 * @tc.desc: Verify existing formId returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormInfoByFormId_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormInfoByFormId_002 start";

    std::string formInfo;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.isEnableUpdate = false;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormHostRecord(_, _))
        .WillOnce(SetArgReferee<1>(std::vector<FormHostRecord>()));

    auto result = FormDebugAdapter::GetInstance().DumpFormInfoByFormId(TEST_FORM_ID, formInfo);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DumpFormInfoByFormId_002 end";
}

/**
 * @tc.name: DumpFormInfoByFormId_003
 * @tc.desc: Verify form with host records returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormInfoByFormId_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormInfoByFormId_003 start";

    std::string formInfo;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    std::vector<FormHostRecord> hostRecords;
    FormHostRecord hostRecord;
    hostRecords.push_back(hostRecord);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormHostRecord(_, _))
        .WillOnce(SetArgReferee<1>(hostRecords));

    auto result = FormDebugAdapter::GetInstance().DumpFormInfoByFormId(TEST_FORM_ID, formInfo);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DumpFormInfoByFormId_003 end";
}

// ========== Method 6: DumpFormTimerByFormId Tests ==========

/**
 * @tc.name: DumpFormTimerByFormId_001
 * @tc.desc: Verify interval timer exists returns "true"
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormTimerByFormId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormTimerByFormId_001 start";

    std::string isTimingService;

    EXPECT_CALL(*MockFormTimerMgr::obj, GetIntervalTimer(_, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormTimerMgr::obj, GetUpdateAtTimer(_, _))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormTimerMgr::obj, GetDynamicItem(_, _))
        .WillOnce(Return(false));

    auto result = FormDebugAdapter::GetInstance().DumpFormTimerByFormId(TEST_FORM_ID, isTimingService);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isTimingService, "true");

    GTEST_LOG_(INFO) << "DumpFormTimerByFormId_001 end";
}

/**
 * @tc.name: DumpFormTimerByFormId_002
 * @tc.desc: Verify no timer exists returns "false"
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormTimerByFormId_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormTimerByFormId_002 start";

    std::string isTimingService;

    EXPECT_CALL(*MockFormTimerMgr::obj, GetIntervalTimer(_, _))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormTimerMgr::obj, GetUpdateAtTimer(_, _))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormTimerMgr::obj, GetDynamicItem(_, _))
        .WillOnce(Return(false));

    auto result = FormDebugAdapter::GetInstance().DumpFormTimerByFormId(TEST_FORM_ID, isTimingService);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isTimingService, "false");

    GTEST_LOG_(INFO) << "DumpFormTimerByFormId_002 end";
}

/**
 * @tc.name: DumpFormTimerByFormId_003
 * @tc.desc: Verify updateAt timer exists returns "true"
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormTimerByFormId_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormTimerByFormId_003 start";

    std::string isTimingService;

    EXPECT_CALL(*MockFormTimerMgr::obj, GetIntervalTimer(_, _))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormTimerMgr::obj, GetUpdateAtTimer(_, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormTimerMgr::obj, GetDynamicItem(_, _))
        .WillOnce(Return(false));

    auto result = FormDebugAdapter::GetInstance().DumpFormTimerByFormId(TEST_FORM_ID, isTimingService);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(isTimingService, "true");

    GTEST_LOG_(INFO) << "DumpFormTimerByFormId_003 end";
}

// ========== Method 7: DumpHasFormVisible Tests ==========

/**
 * @tc.name: DumpHasFormVisible_001
 * @tc.desc: Verify valid bundleInfo returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpHasFormVisible_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpHasFormVisible_001 start";

    std::string formInfos;

    auto result = FormDebugAdapter::GetInstance().DumpHasFormVisible("com.test.bundle", formInfos);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DumpHasFormVisible_001 end";
}

// ========== Method 8: DumpFormRunningFormInfos Tests ==========

/**
 * @tc.name: DumpFormRunningFormInfos_001
 * @tc.desc: Verify GetRunningFormInfos failure returns error code
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormRunningFormInfos_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormRunningFormInfos_001 start";

    std::string runningFormInfosResult;

    EXPECT_CALL(*MockFormDataMgr::obj, GetRunningFormInfos(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormDebugAdapter::GetInstance().DumpFormRunningFormInfos(runningFormInfosResult);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "DumpFormRunningFormInfos_001 end";
}

/**
 * @tc.name: DumpFormRunningFormInfos_002
 * @tc.desc: Verify GetRunningFormInfos success returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDebugAdapterTest, DumpFormRunningFormInfos_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DumpFormRunningFormInfos_002 start";

    std::string runningFormInfosResult;

    EXPECT_CALL(*MockFormDataMgr::obj, GetRunningFormInfos(_, _, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormDebugAdapter::GetInstance().DumpFormRunningFormInfos(runningFormInfosResult);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DumpFormRunningFormInfos_002 end";
}

} // namespace AppExecFwk
} // namespace OHOS
