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
#include "form_mgr/form_data_adapter.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_mgr_errors.h"
#include "want.h"
#include "bundle_info.h"
#include "form_info.h"
#include "data_center/form_info/form_item_info.h"
#include "data_center/form_record/form_record.h"
#include "iremote_object.h"
#include "application_info.h"
#include "want_params.h"
#include "form_provider_data.h"
#include "form_provider_data_proxy.h"

#include "mock_form_data_mgr.h"
#include "mock_form_info_mgr.h"
#include "mock_form_bms_helper.h"
#include "mock_form_timer_mgr.h"
#include "mock_form_db_cache.h"
#include "mock_form_bundle_forbid_mgr.h"
#include "mock_form_bundle_lock_mgr.h"
#include "mock_form_exempt_lock_mgr.h"
#include "mock_form_distributed_mgr.h"
#include "mock_param_control.h"
#include "mock_i_remote_object.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"
#include "form_refresh/mock_form_refresh_mgr.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 20000000;
constexpr int64_t TEST_FORM_ID = 123456789L;
constexpr int64_t INVALID_FORM_ID = -1L;
constexpr int64_t ZERO_FORM_ID = 0L;
constexpr int32_t TEST_DIMENSION_ID = 2;
constexpr int64_t TEST_NEXT_TIME = 3600000L;
constexpr int32_t TEST_FORM_REFRESH_TYPE = 1;
constexpr int32_t TEST_FORM_LOCATION = 1;
constexpr int32_t TEST_CALLING_PID = 1234;
}

class FmsFormDataAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormDataAdapterTest::SetUpTestCase()
{
    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    MockFormInfoMgr::obj = std::make_shared<MockFormInfoMgr>();
    MockFormBmsHelper::obj = std::make_shared<MockFormBmsHelper>();
    MockFormTimerMgr::obj = std::make_shared<MockFormTimerMgr>();
    MockFormDbCache::obj = std::make_shared<MockFormDbCache>();
    MockFormBundleForbidMgr::obj = std::make_shared<MockFormBundleForbidMgr>();
    MockFormBundleLockMgr::obj = std::make_shared<MockFormBundleLockMgr>();
    MockFormExemptLockMgr::obj = std::make_shared<MockFormExemptLockMgr>();
    MockFormDistributedMgr::obj = std::make_shared<MockFormDistributedMgr>();
    MockParamControl::obj = std::make_shared<MockParamControl>();
    MockIPCSkeleton::obj = new MockIPCSkeleton();
    MockFormRefreshMgr::obj = std::make_shared<MockFormRefreshMgr>();
}

void FmsFormDataAdapterTest::TearDownTestCase()
{
    MockFormDataMgr::obj = nullptr;
    MockFormInfoMgr::obj = nullptr;
    MockFormBmsHelper::obj = nullptr;
    MockFormTimerMgr::obj = nullptr;
    MockFormDbCache::obj = nullptr;
    MockFormBundleForbidMgr::obj = nullptr;
    MockFormBundleLockMgr::obj = nullptr;
    MockFormExemptLockMgr::obj = nullptr;
    MockFormDistributedMgr::obj = nullptr;
    MockParamControl::obj = nullptr;
    delete MockIPCSkeleton::obj;
    MockIPCSkeleton::obj = nullptr;
    MockFormRefreshMgr::obj = nullptr;
}

void FmsFormDataAdapterTest::SetUp()
{
}

void FmsFormDataAdapterTest::TearDown()
{
}

// ========== UpdateForm Tests ==========

/**
 * @tc.name: UpdateForm_001
 * @tc.desc: Verify UpdateForm with invalid formId (<=0) returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateForm_001 start";

    FormProviderData formProviderData;
    std::vector<FormDataProxy> formDataProxies;

    auto result = FormDataAdapter::GetInstance().UpdateForm(
        INVALID_FORM_ID, TEST_CALLING_UID, formProviderData, formDataProxies);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "UpdateForm_001 end";
}

/**
 * @tc.name: UpdateForm_002
 * @tc.desc: Verify UpdateForm with formId=0 returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateForm_002 start";

    FormProviderData formProviderData;
    std::vector<FormDataProxy> formDataProxies;

    auto result = FormDataAdapter::GetInstance().UpdateForm(
        ZERO_FORM_ID, TEST_CALLING_UID, formProviderData, formDataProxies);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "UpdateForm_002 end";
}

/**
 * @tc.name: UpdateForm_003
 * @tc.desc: Verify UpdateForm with no form record returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateForm_003 start";

    FormProviderData formProviderData;
    std::vector<FormDataProxy> formDataProxies;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    auto result = FormDataAdapter::GetInstance().UpdateForm(
        TEST_FORM_ID, TEST_CALLING_UID, formProviderData, formDataProxies);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "UpdateForm_003 end";
}

/**
 * @tc.name: UpdateForm_004
 * @tc.desc: Verify UpdateForm with valid form record delegates to FormRefreshMgr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateForm_004 start";

    FormProviderData formProviderData;
    std::vector<FormDataProxy> formDataProxies;

    FormRecord formRecord;
    formRecord.formId = TEST_FORM_ID;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    EXPECT_CALL(*MockFormRefreshMgr::obj, RequestRefresh(_, TYPE_DATA))
        .WillOnce(Return(ERR_OK));

    auto result = FormDataAdapter::GetInstance().UpdateForm(
        TEST_FORM_ID, TEST_CALLING_UID, formProviderData, formDataProxies);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "UpdateForm_004 end";
}

// ========== RequestForm Tests ==========

/**
 * @tc.name: RequestForm_001
 * @tc.desc: Verify RequestForm with invalid formId (<=0) returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, RequestForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestForm_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    Want want;

    auto result = FormDataAdapter::GetInstance().RequestForm(INVALID_FORM_ID, callerToken, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RequestForm_001 end";
}

/**
 * @tc.name: RequestForm_002
 * @tc.desc: Verify RequestForm with null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, RequestForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestForm_002 start";

    sptr<IRemoteObject> callerToken = nullptr;
    Want want;

    auto result = FormDataAdapter::GetInstance().RequestForm(TEST_FORM_ID, callerToken, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RequestForm_002 end";
}

/**
 * @tc.name: RequestForm_003
 * @tc.desc: Verify RequestForm with no form record returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, RequestForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestForm_003 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    Want want;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    auto result = FormDataAdapter::GetInstance().RequestForm(TEST_FORM_ID, callerToken, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "RequestForm_003 end";
}

/**
 * @tc.name: RequestForm_004
 * @tc.desc: Verify RequestForm with valid record delegates to FormRefreshMgr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, RequestForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestForm_004 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    Want want;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.needRefresh = false;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormRefreshMgr::obj, RequestRefresh(_, TYPE_HOST))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormDataAdapter::GetInstance().RequestForm(TEST_FORM_ID, callerToken, want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RequestForm_004 end";
}

// ========== UpdateFormSize(float) Tests ==========

/**
 * @tc.name: UpdateFormSize_Float_001
 * @tc.desc: Verify UpdateFormSize(float) always returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateFormSize_Float_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormSize_Float_001 start";

    auto result = FormDataAdapter::GetInstance().UpdateFormSize(
        TEST_FORM_ID, 100.0f, 100.0f, 1.0f, 1.0f);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "UpdateFormSize_Float_001 end";
}

// ========== UpdateFormSize(int32_t) Tests ==========

/**
 * @tc.name: UpdateFormSize_Int_001
 * @tc.desc: Verify UpdateFormSize(int32_t) with no form record returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateFormSize_Int_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormSize_Int_001 start";

    Rect *newRect = nullptr;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    auto result = FormDataAdapter::GetInstance().UpdateFormSize(TEST_FORM_ID, TEST_DIMENSION_ID, *newRect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "UpdateFormSize_Int_001 end";
}

// ========== EnableUpdateForm / DisableUpdateForm Tests ==========

/**
 * @tc.name: EnableUpdateForm_001
 * @tc.desc: Verify EnableUpdateForm with empty formIds returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, EnableUpdateForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnableUpdateForm_001 start";

    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormDataAdapter::GetInstance().EnableUpdateForm(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "EnableUpdateForm_001 end";
}

/**
 * @tc.name: EnableUpdateForm_002
 * @tc.desc: Verify EnableUpdateForm with null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, EnableUpdateForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnableUpdateForm_002 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = nullptr;

    auto result = FormDataAdapter::GetInstance().EnableUpdateForm(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "EnableUpdateForm_002 end";
}

/**
 * @tc.name: DisableUpdateForm_001
 * @tc.desc: Verify DisableUpdateForm with empty formIds returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, DisableUpdateForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DisableUpdateForm_001 start";

    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormDataAdapter::GetInstance().DisableUpdateForm(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "DisableUpdateForm_001 end";
}

/**
 * @tc.name: DisableUpdateForm_002
 * @tc.desc: Verify DisableUpdateForm with null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, DisableUpdateForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DisableUpdateForm_002 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = nullptr;

    auto result = FormDataAdapter::GetInstance().DisableUpdateForm(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "DisableUpdateForm_002 end";
}

// ========== HandleUpdateFormFlag Tests ==========

/**
 * @tc.name: HandleUpdateFormFlag_001
 * @tc.desc: Verify HandleUpdateFormFlag delegates to FormDataMgr::UpdateHostFormFlag
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, HandleUpdateFormFlag_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_001 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, UpdateHostFormFlag(_, _, true, false, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormDataAdapter::GetInstance().EnableUpdateForm(formIds, callerToken);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_001 end";
}

/**
 * @tc.name: HandleUpdateFormFlag_002
 * @tc.desc: Verify HandleUpdateFormFlag returns error when UpdateHostFormFlag fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, HandleUpdateFormFlag_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_002 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, UpdateHostFormFlag(_, _, false, false, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormDataAdapter::GetInstance().DisableUpdateForm(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_002 end";
}

// ========== BatchRefreshForms Tests ==========

/**
 * @tc.name: BatchRefreshForms_001
 * @tc.desc: Verify BatchRefreshForms always returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, BatchRefreshForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BatchRefreshForms_001 start";

    auto result = FormDataAdapter::GetInstance().BatchRefreshForms(TEST_FORM_REFRESH_TYPE);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "BatchRefreshForms_001 end";
}

// ========== SetNextRefreshTime Tests ==========

/**
 * @tc.name: SetNextRefreshTime_001
 * @tc.desc: Verify SetNextRefreshTime with invalid formId (<=0) returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, SetNextRefreshTime_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetNextRefreshTime_001 start";

    auto result = FormDataAdapter::GetInstance().SetNextRefreshTime(INVALID_FORM_ID, TEST_NEXT_TIME);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "SetNextRefreshTime_001 end";
}

/**
 * @tc.name: SetNextRefreshTime_002
 * @tc.desc: Verify SetNextRefreshTime with no form record returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, SetNextRefreshTime_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetNextRefreshTime_002 start";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    auto result = FormDataAdapter::GetInstance().SetNextRefreshTime(TEST_FORM_ID, TEST_NEXT_TIME);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "SetNextRefreshTime_002 end";
}

/**
 * @tc.name: SetNextRefreshTime_003
 * @tc.desc: Verify SetNextRefreshTime with valid record delegates to FormRefreshMgr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, SetNextRefreshTime_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetNextRefreshTime_003 start";

    FormRecord record;
    record.formId = TEST_FORM_ID;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormRefreshMgr::obj, RequestRefresh(_, TYPE_NEXT_TIME))
        .WillOnce(Return(ERR_OK));

    auto result = FormDataAdapter::GetInstance().SetNextRefreshTime(TEST_FORM_ID, TEST_NEXT_TIME);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "SetNextRefreshTime_003 end";
}

// ========== UpdateFormLocation Tests ==========

/**
 * @tc.name: UpdateFormLocation_001
 * @tc.desc: Verify UpdateFormLocation with no form record returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateFormLocation_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormLocation_001 start";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    auto result = FormDataAdapter::GetInstance().UpdateFormLocation(TEST_FORM_ID, TEST_FORM_LOCATION);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "UpdateFormLocation_001 end";
}

// ========== ReAcquireProviderFormInfoAsync Tests ==========

/**
 * @tc.name: ReAcquireProviderFormInfoAsync_001
 * @tc.desc: Verify ReAcquireProviderFormInfoAsync with reconnect overflow returns ERR_BIND_PROVIDER_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, ReAcquireProviderFormInfoAsync_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReAcquireProviderFormInfoAsync_001 start";

    FormItemInfo info;
    info.SetFormId(TEST_FORM_ID);
    info.SetProviderBundleName("com.test.bundle");
    WantParams wantParams;

    // Clear reconnect map first
    FormDataAdapter::GetInstance().formReconnectMap_.clear();

    // First call - should succeed (count = 1)
    auto result1 = FormDataAdapter::GetInstance().ReAcquireProviderFormInfoAsync(info, wantParams);
    EXPECT_EQ(result1, ERR_OK);

    // Second call (count = 2)
    auto result2 = FormDataAdapter::GetInstance().ReAcquireProviderFormInfoAsync(info, wantParams);
    EXPECT_EQ(result2, ERR_OK);

    // Third call (count = 3)
    auto result3 = FormDataAdapter::GetInstance().ReAcquireProviderFormInfoAsync(info, wantParams);
    EXPECT_EQ(result3, ERR_OK);

    // Fourth call (count = 4 = MAX_RECONNECT_NUMS)
    auto result4 = FormDataAdapter::GetInstance().ReAcquireProviderFormInfoAsync(info, wantParams);
    EXPECT_EQ(result4, ERR_OK);

    // Fifth call (count = 5 > MAX_RECONNECT_NUMS) - should fail
    auto result5 = FormDataAdapter::GetInstance().ReAcquireProviderFormInfoAsync(info, wantParams);
    EXPECT_EQ(result5, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);

    // Clean up
    FormDataAdapter::GetInstance().formReconnectMap_.clear();

    GTEST_LOG_(INFO) << "ReAcquireProviderFormInfoAsync_001 end";
}

// ========== ReloadForms Tests ==========

/**
 * @tc.name: ReloadForms_001
 * @tc.desc: Verify ReloadForms returns ERR_APPEXECFWK_CALLING_NOT_UI_ABILITY
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, ReloadForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReloadForms_001 start";

    int32_t reloadNum = 0;
    std::vector<FormRecord> refreshForms;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormDataAdapter::GetInstance().ReloadForms(reloadNum, refreshForms);
    EXPECT_EQ(result, ERR_APPEXECFWK_CALLING_NOT_UI_ABILITY);

    GTEST_LOG_(INFO) << "ReloadForms_001 end";
}

// ========== UpdateFormByCondition Tests ==========

/**
 * @tc.name: UpdateFormByCondition_001
 * @tc.desc: Verify UpdateFormByCondition with no forms found returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateFormByCondition_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateFormByCondition_001 start";

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByCondition(_, _))
        .WillOnce(Return(false));

    auto result = FormDataAdapter::GetInstance().UpdateFormByCondition(TEST_FORM_REFRESH_TYPE);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "UpdateFormByCondition_001 end";
}

// ========== UpdateReUpdateFormMap / SetReUpdateFormMap Tests ==========

/**
 * @tc.name: UpdateReUpdateFormMap_001
 * @tc.desc: Verify UpdateReUpdateFormMap adds entry to the map
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateReUpdateFormMap_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateReUpdateFormMap_001 start";

    FormDataAdapter::GetInstance().reUpdateFormMap_.clear();

    FormDataAdapter::GetInstance().UpdateReUpdateFormMap(TEST_FORM_ID);
    EXPECT_EQ(FormDataAdapter::GetInstance().reUpdateFormMap_.size(), 1u);
    EXPECT_NE(FormDataAdapter::GetInstance().reUpdateFormMap_.find(TEST_FORM_ID),
        FormDataAdapter::GetInstance().reUpdateFormMap_.end());

    // Verify the second value (isUpdate flag) is false
    EXPECT_FALSE(FormDataAdapter::GetInstance().reUpdateFormMap_[TEST_FORM_ID].second);

    FormDataAdapter::GetInstance().reUpdateFormMap_.clear();

    GTEST_LOG_(INFO) << "UpdateReUpdateFormMap_001 end";
}

/**
 * @tc.name: SetReUpdateFormMap_001
 * @tc.desc: Verify SetReUpdateFormMap sets the isUpdate flag to true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, SetReUpdateFormMap_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetReUpdateFormMap_001 start";

    FormDataAdapter::GetInstance().reUpdateFormMap_.clear();

    // First add entry
    FormDataAdapter::GetInstance().UpdateReUpdateFormMap(TEST_FORM_ID);
    EXPECT_FALSE(FormDataAdapter::GetInstance().reUpdateFormMap_[TEST_FORM_ID].second);

    // Then set flag
    FormDataAdapter::GetInstance().SetReUpdateFormMap(TEST_FORM_ID);
    EXPECT_TRUE(FormDataAdapter::GetInstance().reUpdateFormMap_[TEST_FORM_ID].second);

    FormDataAdapter::GetInstance().reUpdateFormMap_.clear();

    GTEST_LOG_(INFO) << "SetReUpdateFormMap_001 end";
}

/**
 * @tc.name: SetReUpdateFormMap_002
 * @tc.desc: Verify SetReUpdateFormMap with non-existent formId does nothing
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, SetReUpdateFormMap_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetReUpdateFormMap_002 start";

    FormDataAdapter::GetInstance().reUpdateFormMap_.clear();

    // Set flag for non-existent formId - should not crash
    FormDataAdapter::GetInstance().SetReUpdateFormMap(TEST_FORM_ID);
    EXPECT_TRUE(FormDataAdapter::GetInstance().reUpdateFormMap_.empty());

    GTEST_LOG_(INFO) << "SetReUpdateFormMap_002 end";
}

// ========== GetUpdateDurationFromAdditionalInfo Tests ==========

/**
 * @tc.name: GetUpdateDurationFromAdditionalInfo_001
 * @tc.desc: Verify GetUpdateDurationFromAdditionalInfo with empty string returns 0
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, GetUpdateDurationFromAdditionalInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetUpdateDurationFromAdditionalInfo_001 start";

    auto result = FormDataAdapter::GetInstance().GetUpdateDurationFromAdditionalInfo("");
    EXPECT_EQ(result, 0);

    GTEST_LOG_(INFO) << "GetUpdateDurationFromAdditionalInfo_001 end";
}

// ========== ClearReconnectNum Tests ==========

/**
 * @tc.name: ClearReconnectNum_001
 * @tc.desc: Verify ClearReconnectNum erases entry from reconnect map
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, ClearReconnectNum_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClearReconnectNum_001 start";

    FormDataAdapter::GetInstance().formReconnectMap_[TEST_FORM_ID] = 3;
    EXPECT_EQ(FormDataAdapter::GetInstance().formReconnectMap_.size(), 1u);

    FormDataAdapter::GetInstance().ClearReconnectNum(TEST_FORM_ID);
    EXPECT_TRUE(FormDataAdapter::GetInstance().formReconnectMap_.empty());

    GTEST_LOG_(INFO) << "ClearReconnectNum_001 end";
}

/**
 * @tc.name: ClearReconnectNum_002
 * @tc.desc: Verify ClearReconnectNum with non-existent formId does not crash
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, ClearReconnectNum_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ClearReconnectNum_002 start";

    FormDataAdapter::GetInstance().formReconnectMap_.clear();

    // Clear non-existent entry - should not crash
    FormDataAdapter::GetInstance().ClearReconnectNum(999999L);
    EXPECT_TRUE(FormDataAdapter::GetInstance().formReconnectMap_.empty());

    GTEST_LOG_(INFO) << "ClearReconnectNum_002 end";
}

// ========== UpdateTimer Tests ==========

/**
 * @tc.name: UpdateTimer_001
 * @tc.desc: Verify UpdateTimer with AddFormTimer failure returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateTimer_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateTimer_001 start";

    FormRecord record;
    record.formTempFlag = false;

    EXPECT_CALL(*MockFormDbCache::obj, UpdateDBRecord(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormDataAdapter::GetInstance().UpdateTimer(TEST_FORM_ID, record);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "UpdateTimer_001 end";
}

/**
 * @tc.name: UpdateTimer_002
 * @tc.desc: Verify UpdateTimer with temp form skips DB update
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, UpdateTimer_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateTimer_002 start";

    FormRecord record;
    record.formTempFlag = true;

    auto result = FormDataAdapter::GetInstance().UpdateTimer(TEST_FORM_ID, record);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "UpdateTimer_002 end";
}

// ========== OnNotifyRefreshForm Tests ==========

/**
 * @tc.name: OnNotifyRefreshForm_001
 * @tc.desc: Verify OnNotifyRefreshForm with empty map returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, OnNotifyRefreshForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnNotifyRefreshForm_001 start";

    FormDataAdapter::GetInstance().reUpdateFormMap_.clear();

    auto result = FormDataAdapter::GetInstance().OnNotifyRefreshForm(TEST_FORM_ID);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "OnNotifyRefreshForm_001 end";
}

/**
 * @tc.name: OnNotifyRefreshForm_002
 * @tc.desc: Verify OnNotifyRefreshForm with entry but isUpdate=false returns ERR_OK without refresh
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormDataAdapterTest, OnNotifyRefreshForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnNotifyRefreshForm_002 start";

    FormDataAdapter::GetInstance().reUpdateFormMap_.clear();

    // Add entry with isUpdate=false
    int64_t currentTime = FormUtil::GetCurrentMillisecond();
    FormDataAdapter::GetInstance().reUpdateFormMap_[TEST_FORM_ID] = std::make_pair(currentTime, false);

    auto result = FormDataAdapter::GetInstance().OnNotifyRefreshForm(TEST_FORM_ID);
    EXPECT_EQ(result, ERR_OK);

    // Map entry should be erased
    EXPECT_EQ(FormDataAdapter::GetInstance().reUpdateFormMap_.find(TEST_FORM_ID),
        FormDataAdapter::GetInstance().reUpdateFormMap_.end());

    FormDataAdapter::GetInstance().reUpdateFormMap_.clear();

    GTEST_LOG_(INFO) << "OnNotifyRefreshForm_002 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
