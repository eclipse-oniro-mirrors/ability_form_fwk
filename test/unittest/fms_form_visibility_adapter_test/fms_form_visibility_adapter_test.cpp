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
#include "form_mgr/form_visibility_adapter.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_mgr_errors.h"
#include "data_center/form_record/form_record.h"
#include "iremote_object.h"

#include "mock_form_data_mgr.h"
#include "mock_form_info_mgr.h"
#include "mock_form_bms_helper.h"
#include "mock_form_bundle_lock_mgr.h"
#include "mock_form_exempt_lock_mgr.h"
#include "mock_i_remote_object.h"
#include "mock_ipc_skeleton.h"
#include "mock_bundle_mgr.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 20000000;
constexpr int64_t TEST_FORM_ID = 123456789L;
}

class FmsFormVisibilityAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormVisibilityAdapterTest::SetUpTestCase()
{
    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    MockFormInfoMgr::obj = std::make_shared<MockFormInfoMgr>();
    MockFormBmsHelper::obj = std::make_shared<MockFormBmsHelper>();
    MockFormBundleLockMgr::obj = std::make_shared<MockFormBundleLockMgr>();
    MockFormExemptLockMgr::obj = std::make_shared<MockFormExemptLockMgr>();
    MockIPCSkeleton::obj = new MockIPCSkeleton();
}

void FmsFormVisibilityAdapterTest::TearDownTestCase()
{
    MockFormDataMgr::obj = nullptr;
    MockFormInfoMgr::obj = nullptr;
    MockFormBmsHelper::obj = nullptr;
    MockFormBundleLockMgr::obj = nullptr;
    MockFormExemptLockMgr::obj = nullptr;
    delete MockIPCSkeleton::obj;
    MockIPCSkeleton::obj = nullptr;
}

void FmsFormVisibilityAdapterTest::SetUp()
{
}

void FmsFormVisibilityAdapterTest::TearDown()
{
}

// ========== NotifyWhetherVisibleForms Tests ==========

/**
 * @tc.name: NotifyWhetherVisibleForms_001
 * @tc.desc: Verify nullptr callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyWhetherVisibleForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyWhetherVisibleForms_001 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    auto result = FormVisibilityAdapter::GetInstance().NotifyWhetherVisibleForms(
        formIds, nullptr, Constants::FORM_VISIBLE);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "NotifyWhetherVisibleForms_001 end";
}

/**
 * @tc.name: NotifyWhetherVisibleForms_002
 * @tc.desc: Verify GetBundleMgr returns nullptr returns ERR_APPEXECFWK_FORM_GET_BMS_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyWhetherVisibleForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyWhetherVisibleForms_002 start";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    std::vector<int64_t> formIds = {TEST_FORM_ID};

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));

    auto result = FormVisibilityAdapter::GetInstance().NotifyWhetherVisibleForms(
        formIds, callerToken, Constants::FORM_VISIBLE);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);
    GTEST_LOG_(INFO) << "NotifyWhetherVisibleForms_002 end";
}

/**
 * @tc.name: NotifyWhetherVisibleForms_003
 * @tc.desc: Verify empty formIds with valid callerToken and valid IBundleMgr returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyWhetherVisibleForms_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyWhetherVisibleForms_003 start";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    std::vector<int64_t> formIds;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(sptr<IBundleMgr>(new MockBundleMgrStub())));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormVisibilityAdapter::GetInstance().NotifyWhetherVisibleForms(
        formIds, callerToken, Constants::FORM_VISIBLE);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "NotifyWhetherVisibleForms_003 end";
}

// ========== NotifyFormsVisible Tests ==========

/**
 * @tc.name: NotifyFormsVisible_001
 * @tc.desc: Verify delegates to FormDataMgr::NotifyFormsVisible and returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyFormsVisible_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyFormsVisible_001 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, NotifyFormsVisible(_, true, _, TEST_USER_ID))
        .WillOnce(Return(ERR_OK));

    auto result = FormVisibilityAdapter::GetInstance().NotifyFormsVisible(
        formIds, true, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "NotifyFormsVisible_001 end";
}

// ========== NotifyFormsEnableUpdate Tests ==========

/**
 * @tc.name: NotifyFormsEnableUpdate_001
 * @tc.desc: Verify delegates to HandleUpdateFormFlag via UpdateHostFormFlag
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyFormsEnableUpdate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyFormsEnableUpdate_001 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, UpdateHostFormFlag(_, _, true, true, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormVisibilityAdapter::GetInstance().NotifyFormsEnableUpdate(
        formIds, true, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "NotifyFormsEnableUpdate_001 end";
}

// ========== HandleUpdateFormFlag Tests ==========

/**
 * @tc.name: HandleUpdateFormFlag_001
 * @tc.desc: Verify empty formIds returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HandleUpdateFormFlag_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_001 start";
    std::vector<int64_t> formIds;
    auto result = FormVisibilityAdapter::GetInstance().HandleUpdateFormFlag(
        formIds, nullptr, true, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_001 end";
}

/**
 * @tc.name: HandleUpdateFormFlag_002
 * @tc.desc: Verify nullptr callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HandleUpdateFormFlag_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_002 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    auto result = FormVisibilityAdapter::GetInstance().HandleUpdateFormFlag(
        formIds, nullptr, true, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_002 end";
}

/**
 * @tc.name: HandleUpdateFormFlag_003
 * @tc.desc: Verify UpdateHostFormFlag success with empty refreshForms returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HandleUpdateFormFlag_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_003 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, UpdateHostFormFlag(_, _, true, true, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormVisibilityAdapter::GetInstance().HandleUpdateFormFlag(
        formIds, callerToken, true, true);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "HandleUpdateFormFlag_003 end";
}

// ========== SetFormsRecyclable Tests ==========

/**
 * @tc.name: SetFormsRecyclable_001
 * @tc.desc: Verify all invalid formIds (<=0) returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, SetFormsRecyclable_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormsRecyclable_001 start";
    std::vector<int64_t> formIds = {-1, 0};

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormVisibilityAdapter::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "SetFormsRecyclable_001 end";
}

/**
 * @tc.name: SetFormsRecyclable_002
 * @tc.desc: Verify form record not exists returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, SetFormsRecyclable_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormsRecyclable_002 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    auto result = FormVisibilityAdapter::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "SetFormsRecyclable_002 end";
}

/**
 * @tc.name: SetFormsRecyclable_003
 * @tc.desc: Verify formTempFlag=true skips form and returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, SetFormsRecyclable_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormsRecyclable_003 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};

    FormRecord record;
    record.formTempFlag = true;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormVisibilityAdapter::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "SetFormsRecyclable_003 end";
}

/**
 * @tc.name: SetFormsRecyclable_004
 * @tc.desc: Verify valid form with all conditions met returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, SetFormsRecyclable_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormsRecyclable_004 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};

    FormRecord record;
    record.formTempFlag = false;
    record.isDynamic = true;
    record.uiSyntax = FormType::ETS;
    record.lowMemoryRecycleStatus = LowMemoryRecycleStatus::NON_RECYCLABLE;
    record.formUserUids.push_back(TEST_CALLING_UID);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(true));

    auto result = FormVisibilityAdapter::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "SetFormsRecyclable_004 end";
}

// ========== NotifyFormLocked Tests ==========

/**
 * @tc.name: NotifyFormLocked_001
 * @tc.desc: Verify GetFormRecord fails returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyFormLocked_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyFormLocked_001 start";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    auto result = FormVisibilityAdapter::GetInstance().NotifyFormLocked(TEST_FORM_ID, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    GTEST_LOG_(INFO) << "NotifyFormLocked_001 end";
}

/**
 * @tc.name: NotifyFormLocked_002
 * @tc.desc: Verify bundle unprotected with isLocked=true returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyFormLocked_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyFormLocked_002 start";

    FormRecord record;
    record.bundleName = "com.test.bundle";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(false));

    auto result = FormVisibilityAdapter::GetInstance().NotifyFormLocked(TEST_FORM_ID, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "NotifyFormLocked_002 end";
}

/**
 * @tc.name: NotifyFormLocked_003
 * @tc.desc: Verify protectForm == isLocked (no change) returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyFormLocked_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyFormLocked_003 start";

    FormRecord record;
    record.bundleName = "com.test.bundle";
    record.protectForm = true;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true));

    auto result = FormVisibilityAdapter::GetInstance().NotifyFormLocked(TEST_FORM_ID, true);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "NotifyFormLocked_003 end";
}

/**
 * @tc.name: NotifyFormLocked_004
 * @tc.desc: Verify successful lock change returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyFormLocked_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyFormLocked_004 start";

    FormRecord record;
    record.bundleName = "com.test.bundle";
    record.protectForm = false;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormDataMgr::obj, SetFormProtect(TEST_FORM_ID, true))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockFormDataMgr::obj, LockForms(_, true))
        .Times(1);

    auto result = FormVisibilityAdapter::GetInstance().NotifyFormLocked(TEST_FORM_ID, true);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "NotifyFormLocked_004 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
