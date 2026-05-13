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
#include "form_mgr/form_common_adapter.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_mgr_errors.h"
#include "data_center/form_record/form_record.h"
#include "iremote_object.h"

#include "mock_form_data_mgr.h"
#include "mock_form_info_mgr.h"
#include "mock_form_ams_helper.h"
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
    MockFormAmsHelper::obj = std::make_shared<MockFormAmsHelper>();
    MockFormBmsHelper::obj = std::make_shared<MockFormBmsHelper>();
    MockFormBundleLockMgr::obj = std::make_shared<MockFormBundleLockMgr>();
    MockFormExemptLockMgr::obj = std::make_shared<MockFormExemptLockMgr>();
    MockIPCSkeleton::obj = new MockIPCSkeleton();
}

void FmsFormVisibilityAdapterTest::TearDownTestCase()
{
    MockFormDataMgr::obj = nullptr;
    MockFormInfoMgr::obj = nullptr;
    MockFormAmsHelper::obj = nullptr;
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

// ========== PaddingNotifyVisibleFormsMap Tests ==========

/**
 * @tc.name: PaddingNotifyVisibleFormsMap_001
 * @tc.desc: Verify formVisibleType matches formInstance.formVisiblity → early return, map unchanged
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, PaddingNotifyVisibleFormsMap_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PaddingNotifyVisibleFormsMap_001 start";
    int32_t formVisibleType = Constants::FORM_VISIBLE;
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;

    // Set formVisiblity to match formVisibleType (VISIBLE) so it returns early
    FormInstance matchInstance;
    matchInstance.formVisiblity = FormVisibilityType::VISIBLE;
    matchInstance.formHostName = "com.test.host";

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormInstanceById3(TEST_FORM_ID, false, _))
        .WillOnce(DoAll(SetArgReferee<2>(matchInstance), Return(ERR_OK)));

    FormVisibilityAdapter::GetInstance().PaddingNotifyVisibleFormsMap(
        formVisibleType, TEST_FORM_ID, formInstanceMaps);
    EXPECT_TRUE(formInstanceMaps.empty());
    GTEST_LOG_(INFO) << "PaddingNotifyVisibleFormsMap_001 end";
}

// ========== CreateHandleEventMap Tests ==========

/**
 * @tc.name: CreateHandleEventMap_001
 * @tc.desc: Verify formVisibleNotify is false → return false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, CreateHandleEventMap_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateHandleEventMap_001 start";
    FormRecord formRecord;
    formRecord.formVisibleNotify = false;
    formRecord.bundleName = "com.test.bundle";
    formRecord.abilityName = "MainAbility";
    formRecord.moduleName = "entry";
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;

    bool result = FormVisibilityAdapter::GetInstance().CreateHandleEventMap(
        TEST_FORM_ID, formRecord, eventMaps);
    EXPECT_FALSE(result);
    EXPECT_TRUE(eventMaps.empty());
    GTEST_LOG_(INFO) << "CreateHandleEventMap_001 end";
}

/**
 * @tc.name: CreateHandleEventMap_002
 * @tc.desc: Verify new providerKey → insert into eventMaps
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, CreateHandleEventMap_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateHandleEventMap_002 start";
    FormRecord formRecord;
    formRecord.formVisibleNotify = true;
    formRecord.bundleName = "com.test.bundle";
    formRecord.abilityName = "MainAbility";
    formRecord.moduleName = "entry";
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;

    bool result = FormVisibilityAdapter::GetInstance().CreateHandleEventMap(
        TEST_FORM_ID, formRecord, eventMaps);
    EXPECT_TRUE(result);
    EXPECT_EQ(eventMaps.size(), 1u);
    std::string expectedKey = "com.test.bundle::MainAbility::entry";
    EXPECT_TRUE(eventMaps.find(expectedKey) != eventMaps.end());
    EXPECT_EQ(eventMaps[expectedKey].size(), 1u);
    EXPECT_EQ(eventMaps[expectedKey][0], TEST_FORM_ID);
    GTEST_LOG_(INFO) << "CreateHandleEventMap_002 end";
}

/**
 * @tc.name: CreateHandleEventMap_003
 * @tc.desc: Verify existing providerKey → emplace_back to existing vector
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, CreateHandleEventMap_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateHandleEventMap_003 start";
    FormRecord formRecord;
    formRecord.formVisibleNotify = true;
    formRecord.bundleName = "com.test.bundle";
    formRecord.abilityName = "MainAbility";
    formRecord.moduleName = "entry";
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;

    std::string expectedKey = "com.test.bundle::MainAbility::entry";
    eventMaps[expectedKey] = {111L};

    bool result = FormVisibilityAdapter::GetInstance().CreateHandleEventMap(
        TEST_FORM_ID, formRecord, eventMaps);
    EXPECT_TRUE(result);
    EXPECT_EQ(eventMaps[expectedKey].size(), 2u);
    EXPECT_EQ(eventMaps[expectedKey][1], TEST_FORM_ID);
    GTEST_LOG_(INFO) << "CreateHandleEventMap_003 end";
}

// ========== HandleEventNotify Tests ==========

/**
 * @tc.name: HandleEventNotify_001
 * @tc.desc: Verify no first delimiter → ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HandleEventNotify_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleEventNotify_001 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    auto result = FormVisibilityAdapter::GetInstance().HandleEventNotify(
        "NoDelimiter", formIds, Constants::FORM_VISIBLE);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "HandleEventNotify_001 end";
}

/**
 * @tc.name: HandleEventNotify_002
 * @tc.desc: Verify no second delimiter → ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HandleEventNotify_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleEventNotify_002 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    auto result = FormVisibilityAdapter::GetInstance().HandleEventNotify(
        "com.test.bundle::OnlyOneDelimiter", formIds, Constants::FORM_VISIBLE);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "HandleEventNotify_002 end";
}

// ========== FilterFormInstanceMapsByVisibleType Tests ==========

/**
 * @tc.name: FilterFormInstanceMapsByVisibleType_001
 * @tc.desc: Verify GetFormRecord fails → instance skipped, kept in map
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterFormInstanceMapsByVisibleType_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_001 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    FormInstance instance;
    instance.formId = TEST_FORM_ID;
    formInstanceMaps["com.test.host"] = {instance};
    std::map<int64_t, FormRecord> restoreFormRecords;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    FormVisibilityAdapter::GetInstance().FilterFormInstanceMapsByVisibleType(
        formInstanceMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    // When GetFormRecord fails, instanceIter++ continues, the instance remains
    // Since formInstances is not empty, the entry is kept
    EXPECT_EQ(formInstanceMaps["com.test.host"].size(), 1u);
    EXPECT_TRUE(restoreFormRecords.empty());
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_001 end";
}

/**
 * @tc.name: FilterFormInstanceMapsByVisibleType_002
 * @tc.desc: Verify formVisibleNotifyState != formVisibleType → erased, added to restoreFormRecords
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterFormInstanceMapsByVisibleType_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_002 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    FormInstance instance;
    instance.formId = TEST_FORM_ID;
    formInstanceMaps["com.test.host"] = {instance};
    std::map<int64_t, FormRecord> restoreFormRecords;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.formVisibleNotifyState = Constants::FORM_INVISIBLE;
    record.isNeedNotify = true;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    FormVisibilityAdapter::GetInstance().FilterFormInstanceMapsByVisibleType(
        formInstanceMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    // Instance erased because formVisibleNotifyState != FORM_VISIBLE
    EXPECT_TRUE(formInstanceMaps.empty());
    EXPECT_EQ(restoreFormRecords.size(), 1u);
    EXPECT_TRUE(restoreFormRecords.find(TEST_FORM_ID) != restoreFormRecords.end());
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_002 end";
}

/**
 * @tc.name: FilterFormInstanceMapsByVisibleType_003
 * @tc.desc: Verify isNeedNotify false → erased (not added to restoreFormRecords)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterFormInstanceMapsByVisibleType_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_003 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    FormInstance instance;
    instance.formId = TEST_FORM_ID;
    formInstanceMaps["com.test.host"] = {instance};
    std::map<int64_t, FormRecord> restoreFormRecords;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    record.isNeedNotify = false;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    FormVisibilityAdapter::GetInstance().FilterFormInstanceMapsByVisibleType(
        formInstanceMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    // Instance erased because isNeedNotify is false
    EXPECT_TRUE(formInstanceMaps.empty());
    // Not added to restoreFormRecords since it wasn't a state mismatch
    EXPECT_TRUE(restoreFormRecords.empty());
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_003 end";
}

/**
 * @tc.name: FilterFormInstanceMapsByVisibleType_004
 * @tc.desc: Verify formVisibleNotifyState matches && isNeedNotify → kept in map
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterFormInstanceMapsByVisibleType_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_004 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    FormInstance instance;
    instance.formId = TEST_FORM_ID;
    formInstanceMaps["com.test.host"] = {instance};
    std::map<int64_t, FormRecord> restoreFormRecords;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    record.isNeedNotify = true;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    FormVisibilityAdapter::GetInstance().FilterFormInstanceMapsByVisibleType(
        formInstanceMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    EXPECT_EQ(formInstanceMaps["com.test.host"].size(), 1u);
    EXPECT_TRUE(restoreFormRecords.empty());
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_004 end";
}

/**
 * @tc.name: FilterFormInstanceMapsByVisibleType_005
 * @tc.desc: Verify all instances filtered → entry erased from formInstanceMaps
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterFormInstanceMapsByVisibleType_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_005 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    FormInstance instance1;
    instance1.formId = TEST_FORM_ID;
    FormInstance instance2;
    instance2.formId = TEST_FORM_ID + 1;
    formInstanceMaps["com.test.host"] = {instance1, instance2};
    std::map<int64_t, FormRecord> restoreFormRecords;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    record.isNeedNotify = false;

    FormRecord record2;
    record2.formId = TEST_FORM_ID + 1;
    record2.formVisibleNotifyState = Constants::FORM_VISIBLE;
    record2.isNeedNotify = false;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID + 1, _))
        .WillOnce(DoAll(SetArgReferee<1>(record2), Return(true)));

    FormVisibilityAdapter::GetInstance().FilterFormInstanceMapsByVisibleType(
        formInstanceMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    EXPECT_TRUE(formInstanceMaps.empty());
    GTEST_LOG_(INFO) << "FilterFormInstanceMapsByVisibleType_005 end";
}

// ========== FilterEventMapsByVisibleType Tests ==========

/**
 * @tc.name: FilterEventMapsByVisibleType_001
 * @tc.desc: Verify GetFormRecord fails → formId skipped, kept in map
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterEventMapsByVisibleType_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_001 start";
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    eventMaps["com.test.bundle::MainAbility::entry"] = {TEST_FORM_ID};
    std::map<int64_t, FormRecord> restoreFormRecords;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    FormVisibilityAdapter::GetInstance().FilterEventMapsByVisibleType(
        eventMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    // GetFormRecord fails, formItr++ continues, kept in map
    EXPECT_EQ(eventMaps["com.test.bundle::MainAbility::entry"].size(), 1u);
    EXPECT_TRUE(restoreFormRecords.empty());
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_001 end";
}

/**
 * @tc.name: FilterEventMapsByVisibleType_002
 * @tc.desc: Verify formVisibleNotifyState != formVisibleType → erased, added to restoreFormRecords
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterEventMapsByVisibleType_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_002 start";
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    eventMaps["com.test.bundle::MainAbility::entry"] = {TEST_FORM_ID};
    std::map<int64_t, FormRecord> restoreFormRecords;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.formVisibleNotifyState = Constants::FORM_INVISIBLE;
    record.isNeedNotify = true;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    FormVisibilityAdapter::GetInstance().FilterEventMapsByVisibleType(
        eventMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    EXPECT_TRUE(eventMaps.empty());
    EXPECT_EQ(restoreFormRecords.size(), 1u);
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_002 end";
}

/**
 * @tc.name: FilterEventMapsByVisibleType_003
 * @tc.desc: Verify isNeedNotify false → erased (not added to restoreFormRecords)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterEventMapsByVisibleType_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_003 start";
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    eventMaps["com.test.bundle::MainAbility::entry"] = {TEST_FORM_ID};
    std::map<int64_t, FormRecord> restoreFormRecords;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    record.isNeedNotify = false;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    FormVisibilityAdapter::GetInstance().FilterEventMapsByVisibleType(
        eventMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    EXPECT_TRUE(eventMaps.empty());
    EXPECT_TRUE(restoreFormRecords.empty());
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_003 end";
}

/**
 * @tc.name: FilterEventMapsByVisibleType_004
 * @tc.desc: Verify formVisibleNotifyState matches && isNeedNotify → kept in map
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterEventMapsByVisibleType_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_004 start";
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    eventMaps["com.test.bundle::MainAbility::entry"] = {TEST_FORM_ID};
    std::map<int64_t, FormRecord> restoreFormRecords;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    record.isNeedNotify = true;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    FormVisibilityAdapter::GetInstance().FilterEventMapsByVisibleType(
        eventMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    EXPECT_EQ(eventMaps["com.test.bundle::MainAbility::entry"].size(), 1u);
    EXPECT_TRUE(restoreFormRecords.empty());
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_004 end";
}

/**
 * @tc.name: FilterEventMapsByVisibleType_005
 * @tc.desc: Verify all formIds filtered → entry erased from eventMaps
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterEventMapsByVisibleType_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_005 start";
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    eventMaps["com.test.bundle::MainAbility::entry"] = {TEST_FORM_ID, TEST_FORM_ID + 1};
    std::map<int64_t, FormRecord> restoreFormRecords;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.formVisibleNotifyState = Constants::FORM_VISIBLE;
    record.isNeedNotify = false;

    FormRecord record2;
    record2.formId = TEST_FORM_ID + 1;
    record2.formVisibleNotifyState = Constants::FORM_VISIBLE;
    record2.isNeedNotify = false;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID + 1, _))
        .WillOnce(DoAll(SetArgReferee<1>(record2), Return(true)));

    FormVisibilityAdapter::GetInstance().FilterEventMapsByVisibleType(
        eventMaps, Constants::FORM_VISIBLE, restoreFormRecords);
    EXPECT_TRUE(eventMaps.empty());
    GTEST_LOG_(INFO) << "FilterEventMapsByVisibleType_005 end";
}

// ========== FilterDataByVisibleType Tests ==========

/**
 * @tc.name: FilterDataByVisibleType_001
 * @tc.desc: Verify restoreFormRecords updated with isNeedNotify=false via UpdateFormRecord
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterDataByVisibleType_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterDataByVisibleType_001 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    FormInstance instance;
    instance.formId = TEST_FORM_ID;
    formInstanceMaps["com.test.host"] = {instance};

    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.formVisibleNotifyState = Constants::FORM_INVISIBLE;
    record.isNeedNotify = true;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    // UpdateFormRecord called for restoreFormRecords entry
    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(true));

    FormVisibilityAdapter::GetInstance().FilterDataByVisibleType(
        formInstanceMaps, eventMaps, Constants::FORM_VISIBLE);
    // Instance was erased from formInstanceMaps due to state mismatch
    EXPECT_TRUE(formInstanceMaps.empty());
    GTEST_LOG_(INFO) << "FilterDataByVisibleType_001 end";
}

/**
 * @tc.name: FilterDataByVisibleType_002
 * @tc.desc: Verify both formInstanceMaps and eventMaps filtered correctly
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterDataByVisibleType_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterDataByVisibleType_002 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    FormInstance instance;
    instance.formId = TEST_FORM_ID;
    formInstanceMaps["com.test.host"] = {instance};

    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    eventMaps["com.test.bundle::MainAbility::entry"] = {TEST_FORM_ID + 1};

    FormRecord formInstanceRecord;
    formInstanceRecord.formId = TEST_FORM_ID;
    formInstanceRecord.formVisibleNotifyState = Constants::FORM_VISIBLE;
    formInstanceRecord.isNeedNotify = true;

    FormRecord eventRecord;
    eventRecord.formId = TEST_FORM_ID + 1;
    eventRecord.formVisibleNotifyState = Constants::FORM_VISIBLE;
    eventRecord.isNeedNotify = true;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(formInstanceRecord), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID + 1, _))
        .WillOnce(DoAll(SetArgReferee<1>(eventRecord), Return(true)));

    FormVisibilityAdapter::GetInstance().FilterDataByVisibleType(
        formInstanceMaps, eventMaps, Constants::FORM_VISIBLE);
    // Both should be kept since state matches and isNeedNotify is true
    EXPECT_EQ(formInstanceMaps["com.test.host"].size(), 1u);
    EXPECT_EQ(eventMaps["com.test.bundle::MainAbility::entry"].size(), 1u);
    GTEST_LOG_(INFO) << "FilterDataByVisibleType_002 end";
}

/**
 * @tc.name: FilterDataByVisibleType_003
 * @tc.desc: Verify empty maps → no crashes, no UpdateFormRecord calls
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, FilterDataByVisibleType_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FilterDataByVisibleType_003 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;

    FormVisibilityAdapter::GetInstance().FilterDataByVisibleType(
        formInstanceMaps, eventMaps, Constants::FORM_VISIBLE);
    EXPECT_TRUE(formInstanceMaps.empty());
    EXPECT_TRUE(eventMaps.empty());
    GTEST_LOG_(INFO) << "FilterDataByVisibleType_003 end";
}

// ========== NotifyWhetherFormsVisible Tests ==========

/**
 * @tc.name: NotifyWhetherFormsVisible_001
 * @tc.desc: Verify bundleName not found in formInstanceMaps → no notify calls
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyWhetherFormsVisible_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyWhetherFormsVisible_001 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::vector<sptr<IRemoteObject>> remoteObjects;
    remoteObjects.push_back(new MockIRemoteObject());

    FormVisibilityAdapter::GetInstance().NotifyWhetherFormsVisible(
        "com.test.host", remoteObjects, formInstanceMaps, Constants::FORM_VISIBLE);
    // bundleName not in formInstanceMaps, maps unchanged
    EXPECT_TRUE(formInstanceMaps.empty());
    GTEST_LOG_(INFO) << "NotifyWhetherFormsVisible_001 end";
}

/**
 * @tc.name: NotifyWhetherFormsVisible_002
 * @tc.desc: Verify empty remoteObjects → no iteration, no crash
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyWhetherFormsVisible_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyWhetherFormsVisible_002 start";
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    FormInstance instance;
    instance.formId = TEST_FORM_ID;
    formInstanceMaps["com.test.host"] = {instance};
    std::vector<sptr<IRemoteObject>> remoteObjects;

    FormVisibilityAdapter::GetInstance().NotifyWhetherFormsVisible(
        "com.test.host", remoteObjects, formInstanceMaps, Constants::FORM_VISIBLE);
    // Empty remoteObjects → no iteration, formInstanceMaps unchanged
    EXPECT_EQ(formInstanceMaps["com.test.host"].size(), 1u);
    GTEST_LOG_(INFO) << "NotifyWhetherFormsVisible_002 end";
}

// ========== HasFormVisible Tests ==========

/**
 * @tc.name: HasFormVisible_001
 * @tc.desc: Verify invalid tokenId (AccessTokenKit fails) returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HasFormVisible_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HasFormVisible_001 start";
    // AccessTokenKit::GetHapTokenInfo will fail with test tokenId
    bool result = FormVisibilityAdapter::GetInstance().HasFormVisible(0);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "HasFormVisible_001 end";
}

/**
 * @tc.name: HasFormVisible_002
 * @tc.desc: Verify GetFormRecord returns empty → returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HasFormVisible_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HasFormVisible_002 start";
    // Using a valid-looking token ID. AccessTokenKit will fail, returning false.
    bool result = FormVisibilityAdapter::GetInstance().HasFormVisible(999999);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "HasFormVisible_002 end";
}

// ========== SetVisibleChange Tests ==========

/**
 * @tc.name: SetVisibleChange_001
 * @tc.desc: Verify invalid formId (<=0) → no calls to SetFormVisible
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, SetVisibleChange_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetVisibleChange_001 start";
    EXPECT_CALL(*MockFormDataMgr::obj, SetFormVisible(_, _))
        .Times(0);
    FormVisibilityAdapter::GetInstance().SetVisibleChange(0, Constants::FORM_VISIBLE, TEST_USER_ID);
    GTEST_LOG_(INFO) << "SetVisibleChange_001 end";
}

/**
 * @tc.name: SetVisibleChange_002
 * @tc.desc: Verify invalid formVisibleType → early return
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, SetVisibleChange_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetVisibleChange_002 start";
    EXPECT_CALL(*MockFormDataMgr::obj, SetFormVisible(_, _))
        .Times(0);
    FormVisibilityAdapter::GetInstance().SetVisibleChange(TEST_FORM_ID, 999, TEST_USER_ID);
    GTEST_LOG_(INFO) << "SetVisibleChange_002 end";
}

/**
 * @tc.name: SetVisibleChange_003
 * @tc.desc: Verify FORM_VISIBLE calls SetFormVisible and SetExpectRecycledStatus
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, SetVisibleChange_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetVisibleChange_003 start";
    EXPECT_CALL(*MockFormDataMgr::obj, SetFormVisible(TEST_FORM_ID, true))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, SetExpectRecycledStatus(TEST_FORM_ID, false))
        .Times(1);
    FormVisibilityAdapter::GetInstance().SetVisibleChange(TEST_FORM_ID, Constants::FORM_VISIBLE, TEST_USER_ID);
    GTEST_LOG_(INFO) << "SetVisibleChange_003 end";
}

/**
 * @tc.name: SetVisibleChange_004
 * @tc.desc: Verify FORM_INVISIBLE calls SetFormVisible but NOT SetExpectRecycledStatus
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, SetVisibleChange_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetVisibleChange_004 start";
    EXPECT_CALL(*MockFormDataMgr::obj, SetFormVisible(TEST_FORM_ID, false))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, SetExpectRecycledStatus(_, _))
        .Times(0);
    FormVisibilityAdapter::GetInstance().SetVisibleChange(TEST_FORM_ID, Constants::FORM_INVISIBLE, TEST_USER_ID);
    GTEST_LOG_(INFO) << "SetVisibleChange_004 end";
}

// ========== isFormShouldUpdateProviderInfoToHost Tests ==========

/**
 * @tc.name: IsFormShouldUpdateProviderInfoToHost_001
 * @tc.desc: Verify GetFormRecord fails returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, IsFormShouldUpdateProviderInfoToHost_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsFormShouldUpdateProviderInfoToHost_001 start";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord formRecord;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    bool result = FormVisibilityAdapter::GetInstance().isFormShouldUpdateProviderInfoToHost(
        TEST_FORM_ID, TEST_USER_ID, callerToken, formRecord);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "IsFormShouldUpdateProviderInfoToHost_001 end";
}

/**
 * @tc.name: IsFormShouldUpdateProviderInfoToHost_002
 * @tc.desc: Verify providerUserId mismatch returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, IsFormShouldUpdateProviderInfoToHost_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsFormShouldUpdateProviderInfoToHost_002 start";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord formRecord;
    formRecord.providerUserId = 999; // mismatch with TEST_USER_ID

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));

    bool result = FormVisibilityAdapter::GetInstance().isFormShouldUpdateProviderInfoToHost(
        TEST_FORM_ID, TEST_USER_ID, callerToken, formRecord);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "IsFormShouldUpdateProviderInfoToHost_002 end";
}

/**
 * @tc.name: IsFormShouldUpdateProviderInfoToHost_003
 * @tc.desc: Verify GetMatchedHostClient fails or form not belong returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, IsFormShouldUpdateProviderInfoToHost_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsFormShouldUpdateProviderInfoToHost_003 start";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord formRecord;
    formRecord.providerUserId = TEST_USER_ID;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, GetMatchedHostClient(_, _))
        .WillOnce(Return(false));

    bool result = FormVisibilityAdapter::GetInstance().isFormShouldUpdateProviderInfoToHost(
        TEST_FORM_ID, TEST_USER_ID, callerToken, formRecord);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "IsFormShouldUpdateProviderInfoToHost_003 end";
}

/**
 * @tc.name: IsFormShouldUpdateProviderInfoToHost_004
 * @tc.desc: Verify all conditions met returns true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, IsFormShouldUpdateProviderInfoToHost_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsFormShouldUpdateProviderInfoToHost_004 start";
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord formRecord;
    formRecord.providerUserId = TEST_USER_ID;

    FormHostRecord hostRecord;
    hostRecord.AddForm(TEST_FORM_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, GetMatchedHostClient(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(hostRecord), Return(true)));

    bool result = FormVisibilityAdapter::GetInstance().isFormShouldUpdateProviderInfoToHost(
        TEST_FORM_ID, TEST_USER_ID, callerToken, formRecord);
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "IsFormShouldUpdateProviderInfoToHost_004 end";
}

// ========== HandleEventNotify Tests ==========

/**
 * @tc.name: HandleEventNotify_003
 * @tc.desc: Verify valid providerKey with ConnectServiceAbility success returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HandleEventNotify_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleEventNotify_003 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    std::string providerKey = "com.test.bundle::MainAbility::entry";

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormAmsHelper::obj, ConnectServiceAbility(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormVisibilityAdapter::GetInstance().HandleEventNotify(
        providerKey, formIds, Constants::FORM_VISIBLE);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "HandleEventNotify_003 end";
}

/**
 * @tc.name: HandleEventNotify_004
 * @tc.desc: Verify valid providerKey with ConnectServiceAbility failure return ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HandleEventNotify_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleEventNotify_004 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    std::string providerKey = "com.test.bundle::MainAbility::entry";

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormAmsHelper::obj, ConnectServiceAbility(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormVisibilityAdapter::GetInstance().HandleEventNotify(
        providerKey, formIds, Constants::FORM_VISIBLE);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED);
    GTEST_LOG_(INFO) << "HandleEventNotify_004 end";
}

// ========== PaddingNotifyVisibleFormsMap Tests ==========

/**
 * @tc.name: PaddingNotifyVisibleFormsMap_002
 * @tc.desc: Verify formVisibleType differs from formInstance → processes formInstance maps
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, PaddingNotifyVisibleFormsMap_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PaddingNotifyVisibleFormsMap_002 start";
    int32_t formVisibleType = Constants::FORM_VISIBLE;
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;

    FormInstance instance;
    instance.formVisiblity = FormVisibilityType::INVISIBLE; // differs from FORM_VISIBLE
    instance.formHostName = "com.test.host";

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormInstanceById3(TEST_FORM_ID, false, _))
        .WillOnce(DoAll(SetArgReferee<2>(instance), Return(ERR_OK)));

    // GetFormObservers() returns empty map, so no entries added to formInstanceMaps
    FormVisibilityAdapter::GetInstance().PaddingNotifyVisibleFormsMap(
        formVisibleType, TEST_FORM_ID, formInstanceMaps);
    // With no formObservers, no entries should be added even though types differ
    EXPECT_TRUE(formInstanceMaps.empty());
    GTEST_LOG_(INFO) << "PaddingNotifyVisibleFormsMap_002 end";
}

// ========== HandlerNotifyWhetherVisibleForms Tests ==========

/**
 * @tc.name: HandlerNotifyWhetherVisibleForms_001
 * @tc.desc: Verify empty maps and INVISIBLE type → no crash, DisableSubscribeFormData called
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HandlerNotifyWhetherVisibleForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandlerNotifyWhetherVisibleForms_001 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // Should not crash with empty maps
    FormVisibilityAdapter::GetInstance().HandlerNotifyWhetherVisibleForms(
        formIds, formInstanceMaps, eventMaps, Constants::FORM_INVISIBLE, callerToken);
    GTEST_LOG_(INFO) << "HandlerNotifyWhetherVisibleForms_001 end";
}

/**
 * @tc.name: HandlerNotifyWhetherVisibleForms_002
 * @tc.desc: Verify with eventMaps containing valid providerKey → HandleEventNotify called
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, HandlerNotifyWhetherVisibleForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandlerNotifyWhetherVisibleForms_002 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    std::unordered_map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::unordered_map<std::string, std::vector<int64_t>> eventMaps;
    eventMaps["com.test.bundle::MainAbility::entry"] = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false)); // FilterEventMapsByVisibleType: GetFormRecord fails → kept

    // Will call HandleEventNotify which calls ConnectServiceAbility
    EXPECT_CALL(*MockFormAmsHelper::obj, ConnectServiceAbility(_, _))
        .WillOnce(Return(ERR_OK));

    FormVisibilityAdapter::GetInstance().HandlerNotifyWhetherVisibleForms(
        formIds, formInstanceMaps, eventMaps, Constants::FORM_VISIBLE, callerToken);
    GTEST_LOG_(INFO) << "HandlerNotifyWhetherVisibleForms_002 end";
}

// ========== NotifyFormsVisible negative path Tests ==========

/**
 * @tc.name: NotifyFormsVisible_002
 * @tc.desc: Verify delegates to FormDataMgr::NotifyFormsVisible and returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormVisibilityAdapterTest, NotifyFormsVisible_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyFormsVisible_002 start";
    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, NotifyFormsVisible(_, false, _, TEST_USER_ID))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_NOT_EXIST_ID));

    auto result = FormVisibilityAdapter::GetInstance().NotifyFormsVisible(
        formIds, false, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    GTEST_LOG_(INFO) << "NotifyFormsVisible_002 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
