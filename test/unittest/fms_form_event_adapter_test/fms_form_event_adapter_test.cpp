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
#include "form_mgr/form_event_adapter.h"
#include "form_mgr/form_common_adapter.h"
#undef private
#undef protected

#include "form_constants.h"
#include "form_mgr_errors.h"
#include "want.h"
#include "accesstoken_kit.h"
#include "application_info.h"
#include "data_center/form_record/form_record.h"
#include "insight_intent/insight_intent_execute_param.h"

#include "mock_form_data_mgr.h"
#include "mock_form_info_mgr.h"
#include "mock_form_bms_helper.h"
#include "mock_form_ams_helper.h"
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

using namespace testing;
using namespace testing::ext;

namespace OHOS {
// Defined in the directory-private mock_accesstoken_kit.cpp.
void MockGetHapTokenID(uint32_t mockRet);
void MockGetHapTokenInfoAttr(uint32_t mockAttr);
void MockGetHapTokenInfoRet(int mockRet);
}

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 20000000;
constexpr int64_t TEST_FORM_ID = 123456789L;
constexpr uint32_t TEST_PROVIDER_HAP_TOKEN_ID = 1000;
// Non-zero tokenAttr so the full token id differs from the bare hap token id.
constexpr uint32_t TEST_PROVIDER_TOKEN_ATTR = 0x1;
}

class FmsFormEventAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormEventAdapterTest::SetUpTestCase()
{
    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    MockFormInfoMgr::obj = std::make_shared<MockFormInfoMgr>();
    MockFormBmsHelper::obj = std::make_shared<MockFormBmsHelper>();
    MockFormAmsHelper::obj = std::make_shared<MockFormAmsHelper>();
    MockFormTimerMgr::obj = std::make_shared<MockFormTimerMgr>();
    MockFormDbCache::obj = std::make_shared<MockFormDbCache>();
    MockFormBundleForbidMgr::obj = std::make_shared<MockFormBundleForbidMgr>();
    MockFormBundleLockMgr::obj = std::make_shared<MockFormBundleLockMgr>();
    MockFormExemptLockMgr::obj = std::make_shared<MockFormExemptLockMgr>();
    MockFormDistributedMgr::obj = std::make_shared<MockFormDistributedMgr>();
    MockParamControl::obj = std::make_shared<MockParamControl>();
    MockIPCSkeleton::obj = new MockIPCSkeleton();
}

void FmsFormEventAdapterTest::TearDownTestCase()
{
    MockFormDataMgr::obj = nullptr;
    MockFormInfoMgr::obj = nullptr;
    MockFormBmsHelper::obj = nullptr;
    MockFormAmsHelper::obj = nullptr;
    MockFormTimerMgr::obj = nullptr;
    MockFormDbCache::obj = nullptr;
    MockFormBundleForbidMgr::obj = nullptr;
    MockFormBundleLockMgr::obj = nullptr;
    MockFormExemptLockMgr::obj = nullptr;
    MockFormDistributedMgr::obj = nullptr;
    MockParamControl::obj = nullptr;
    delete MockIPCSkeleton::obj;
    MockIPCSkeleton::obj = nullptr;
}

void FmsFormEventAdapterTest::SetUp()
{
}

void FmsFormEventAdapterTest::TearDown()
{
}

// ========== Method 1: MessageEvent Tests ==========

/**
 * @tc.name: MessageEvent_001
 * @tc.desc: Verify invalid formId (<=0) returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, MessageEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MessageEvent_001 start";

    Want want;
    want.SetParam(Constants::PARAM_MESSAGE_KEY, std::string("test_message"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormEventAdapter::GetInstance().MessageEvent(0, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "MessageEvent_001 end";
}

/**
 * @tc.name: MessageEvent_002
 * @tc.desc: Verify null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, MessageEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MessageEvent_002 start";

    Want want;
    want.SetParam(Constants::PARAM_MESSAGE_KEY, std::string("test_message"));

    auto result = FormEventAdapter::GetInstance().MessageEvent(TEST_FORM_ID, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "MessageEvent_002 end";
}

/**
 * @tc.name: MessageEvent_003
 * @tc.desc: Verify missing message parameter returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, MessageEvent_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MessageEvent_003 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormEventAdapter::GetInstance().MessageEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "MessageEvent_003 end";
}

/**
 * @tc.name: MessageEvent_004
 * @tc.desc: Verify non-existent form returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, MessageEvent_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "MessageEvent_004 start";

    Want want;
    want.SetParam(Constants::PARAM_MESSAGE_KEY, std::string("test_message"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    auto result = FormEventAdapter::GetInstance().MessageEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "MessageEvent_004 end";
}

// ========== Method 2: RouterEvent Tests ==========

/**
 * @tc.name: RouterEvent_001
 * @tc.desc: Verify invalid formId (<=0) returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_001 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormEventAdapter::GetInstance().RouterEvent(0, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RouterEvent_001 end";
}

/**
 * @tc.name: RouterEvent_002
 * @tc.desc: Verify negative formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_002 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormEventAdapter::GetInstance().RouterEvent(-1, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RouterEvent_002 end";
}

/**
 * @tc.name: RouterEvent_003
 * @tc.desc: Verify non-existent form returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_003 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "RouterEvent_003 end";
}

/**
 * @tc.name: RouterEvent_004
 * @tc.desc: Verify GetApplicationInfo failure returns ERR_APPEXECFWK_FORM_GET_BMS_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_004 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "RouterEvent_004 end";
}

// ========== Method 3: BackgroundEvent Tests ==========

/**
 * @tc.name: BackgroundEvent_001
 * @tc.desc: Verify invalid formId (<=0) returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, BackgroundEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BackgroundEvent_001 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormEventAdapter::GetInstance().BackgroundEvent(0, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "BackgroundEvent_001 end";
}

/**
 * @tc.name: BackgroundEvent_002
 * @tc.desc: Verify non-existent form returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, BackgroundEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BackgroundEvent_002 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    auto result = FormEventAdapter::GetInstance().BackgroundEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "BackgroundEvent_002 end";
}

/**
 * @tc.name: BackgroundEvent_003
 * @tc.desc: Verify CheckKeepBackgroundRunningPermission failure returns ERR_APPEXECFWK_FORM_PERMISSION_DENY
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, BackgroundEvent_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BackgroundEvent_003 start";

    Want want;
    want.SetBundle("com.test.bundle");
    want.SetElementName("com.test.bundle", "MainAbility");
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoWithPermission(_, _, _))
        .WillOnce(Return(false));

    auto result = FormEventAdapter::GetInstance().BackgroundEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    GTEST_LOG_(INFO) << "BackgroundEvent_003 end";
}

// ========== Method 4: SetFreeInstallFlag Tests ==========

/**
 * @tc.name: SetFreeInstallFlag_001
 * @tc.desc: Verify no FLAG_INSTALL_ON_DEMAND does not modify want
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, SetFreeInstallFlag_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFreeInstallFlag_001 start";

    FormRecord record;
    record.isSystemApp = true;
    record.uid = TEST_CALLING_UID;
    Want want;

    FormEventAdapter::GetInstance().SetFreeInstallFlag(record, want);
    EXPECT_FALSE(want.HasParameter("ohos.freeinstall.params.callingUid"));

    GTEST_LOG_(INFO) << "SetFreeInstallFlag_001 end";
}

/**
 * @tc.name: SetFreeInstallFlag_002
 * @tc.desc: Verify system app with FLAG_INSTALL_ON_DEMAND keeps flag and sets uid param
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, SetFreeInstallFlag_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFreeInstallFlag_002 start";

    FormRecord record;
    record.isSystemApp = true;
    record.uid = TEST_CALLING_UID;
    Want want;
    want.SetFlags(Want::FLAG_INSTALL_ON_DEMAND);

    FormEventAdapter::GetInstance().SetFreeInstallFlag(record, want);
    EXPECT_TRUE(want.HasParameter("ohos.freeinstall.params.callingUid"));
    EXPECT_NE(want.GetFlags() & Want::FLAG_INSTALL_ON_DEMAND, 0);

    GTEST_LOG_(INFO) << "SetFreeInstallFlag_002 end";
}

// ========== Method 5: OpenByOpenType Tests ==========

/**
 * @tc.name: OpenByOpenType_001
 * @tc.desc: Verify non-system app returns true with ERR_APPEXECFWK_FORM_PERMISSION_DENY
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, OpenByOpenType_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OpenByOpenType_001 start";

    FormRecord record;
    record.isSystemApp = false;
    Want want;
    int32_t openResult = ERR_OK;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    bool result = FormEventAdapter::GetInstance().OpenByOpenType(
        static_cast<int32_t>(Constants::CardActionParamOpenType::OPEN_APP_LINKING),
        record, callerToken, want, openResult);
    EXPECT_TRUE(result);
    EXPECT_EQ(openResult, ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    GTEST_LOG_(INFO) << "OpenByOpenType_001 end";
}

/**
 * @tc.name: OpenByOpenType_002
 * @tc.desc: Verify OPEN_APP_LINKING with GetCallerBundleName failure returns true with error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, OpenByOpenType_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OpenByOpenType_002 start";

    FormRecord record;
    record.isSystemApp = true;
    record.formId = TEST_FORM_ID;
    Want want;
    int32_t openResult = ERR_OK;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    bool result = FormEventAdapter::GetInstance().OpenByOpenType(
        static_cast<int32_t>(Constants::CardActionParamOpenType::OPEN_APP_LINKING),
        record, callerToken, want, openResult);
    EXPECT_TRUE(result);
    EXPECT_EQ(openResult, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    GTEST_LOG_(INFO) << "OpenByOpenType_002 end";
}

/**
 * @tc.name: OpenByOpenType_003
 * @tc.desc: Verify START_ABILITY type returns false (fall-through)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, OpenByOpenType_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OpenByOpenType_003 start";

    FormRecord record;
    record.isSystemApp = true;
    record.formId = TEST_FORM_ID;
    Want want;
    int32_t openResult = ERR_OK;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    bool result = FormEventAdapter::GetInstance().OpenByOpenType(
        static_cast<int32_t>(Constants::CardActionParamOpenType::START_ABILITY),
        record, callerToken, want, openResult);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "OpenByOpenType_003 end";
}

// ========== Method 6: CheckKeepBackgroundRunningPermission Tests ==========

/**
 * @tc.name: CheckKeepBackgroundRunningPermission_001
 * @tc.desc: Verify GetBundleInfoWithPermission returns false → returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, CheckKeepBackgroundRunningPermission_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckKeepBackgroundRunningPermission_001 start";

    std::string bundleName = "com.test.bundle";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoWithPermission(_, _, _))
        .WillOnce(Return(false));

    auto result = FormEventAdapter::GetInstance().CheckKeepBackgroundRunningPermission(
        bundleName);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "CheckKeepBackgroundRunningPermission_001 end";
}

/**
 * @tc.name: CheckKeepBackgroundRunningPermission_002
 * @tc.desc: Verify GetBundleInfoWithPermission returns true but reqPermissions does NOT
 *           contain PERMISSION_KEEP_BACKGROUND_RUNNING → returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, CheckKeepBackgroundRunningPermission_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckKeepBackgroundRunningPermission_002 start";

    std::string bundleName = "com.test.bundle";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoWithPermission(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(BundleInfo()), Return(true)));

    auto result = FormEventAdapter::GetInstance().CheckKeepBackgroundRunningPermission(
        bundleName);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "CheckKeepBackgroundRunningPermission_002 end";
}

/**
 * @tc.name: CheckKeepBackgroundRunningPermission_003
 * @tc.desc: Verify GetBundleInfoWithPermission returns true and reqPermissions contains
 *           PERMISSION_KEEP_BACKGROUND_RUNNING → returns true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, CheckKeepBackgroundRunningPermission_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckKeepBackgroundRunningPermission_003 start";

    std::string bundleName = "com.test.bundle";

    BundleInfo bundleInfo;
    bundleInfo.reqPermissions.push_back(Constants::PERMISSION_KEEP_BACKGROUND_RUNNING);
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoWithPermission(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(bundleInfo), Return(true)));

    auto result = FormEventAdapter::GetInstance().CheckKeepBackgroundRunningPermission(
        bundleName);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "CheckKeepBackgroundRunningPermission_003 end";
}

// ========== Method 7: BackgroundEvent Additional Branch Tests ==========

/**
 * @tc.name: BackgroundEvent_005
 * @tc.desc: Verify invalid JSON params (is_discarded) → ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, BackgroundEvent_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BackgroundEvent_005 start";

    Want want;
    want.SetBundle("com.test.bundle");
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::FORM_CALL_EVENT_PARAMS, std::string("invalid json"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";

    BundleInfo bundleInfo;
    bundleInfo.reqPermissions.push_back(Constants::PERMISSION_KEEP_BACKGROUND_RUNNING);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoWithPermission(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(bundleInfo), Return(true)));

    auto result = FormEventAdapter::GetInstance().BackgroundEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "BackgroundEvent_005 end";
}

/**
 * @tc.name: BackgroundEvent_006
 * @tc.desc: Verify JSON missing method key → ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, BackgroundEvent_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BackgroundEvent_006 start";

    Want want;
    want.SetBundle("com.test.bundle");
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::FORM_CALL_EVENT_PARAMS, std::string("{\"otherKey\":\"otherValue\"}"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";

    BundleInfo bundleInfo;
    bundleInfo.reqPermissions.push_back(Constants::PERMISSION_KEEP_BACKGROUND_RUNNING);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoWithPermission(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(bundleInfo), Return(true)));

    auto result = FormEventAdapter::GetInstance().BackgroundEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "BackgroundEvent_006 end";
}

/**
 * @tc.name: BackgroundEvent_007
 * @tc.desc: Verify JSON method key is not string type → ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, BackgroundEvent_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BackgroundEvent_007 start";

    Want want;
    want.SetBundle("com.test.bundle");
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::FORM_CALL_EVENT_PARAMS, std::string("{\"method\":12345}"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";

    BundleInfo bundleInfo;
    bundleInfo.reqPermissions.push_back(Constants::PERMISSION_KEEP_BACKGROUND_RUNNING);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoWithPermission(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(bundleInfo), Return(true)));

    auto result = FormEventAdapter::GetInstance().BackgroundEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "BackgroundEvent_007 end";
}

/**
 * @tc.name: BackgroundEvent_008
 * @tc.desc: Verify empty bundle in want gets corrected to record.bundleName
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, BackgroundEvent_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BackgroundEvent_008 start";

    Want want;
    // No bundle set → empty bundle
    want.SetParam(Constants::FORM_CALL_EVENT_PARAMS, std::string("invalid json"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoWithPermission(_, _, _))
        .WillOnce(Return(false));

    auto result = FormEventAdapter::GetInstance().BackgroundEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    // Verify want bundle was corrected
    EXPECT_EQ(want.GetBundle(), "com.test.bundle");

    GTEST_LOG_(INFO) << "BackgroundEvent_008 end";
}

// ========== Method 8: RouterEvent Additional Branch Tests ==========

/**
 * @tc.name: RouterEvent_005
 * @tc.desc: Verify formId < MAX_NUMBER_OF_JS sets formId as int64 parameter
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_005 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    // formId 123456789 (< MAX_NUMBER_OF_JS) should be set as int64
    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    // Verify formId was set as int64 (not string) - parameter should exist
    EXPECT_TRUE(want.HasParameter(Constants::PARAM_FORM_IDENTITY_KEY));

    GTEST_LOG_(INFO) << "RouterEvent_005 end";
}

/**
 * @tc.name: RouterEvent_006
 * @tc.desc: Verify formId >= MAX_NUMBER_OF_JS sets formId as string parameter
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_006 start";

    constexpr int64_t LARGE_FORM_ID = 200000000000000L;
    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(LARGE_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    auto result = FormEventAdapter::GetInstance().RouterEvent(LARGE_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    // Verify formId was set as string for large formId
    EXPECT_TRUE(want.HasParameter(Constants::PARAM_FORM_IDENTITY_KEY));

    GTEST_LOG_(INFO) << "RouterEvent_006 end";
}

/**
 * @tc.name: RouterEvent_007
 * @tc.desc: Verify bundle mismatch with non-system app sets bundle to record.bundleName
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_007 start";

    Want want;
    want.SetBundle("com.other.bundle");
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = false;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    // GetApplicationInfo fails → ERR_APPEXECFWK_FORM_GET_BMS_FAILED
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);
    // Verify bundle was corrected for non-system app
    EXPECT_EQ(want.GetBundle(), "com.test.bundle");

    GTEST_LOG_(INFO) << "RouterEvent_007 end";
}

/**
 * @tc.name: RouterEvent_008
 * @tc.desc: Verify GetApplicationInfo fails → ERR_APPEXECFWK_FORM_GET_BMS_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_008 start";

    Want want;
    want.SetBundle("com.test.bundle");
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = true;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "RouterEvent_008 end";
}

/**
 * @tc.name: RouterEvent_009
 * @tc.desc: Verify PARAM_OPEN_TYPE triggers OpenByOpenType path
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_009 start";

    Want want;
    want.SetBundle("com.test.bundle");
    want.SetParam(Constants::PARAM_OPEN_TYPE,
        static_cast<int32_t>(Constants::CardActionParamOpenType::OPEN_APP_LINKING));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = false;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    // OpenByOpenType with non-system app → PERMISSION_DENY
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    GTEST_LOG_(INFO) << "RouterEvent_009 end";
}

/**
 * @tc.name: RouterEvent_010
 * @tc.desc: Verify system app with bundle mismatch does NOT override bundle when URI is not empty
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_010 start";

    Want want;
    want.SetBundle("com.other.bundle");
    want.SetUri("test://uri");
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = true;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    // When URI is not empty, bundle is NOT overridden even if mismatched
    EXPECT_EQ(want.GetBundle(), "com.other.bundle");
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "RouterEvent_010 end";
}

/**
 * @tc.name: RouterEvent_011
 * @tc.desc: Verify uri is passed through when enableRouteSecondPage is true and
 *           the form provider is a system app (uri and abilityName coexist)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_011 start";

    Want want;
    want.SetUri("test://uri");
    want.SetElementName("com.other.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_ENABLE_ROUTE_SECOND_PAGE, true);
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = true;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(want.GetUriString(), "test://uri");
    EXPECT_EQ(want.GetBundle(), "com.other.bundle");
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "RouterEvent_011 end";
}

/**
 * @tc.name: RouterEvent_012
 * @tc.desc: Verify uri is discarded when enableRouteSecondPage is true but the
 *           form provider is not a system app (abilityName takes priority)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_012 start";

    Want want;
    want.SetUri("test://uri");
    want.SetElementName("com.other.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_ENABLE_ROUTE_SECOND_PAGE, true);
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = false;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_TRUE(want.GetUriString().empty());
    EXPECT_EQ(want.GetBundle(), "com.test.bundle");
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "RouterEvent_012 end";
}

/**
 * @tc.name: RouterEvent_013
 * @tc.desc: Verify uri is discarded when enableRouteSecondPage is false even if
 *           the form provider is a system app (abilityName takes priority)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_013 start";

    Want want;
    want.SetUri("test://uri");
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_ENABLE_ROUTE_SECOND_PAGE, false);
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = true;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_TRUE(want.GetUriString().empty());
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "RouterEvent_013 end";
}

/**
 * @tc.name: RouterEvent_014
 * @tc.desc: Verify uri is discarded when enableRouteSecondPage is not set
 *           (default false) even if the form provider is a system app
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_014 start";

    Want want;
    want.SetUri("test://uri");
    want.SetElementName("com.test.bundle", "MainAbility");
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = true;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_TRUE(want.GetUriString().empty());
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "RouterEvent_014 end";
}

/**
 * @tc.name: RouterEvent_015
 * @tc.desc: Verify the success path when GetApplicationInfo and StartAbilityOnlyUIAbility
 *           both succeed: StartAbilityForRouter invokes StartAbilityOnlyUIAbility once and
 *           NotifyFormClickEvent is triggered (GetRunningFormInfosByFormId called) and uri
 *           is kept for a system app when enableRouteSecondPage is true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, RouterEvent_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RouterEvent_015 start";

    Want want;
    want.SetUri("test://uri");
    want.SetBundle("com.test.bundle");
    want.SetParam(Constants::PARAM_ENABLE_ROUTE_SECOND_PAGE, true);
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    sptr<IBundleMgr> mockBundleMgr = new MockBundleMgrStub();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = true;

    ApplicationInfo appInfo;
    appInfo.accessTokenId = TEST_PROVIDER_HAP_TOKEN_ID;

    RunningFormInfo runningFormInfo;
    runningFormInfo.hostBundleName = "com.test.host";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(mockBundleMgr));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetApplicationInfo(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(appInfo), Return(ERR_OK)));
    // Verify StartAbilityForRouter is invoked.
    EXPECT_CALL(*MockFormAmsHelper::obj, StartAbilityOnlyUIAbility(_, _, _, _))
        .WillOnce(Return(ERR_OK));
    // Verify NotifyFormClickEvent is triggered after StartAbility succeeds.
    EXPECT_CALL(*MockFormDataMgr::obj, GetRunningFormInfosByFormId(_, _, _))
        .WillOnce(DoAll(SetArgReferee<1>(runningFormInfo), Return(ERR_OK)));

    auto result = FormEventAdapter::GetInstance().RouterEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(want.GetUriString(), "test://uri");

    GTEST_LOG_(INFO) << "RouterEvent_015 end";
}

// ========== Method 9: OpenByOpenType Additional Branch Tests ==========

/**
 * @tc.name: OpenByOpenType_004
 * @tc.desc: Verify invalid openType returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, OpenByOpenType_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OpenByOpenType_004 start";

    FormRecord record;
    record.isSystemApp = true;
    record.formId = TEST_FORM_ID;
    Want want;
    int32_t openResult = ERR_OK;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    bool result = FormEventAdapter::GetInstance().OpenByOpenType(
        999, // invalid openType
        record, callerToken, want, openResult);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "OpenByOpenType_004 end";
}

// ========== Method 10: InsightIntentEvent Tests ==========

/**
 * @tc.name: InsightIntentEvent_001
 * @tc.desc: Verify invalid formId (<=0) returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_001 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(0, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "InsightIntentEvent_001 end";
}

/**
 * @tc.name: InsightIntentEvent_002
 * @tc.desc: Verify form record not found returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_002 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "InsightIntentEvent_002 end";
}

/**
 * @tc.name: InsightIntentEvent_003
 * @tc.desc: Verify non-system-app provider returns ERR_APPEXECFWK_FORM_PERMISSION_DENY
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_003 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.isSystemApp = false;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_PERMISSION_DENY);

    GTEST_LOG_(INFO) << "InsightIntentEvent_003 end";
}

/**
 * @tc.name: InsightIntentEvent_004
 * @tc.desc: Verify failed to get provider hapTokenId returns ERR_APPEXECFWK_FORM_GET_INFO_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_004 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.isSystemApp = true;

    MockGetHapTokenID(0);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "InsightIntentEvent_004 end";
}

/**
 * @tc.name: InsightIntentEvent_005
 * @tc.desc: Verify want without intent name param returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_005 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.isSystemApp = true;

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "InsightIntentEvent_005 end";
}

/**
 * @tc.name: InsightIntentEvent_006
 * @tc.desc: Verify empty intent name returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_006 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string(""));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.isSystemApp = true;

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "InsightIntentEvent_006 end";
}

/**
 * @tc.name: InsightIntentEvent_007
 * @tc.desc: Verify GetBundleInfoByFlags failure when backfilling abilityName
 *           returns ERR_APPEXECFWK_FORM_GET_BMS_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_007 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.moduleName = "entry";
    record.isSystemApp = true;

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _))
        .WillOnce(Return(false));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "InsightIntentEvent_007 end";
}

/**
 * @tc.name: InsightIntentEvent_008
 * @tc.desc: Verify moduleName not matched in hapModuleInfos returns ERR_APPEXECFWK_FORM_GET_BMS_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_008 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.moduleName = "entry";
    record.isSystemApp = true;

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = "otherModule";
    hapModuleInfo.mainElementName = "OtherAbility";
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<3>(bundleInfo), Return(true)));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BMS_FAILED);

    GTEST_LOG_(INFO) << "InsightIntentEvent_008 end";
}

/**
 * @tc.name: InsightIntentEvent_009
 * @tc.desc: Verify non-ERR_OK result from AMS is passed through
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_009 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    want.SetElementName("", "com.test.bundle", "MainAbility");
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.moduleName = "entry";
    record.isSystemApp = true;

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormAmsHelper::obj, ExecuteUIAbilityForegroundIntentWithSpecifyTokenId(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "InsightIntentEvent_009 end";
}

/**
 * @tc.name: InsightIntentEvent_010
 * @tc.desc: Verify success path backfills provider triple into want, passes the provider
 *           specified full token id (spliced from hapTokenId and tokenAttr) and returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_010 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.moduleName = "entry";
    record.isSystemApp = true;

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = "entry";
    hapModuleInfo.mainElementName = "EntryAbility";
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<3>(bundleInfo), Return(true)));
    EXPECT_CALL(*MockFormAmsHelper::obj,
        ExecuteUIAbilityForegroundIntentWithSpecifyTokenId(_, _, _, TEST_PROVIDER_HAP_TOKEN_ID))
        .WillOnce(Return(ERR_OK));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(want.GetElement().GetBundleName(), "com.test.bundle");
    EXPECT_EQ(want.GetElement().GetModuleName(), "entry");
    EXPECT_EQ(want.GetElement().GetAbilityName(), "EntryAbility");
    EXPECT_TRUE(want.HasParameter(Constants::PARAM_FORM_IDENTITY_KEY));

    GTEST_LOG_(INFO) << "InsightIntentEvent_010 end";
}

/**
 * @tc.name: InsightIntentEvent_011
 * @tc.desc: Verify the specified full token id passed to AMS is spliced with tokenAttr
 *           in the high 32 bits and the hap token id in the low 32 bits
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_011 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.moduleName = "entry";
    record.isSystemApp = true;

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = "entry";
    hapModuleInfo.mainElementName = "EntryAbility";
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);
    MockGetHapTokenInfoAttr(TEST_PROVIDER_TOKEN_ATTR);
    const uint64_t expectedFullTokenId =
        (static_cast<uint64_t>(TEST_PROVIDER_TOKEN_ATTR) << 32) + TEST_PROVIDER_HAP_TOKEN_ID;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<3>(bundleInfo), Return(true)));
    EXPECT_CALL(*MockFormAmsHelper::obj,
        ExecuteUIAbilityForegroundIntentWithSpecifyTokenId(_, _, _, expectedFullTokenId))
        .WillOnce(Return(ERR_OK));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_OK);

    MockGetHapTokenInfoAttr(0);
    GTEST_LOG_(INFO) << "InsightIntentEvent_011 end";
}

/**
 * @tc.name: InsightIntentEvent_012
 * @tc.desc: Verify empty provider bundleName returns ERR_APPEXECFWK_FORM_GET_INFO_FAILED
 *           before the GetHapTokenID lookup
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_012 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "";
    record.providerUserId = TEST_USER_ID;
    record.isSystemApp = true;

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_INFO_FAILED);

    GTEST_LOG_(INFO) << "InsightIntentEvent_012 end";
}

/**
 * @tc.name: InsightIntentEvent_013
 * @tc.desc: Verify failed GetHapTokenInfo falls back to the zero-extended hap token id
 *           passed to AMS
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_013 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    want.SetElementName("", "com.test.bundle", "MainAbility");
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.moduleName = "entry";
    record.isSystemApp = true;

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);
    MockGetHapTokenInfoRet(Security::AccessToken::AccessTokenKitRet::RET_FAILED);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormAmsHelper::obj,
        ExecuteUIAbilityForegroundIntentWithSpecifyTokenId(_, _, _, TEST_PROVIDER_HAP_TOKEN_ID))
        .WillOnce(Return(ERR_OK));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_OK);

    MockGetHapTokenInfoRet(Security::AccessToken::AccessTokenKitRet::RET_SUCCESS);
    GTEST_LOG_(INFO) << "InsightIntentEvent_013 end";
}

/**
 * @tc.name: InsightIntentEvent_014
 * @tc.desc: Verify a partially filled want element keeps the host-provided
 *           bundleName/moduleName and only backfills the missing abilityName
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_014 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    ElementName element;
    element.SetBundleName("com.host.bundle");
    element.SetModuleName("hostModule");
    want.SetElement(element);
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.moduleName = "entry";
    record.isSystemApp = true;

    BundleInfo bundleInfo;
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = "entry";
    hapModuleInfo.mainElementName = "EntryAbility";
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleInfoByFlags(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<3>(bundleInfo), Return(true)));
    EXPECT_CALL(*MockFormAmsHelper::obj,
        ExecuteUIAbilityForegroundIntentWithSpecifyTokenId(_, _, _, TEST_PROVIDER_HAP_TOKEN_ID))
        .WillOnce(Return(ERR_OK));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(want.GetElement().GetBundleName(), "com.host.bundle");
    EXPECT_EQ(want.GetElement().GetModuleName(), "hostModule");
    EXPECT_EQ(want.GetElement().GetAbilityName(), "EntryAbility");

    GTEST_LOG_(INFO) << "InsightIntentEvent_014 end";
}

/**
 * @tc.name: InsightIntentEvent_015
 * @tc.desc: Verify a matched formId at the JS number limit is serialized as a string
 *           form identity param to avoid JS precision overflow
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventAdapterTest, InsightIntentEvent_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentEvent_015 start";

    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("TestIntent"));
    want.SetElementName("", "com.test.bundle", "MainAbility");
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.providerUserId = TEST_USER_ID;
    record.moduleName = "entry";
    record.isSystemApp = true;

    constexpr int64_t beyondJsNumber = 0x20000000000000;

    MockGetHapTokenID(TEST_PROVIDER_HAP_TOKEN_ID);

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(beyondJsNumber));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormAmsHelper::obj,
        ExecuteUIAbilityForegroundIntentWithSpecifyTokenId(_, _, _, TEST_PROVIDER_HAP_TOKEN_ID))
        .WillOnce(Return(ERR_OK));

    auto result = FormEventAdapter::GetInstance().InsightIntentEvent(TEST_FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(want.GetStringParam(Constants::PARAM_FORM_ID), "9007199254740992");
    EXPECT_EQ(want.GetStringParam(Constants::PARAM_FORM_IDENTITY_KEY), "9007199254740992");

    GTEST_LOG_(INFO) << "InsightIntentEvent_015 end";
}

} // namespace AppExecFwk
} // namespace OHOS
