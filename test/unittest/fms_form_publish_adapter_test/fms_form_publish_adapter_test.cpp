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
#include "form_mgr/form_publish_adapter.h"
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
#include "ability_info.h"

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
#include "mock_form_callback_adapter.h"
#include "mock_form_ams_helper.h"
#include "mock_form_ecological_rule_client.h"
#include "form_adapter_constants.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk::FormAdapterConstants;

namespace OHOS {
namespace AppExecFwk {
namespace {
class MockFormPublishInterceptor : public IRemoteStub<IFormPublishInterceptor> {
public:
    MockFormPublishInterceptor() = default;
    ~MockFormPublishInterceptor() override = default;
    MOCK_METHOD1(ProcessPublishForm, int32_t(const Want &want));
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }
};

constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 20000000;
constexpr int32_t TEST_CALLING_PID = 1234;
constexpr int64_t TEST_FORM_ID = 123456789L;
constexpr int32_t TEST_DIMENSION_ID = 2;
constexpr int32_t SYSTEM_UID = 1000;
const std::string TEST_BUNDLE_NAME = "com.test.bundle";
const std::string TEST_MODULE_NAME = "entry";
const std::string TEST_ABILITY_NAME = "MainAbility";
const std::string TEST_FORM_NAME = "widget";
const std::string TEST_ACTION = "action.system.publish.form";
const std::string TEST_PAGE_ACTION = "action.system.page.form";
const std::string TEST_INVALID_ACTION = "action.invalid.test";
const std::string TEST_SNAPSHOT_VALUE = "snapshot_data";
const std::string TEST_WIDTH_VALUE = "100";
const std::string TEST_HEIGHT_VALUE = "200";
const std::string TEST_SCREEN_X_VALUE = "10";
const std::string TEST_SCREEN_Y_VALUE = "20";
}

class FmsFormPublishAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormPublishAdapterTest::SetUpTestCase()
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
    MockFormCallbackAdapter::obj = std::make_shared<MockFormCallbackAdapter>();
    MockFormAmsHelper::obj = std::make_shared<MockFormAmsHelper>();
    MockFormEcologicalRuleClient::obj = std::make_shared<MockFormEcologicalRuleClient>();
}

void FmsFormPublishAdapterTest::TearDownTestCase()
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
    MockFormCallbackAdapter::obj = nullptr;
    MockFormAmsHelper::obj = nullptr;
    MockFormEcologicalRuleClient::obj = nullptr;
}

void FmsFormPublishAdapterTest::SetUp()
{
    FormPublishAdapter::GetInstance().formIdMap_.clear();
}

void FmsFormPublishAdapterTest::TearDown()
{
    testing::Mock::VerifyAndClear(MockFormDataMgr::obj.get());
    testing::Mock::VerifyAndClear(MockFormInfoMgr::obj.get());
    testing::Mock::VerifyAndClear(MockFormBmsHelper::obj.get());
    testing::Mock::VerifyAndClear(MockFormTimerMgr::obj.get());
    testing::Mock::VerifyAndClear(MockFormDbCache::obj.get());
    testing::Mock::VerifyAndClear(MockFormBundleForbidMgr::obj.get());
    testing::Mock::VerifyAndClear(MockFormBundleLockMgr::obj.get());
    testing::Mock::VerifyAndClear(MockFormExemptLockMgr::obj.get());
    testing::Mock::VerifyAndClear(MockFormDistributedMgr::obj.get());
    testing::Mock::VerifyAndClear(MockParamControl::obj.get());
    testing::Mock::VerifyAndClear(MockIPCSkeleton::obj);
    testing::Mock::VerifyAndClear(MockFormCallbackAdapter::obj.get());
    testing::Mock::VerifyAndClear(MockFormAmsHelper::obj.get());
    testing::Mock::VerifyAndClear(MockFormEcologicalRuleClient::obj.get());
}

// ========== CheckFormBundleName Tests ==========

/**
 * @tc.name: CheckFormBundleName_001
 * @tc.desc: Verify GetBundleName fails returns ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckFormBundleName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckFormBundleName_001 start";

    Want want;
    want.SetBundle(TEST_BUNDLE_NAME);
    std::string bundleName;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));

    auto result = FormPublishAdapter::GetInstance().CheckFormBundleName(want, bundleName, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    GTEST_LOG_(INFO) << "CheckFormBundleName_001 end";
}

// ========== GetBundleName Tests ==========

/**
 * @tc.name: GetBundleName_001
 * @tc.desc: Verify null IBundleMgr returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, GetBundleName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetBundleName_001 start";

    std::string bundleName;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));

    auto result = FormPublishAdapter::GetInstance().GetBundleName(bundleName, true);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "GetBundleName_001 end";
}

// ========== IsActionAllowToPublish Tests ==========

/**
 * @tc.name: IsActionAllowToPublish_001
 * @tc.desc: Verify FORM_PUBLISH_ACTION returns true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IsActionAllowToPublish_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsActionAllowToPublish_001 start";

    auto result = FormPublishAdapter::GetInstance().IsActionAllowToPublish(Constants::FORM_PUBLISH_ACTION);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "IsActionAllowToPublish_001 end";
}

/**
 * @tc.name: IsActionAllowToPublish_002
 * @tc.desc: Verify FORM_PAGE_ACTION returns true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IsActionAllowToPublish_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsActionAllowToPublish_002 start";

    auto result = FormPublishAdapter::GetInstance().IsActionAllowToPublish(Constants::FORM_PAGE_ACTION);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "IsActionAllowToPublish_002 end";
}

/**
 * @tc.name: IsActionAllowToPublish_003
 * @tc.desc: Verify invalid action returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IsActionAllowToPublish_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsActionAllowToPublish_003 start";

    auto result = FormPublishAdapter::GetInstance().IsActionAllowToPublish(TEST_INVALID_ACTION);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "IsActionAllowToPublish_003 end";
}

/**
 * @tc.name: IsActionAllowToPublish_004
 * @tc.desc: Verify empty action returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IsActionAllowToPublish_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsActionAllowToPublish_004 start";

    auto result = FormPublishAdapter::GetInstance().IsActionAllowToPublish("");
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "IsActionAllowToPublish_004 end";
}

// ========== CheckSnapshotWant Tests ==========

/**
 * @tc.name: CheckSnapshotWant_001
 * @tc.desc: Verify all snapshot params present returns true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckSnapshotWant_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckSnapshotWant_001 start";

    Want want;
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_SNAPSHOT_KEY, TEST_SNAPSHOT_VALUE);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_WIDTH_KEY, TEST_WIDTH_VALUE);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_HEIGHT_KEY, TEST_HEIGHT_VALUE);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_SCREENX_KEY, TEST_SCREEN_X_VALUE);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_SCREENY_KEY, TEST_SCREEN_Y_VALUE);

    auto result = FormPublishAdapter::GetInstance().CheckSnapshotWant(want);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "CheckSnapshotWant_001 end";
}

/**
 * @tc.name: CheckSnapshotWant_002
 * @tc.desc: Verify missing snapshot param returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckSnapshotWant_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckSnapshotWant_002 start";

    Want want;
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_SNAPSHOT_KEY, TEST_SNAPSHOT_VALUE);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_WIDTH_KEY, TEST_WIDTH_VALUE);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_HEIGHT_KEY, TEST_HEIGHT_VALUE);
    want.SetParam(Constants::PARAM_PUBLISH_FORM_HOST_SCREENX_KEY, TEST_SCREEN_X_VALUE);
    // Missing PARAM_PUBLISH_FORM_HOST_SCREENY_KEY

    auto result = FormPublishAdapter::GetInstance().CheckSnapshotWant(want);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "CheckSnapshotWant_002 end";
}

/**
 * @tc.name: CheckSnapshotWant_003
 * @tc.desc: Verify empty want returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckSnapshotWant_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckSnapshotWant_003 start";

    Want want;

    auto result = FormPublishAdapter::GetInstance().CheckSnapshotWant(want);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "CheckSnapshotWant_003 end";
}

// ========== CheckPublishForm Tests ==========

/**
 * @tc.name: CheckPublishForm_001
 * @tc.desc: Verify CheckFormBundleName fails returns error code
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckPublishForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckPublishForm_001 start";

    Want want;
    want.SetBundle(TEST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, TEST_MODULE_NAME);

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));

    auto result = FormPublishAdapter::GetInstance().CheckPublishForm(want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    GTEST_LOG_(INFO) << "CheckPublishForm_001 end";
}

// ========== QueryPublishFormToHost Tests ==========

/**
 * @tc.name: QueryPublishFormToHost_001
 * @tc.desc: Verify empty action defaults to FORM_PUBLISH_ACTION and GetAbilityInfoByAction fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, QueryPublishFormToHost_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "QueryPublishFormToHost_001 start";

    Want wantToHost;
    // No action set, should default to FORM_PUBLISH_ACTION

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(Return(false));

    auto result = FormPublishAdapter::GetInstance().QueryPublishFormToHost(wantToHost);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "QueryPublishFormToHost_001 end";
}

/**
 * @tc.name: QueryPublishFormToHost_002
 * @tc.desc: Verify empty ability names returns ERR_APPEXECFWK_FORM_GET_HOST_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, QueryPublishFormToHost_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "QueryPublishFormToHost_002 start";

    Want wantToHost;
    // No action set, should default to FORM_PUBLISH_ACTION

    AbilityInfo emptyAbilityInfo;
    ExtensionAbilityInfo emptyExtAbilityInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(emptyAbilityInfo), SetArgReferee<3>(emptyExtAbilityInfo),
            Return(true)));

    auto result = FormPublishAdapter::GetInstance().QueryPublishFormToHost(wantToHost);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "QueryPublishFormToHost_002 end";
}

/**
 * @tc.name: QueryPublishFormToHost_003
 * @tc.desc: Verify disallowed action returns ERR_APPEXECFWK_FORM_GET_HOST_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, QueryPublishFormToHost_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "QueryPublishFormToHost_003 start";

    Want wantToHost;
    wantToHost.SetAction(TEST_INVALID_ACTION);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormPublishAdapter::GetInstance().QueryPublishFormToHost(wantToHost);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "QueryPublishFormToHost_003 end";
}

/**
 * @tc.name: QueryPublishFormToHost_004
 * @tc.desc: Verify success with ability info returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, QueryPublishFormToHost_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "QueryPublishFormToHost_004 start";

    Want wantToHost;

    AbilityInfo abilityInfo;
    abilityInfo.name = TEST_ABILITY_NAME;
    abilityInfo.bundleName = TEST_BUNDLE_NAME;
    ExtensionAbilityInfo emptyExtAbilityInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(abilityInfo), SetArgReferee<3>(emptyExtAbilityInfo),
            Return(true)));

    auto result = FormPublishAdapter::GetInstance().QueryPublishFormToHost(wantToHost);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "QueryPublishFormToHost_004 end";
}

/**
 * @tc.name: QueryPublishFormToHost_005
 * @tc.desc: Verify success with extension ability info returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, QueryPublishFormToHost_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "QueryPublishFormToHost_005 start";

    Want wantToHost;

    AbilityInfo emptyAbilityInfo;
    ExtensionAbilityInfo extAbilityInfo;
    extAbilityInfo.name = "ExtAbility";
    extAbilityInfo.bundleName = TEST_BUNDLE_NAME;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(emptyAbilityInfo), SetArgReferee<3>(extAbilityInfo),
            Return(true)));

    auto result = FormPublishAdapter::GetInstance().QueryPublishFormToHost(wantToHost);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "QueryPublishFormToHost_005 end";
}

// ========== CheckAddFormTaskTimeoutOrFailed Tests ==========

/**
 * @tc.name: CheckAddFormTaskTimeoutOrFailed_001
 * @tc.desc: Verify formId not in map returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckAddFormTaskTimeoutOrFailed_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_001 start";

    AddFormResultErrorCodes formStates = AddFormResultErrorCodes::UNKNOWN;
    auto result = FormPublishAdapter::GetInstance().CheckAddFormTaskTimeoutOrFailed(TEST_FORM_ID, formStates);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_001 end";
}

/**
 * @tc.name: CheckAddFormTaskTimeoutOrFailed_002
 * @tc.desc: Verify formId in map with FAILED returns ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckAddFormTaskTimeoutOrFailed_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_002 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::FAILED;
    AddFormResultErrorCodes formStates = AddFormResultErrorCodes::UNKNOWN;

    auto result = FormPublishAdapter::GetInstance().CheckAddFormTaskTimeoutOrFailed(TEST_FORM_ID, formStates);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_002 end";
}

/**
 * @tc.name: CheckAddFormTaskTimeoutOrFailed_003
 * @tc.desc: Verify formId in map with TIMEOUT returns ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckAddFormTaskTimeoutOrFailed_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_003 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::TIMEOUT;
    AddFormResultErrorCodes formStates = AddFormResultErrorCodes::UNKNOWN;

    auto result = FormPublishAdapter::GetInstance().CheckAddFormTaskTimeoutOrFailed(TEST_FORM_ID, formStates);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_003 end";
}

/**
 * @tc.name: CheckAddFormTaskTimeoutOrFailed_004
 * @tc.desc: Verify formId in map with UNKNOWN returns ERR_OK and sets formStates
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckAddFormTaskTimeoutOrFailed_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_004 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::UNKNOWN;
    AddFormResultErrorCodes formStates = AddFormResultErrorCodes::FAILED;

    auto result = FormPublishAdapter::GetInstance().CheckAddFormTaskTimeoutOrFailed(TEST_FORM_ID, formStates);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(formStates, AddFormResultErrorCodes::UNKNOWN);

    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_004 end";
}

/**
 * @tc.name: CheckAddFormTaskTimeoutOrFailed_005
 * @tc.desc: Verify formId in map with SUCCESS returns ERR_OK and sets formStates
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckAddFormTaskTimeoutOrFailed_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_005 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::SUCCESS;
    AddFormResultErrorCodes formStates = AddFormResultErrorCodes::UNKNOWN;

    auto result = FormPublishAdapter::GetInstance().CheckAddFormTaskTimeoutOrFailed(TEST_FORM_ID, formStates);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(formStates, AddFormResultErrorCodes::SUCCESS);

    GTEST_LOG_(INFO) << "CheckAddFormTaskTimeoutOrFailed_005 end";
}

// ========== RemoveFormIdMapElement Tests ==========

/**
 * @tc.name: RemoveFormIdMapElement_001
 * @tc.desc: Verify removing existing entry works
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RemoveFormIdMapElement_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveFormIdMapElement_001 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::UNKNOWN;
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_.size(), 1u);

    FormPublishAdapter::GetInstance().RemoveFormIdMapElement(TEST_FORM_ID);
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_.size(), 0u);
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_.find(TEST_FORM_ID),
        FormPublishAdapter::GetInstance().formIdMap_.end());

    GTEST_LOG_(INFO) << "RemoveFormIdMapElement_001 end";
}

/**
 * @tc.name: RemoveFormIdMapElement_002
 * @tc.desc: Verify removing non-existing entry is a no-op
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RemoveFormIdMapElement_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveFormIdMapElement_002 start";

    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_.size(), 0u);

    FormPublishAdapter::GetInstance().RemoveFormIdMapElement(TEST_FORM_ID);
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_.size(), 0u);

    GTEST_LOG_(INFO) << "RemoveFormIdMapElement_002 end";
}

// ========== RequestPublishFormCommon Tests ==========

/**
 * @tc.name: RequestPublishFormCommon_001
 * @tc.desc: Verify GenerateFormId returns negative returns ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormCommon_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormCommon_001 start";

    Want want;
    int64_t formId = 0;

    EXPECT_CALL(*MockFormDataMgr::obj, GenerateFormId())
        .WillOnce(Return(-1));

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormCommon(want, TEST_USER_ID, formId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "RequestPublishFormCommon_001 end";
}

/**
 * @tc.name: RequestPublishFormCommon_002
 * @tc.desc: Verify success sets formIdMap and returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormCommon_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormCommon_002 start";

    Want want;
    int64_t formId = 0;

    EXPECT_CALL(*MockFormDataMgr::obj, GenerateFormId())
        .WillOnce(Return(TEST_FORM_ID));

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormCommon(want, TEST_USER_ID, formId);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(formId, TEST_FORM_ID);
    EXPECT_NE(FormPublishAdapter::GetInstance().formIdMap_.find(TEST_FORM_ID),
        FormPublishAdapter::GetInstance().formIdMap_.end());

    GTEST_LOG_(INFO) << "RequestPublishFormCommon_002 end";
}

// ========== IsRequestPublishFormSupported Tests ==========

/**
 * @tc.name: IsRequestPublishFormSupported_001
 * @tc.desc: Verify GetBundleName fails returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IsRequestPublishFormSupported_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsRequestPublishFormSupported_001 start";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));

    auto result = FormPublishAdapter::GetInstance().IsRequestPublishFormSupported();
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "IsRequestPublishFormSupported_001 end";
}

// ========== SetPublishFormResult Tests ==========

/**
 * @tc.name: SetPublishFormResult_001
 * @tc.desc: Verify formId not in map returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, SetPublishFormResult_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetPublishFormResult_001 start";

    Constants::PublishFormResult errorCodeInfo;
    errorCodeInfo.code = Constants::PublishFormErrorCode::SUCCESS;

    auto result = FormPublishAdapter::GetInstance().SetPublishFormResult(TEST_FORM_ID, errorCodeInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "SetPublishFormResult_001 end";
}

/**
 * @tc.name: SetPublishFormResult_002
 * @tc.desc: Verify success sets AddFormResultErrorCodes::SUCCESS
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, SetPublishFormResult_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetPublishFormResult_002 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::UNKNOWN;
    Constants::PublishFormResult errorCodeInfo;
    errorCodeInfo.code = Constants::PublishFormErrorCode::SUCCESS;

    auto result = FormPublishAdapter::GetInstance().SetPublishFormResult(TEST_FORM_ID, errorCodeInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID], AddFormResultErrorCodes::SUCCESS);

    GTEST_LOG_(INFO) << "SetPublishFormResult_002 end";
}

/**
 * @tc.name: SetPublishFormResult_003
 * @tc.desc: Verify non-success sets AddFormResultErrorCodes::FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, SetPublishFormResult_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetPublishFormResult_003 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::UNKNOWN;
    Constants::PublishFormResult errorCodeInfo;
    errorCodeInfo.code = Constants::PublishFormErrorCode::INTERNAL_ERROR;

    auto result = FormPublishAdapter::GetInstance().SetPublishFormResult(TEST_FORM_ID, errorCodeInfo);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID], AddFormResultErrorCodes::FAILED);

    GTEST_LOG_(INFO) << "SetPublishFormResult_003 end";
}

// ========== CancelAddFormRequestTimeOutTask Tests ==========

/**
 * @tc.name: CancelAddFormRequestTimeOutTask_001
 * @tc.desc: Verify cancel with ERR_OK sets SUCCESS state
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CancelAddFormRequestTimeOutTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CancelAddFormRequestTimeOutTask_001 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::UNKNOWN;

    FormPublishAdapter::GetInstance().CancelAddFormRequestTimeOutTask(TEST_FORM_ID, ERR_OK);
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID], AddFormResultErrorCodes::SUCCESS);

    GTEST_LOG_(INFO) << "CancelAddFormRequestTimeOutTask_001 end";
}

/**
 * @tc.name: CancelAddFormRequestTimeOutTask_002
 * @tc.desc: Verify cancel with non-ERR_OK sets FAILED state
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CancelAddFormRequestTimeOutTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CancelAddFormRequestTimeOutTask_002 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::UNKNOWN;

    FormPublishAdapter::GetInstance().CancelAddFormRequestTimeOutTask(TEST_FORM_ID, ERR_APPEXECFWK_FORM_COMMON_CODE);
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID], AddFormResultErrorCodes::FAILED);

    GTEST_LOG_(INFO) << "CancelAddFormRequestTimeOutTask_002 end";
}

/**
 * @tc.name: CancelAddFormRequestTimeOutTask_003
 * @tc.desc: Verify cancel for non-existing formId is no-op
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CancelAddFormRequestTimeOutTask_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CancelAddFormRequestTimeOutTask_003 start";

    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_.size(), 0u);

    FormPublishAdapter::GetInstance().CancelAddFormRequestTimeOutTask(TEST_FORM_ID, ERR_OK);
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_.size(), 0u);

    GTEST_LOG_(INFO) << "CancelAddFormRequestTimeOutTask_003 end";
}

// ========== AcquireAddFormResult Tests ==========

/**
 * @tc.name: AcquireAddFormResult_001
 * @tc.desc: Verify formId with SUCCESS state returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, AcquireAddFormResult_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireAddFormResult_001 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::SUCCESS;

    auto result = FormPublishAdapter::GetInstance().AcquireAddFormResult(TEST_FORM_ID);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "AcquireAddFormResult_001 end";
}

/**
 * @tc.name: AcquireAddFormResult_002
 * @tc.desc: Verify formId with FAILED state returns ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, AcquireAddFormResult_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireAddFormResult_002 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::FAILED;

    auto result = FormPublishAdapter::GetInstance().AcquireAddFormResult(TEST_FORM_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "AcquireAddFormResult_002 end";
}

/**
 * @tc.name: AcquireAddFormResult_003
 * @tc.desc: Verify formId with TIMEOUT state returns ERR_APPEXECFWK_FORM_ADD_FORM_TIME_OUT
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, AcquireAddFormResult_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireAddFormResult_003 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::TIMEOUT;

    auto result = FormPublishAdapter::GetInstance().AcquireAddFormResult(TEST_FORM_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_ADD_FORM_TIME_OUT);

    GTEST_LOG_(INFO) << "AcquireAddFormResult_003 end";
}

/**
 * @tc.name: AcquireAddFormResult_005
 * @tc.desc: Verify formId NOT in map returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, AcquireAddFormResult_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AcquireAddFormResult_005 start";

    auto result = FormPublishAdapter::GetInstance().AcquireAddFormResult(TEST_FORM_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "AcquireAddFormResult_005 end";
}

// ========== RequestPublishFormCrossUser Tests ==========

/**
 * @tc.name: RequestPublishFormCrossUser_001
 * @tc.desc: Verify RequestPublishFormCommon failure propagates error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormCrossUser_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormCrossUser_001 start";

    Want want;
    int64_t formId = 0;

    EXPECT_CALL(*MockFormDataMgr::obj, GenerateFormId())
        .WillOnce(Return(-1));

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormCrossUser(want, TEST_USER_ID, formId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "RequestPublishFormCrossUser_001 end";
}

/**
 * @tc.name: RequestPublishFormCrossUser_002
 * @tc.desc: Verify AddRequestPublishFormInfo failure propagates error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormCrossUser_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormCrossUser_002 start";

    Want want;
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(TEST_FORM_ID));
    int64_t formId = 0;

    EXPECT_CALL(*MockFormDataMgr::obj, GenerateFormId())
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, AddRequestPublishFormInfo(_, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormCrossUser(want, TEST_USER_ID, formId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "RequestPublishFormCrossUser_002 end";
}

// ========== QueryPublishFormToHost(userId) Tests ==========

/**
 * @tc.name: QueryPublishFormToHost_006
 * @tc.desc: Verify QueryPublishFormToHost with userId overload, action disallowed returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, QueryPublishFormToHost_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "QueryPublishFormToHost_006 start";

    Want wantToHost;
    wantToHost.SetAction(TEST_INVALID_ACTION);

    auto result = FormPublishAdapter::GetInstance().QueryPublishFormToHost(wantToHost, TEST_USER_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "QueryPublishFormToHost_006 end";
}

/**
 * @tc.name: QueryPublishFormToHost_007
 * @tc.desc: Verify QueryPublishFormToHost with userId, GetAbilityInfoByAction fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, QueryPublishFormToHost_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "QueryPublishFormToHost_007 start";

    Want wantToHost;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(Return(false));

    auto result = FormPublishAdapter::GetInstance().QueryPublishFormToHost(wantToHost, TEST_USER_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "QueryPublishFormToHost_007 end";
}

/**
 * @tc.name: QueryPublishFormToHost_008
 * @tc.desc: Verify QueryPublishFormToHost with userId, success with ability info
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, QueryPublishFormToHost_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "QueryPublishFormToHost_008 start";

    Want wantToHost;

    AbilityInfo abilityInfo;
    abilityInfo.name = TEST_ABILITY_NAME;
    abilityInfo.bundleName = TEST_BUNDLE_NAME;
    ExtensionAbilityInfo emptyExtAbilityInfo;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(abilityInfo), SetArgReferee<3>(emptyExtAbilityInfo),
            Return(true)));

    auto result = FormPublishAdapter::GetInstance().QueryPublishFormToHost(wantToHost, TEST_USER_ID);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "QueryPublishFormToHost_008 end";
}

// ========== CheckIsSystemAppByBundleName Tests ==========

/**
 * @tc.name: CheckIsSystemAppByBundleName_001
 * @tc.desc: Verify GetApplicationInfoV9 fails returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckIsSystemAppByBundleName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckIsSystemAppByBundleName_001 start";

    sptr<MockBundleMgrStub> bundleMgr = new (std::nothrow) MockBundleMgrStub();
    ASSERT_NE(bundleMgr, nullptr);
    EXPECT_CALL(*bundleMgr, GetApplicationInfoV9(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_INVALID_PARAM));

    auto result = FormPublishAdapter::GetInstance().CheckIsSystemAppByBundleName(
        bundleMgr, TEST_USER_ID, TEST_BUNDLE_NAME);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "CheckIsSystemAppByBundleName_001 end";
}

/**
 * @tc.name: CheckIsSystemAppByBundleName_002
 * @tc.desc: Verify isSystemApp=true returns true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckIsSystemAppByBundleName_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckIsSystemAppByBundleName_002 start";

    sptr<MockBundleMgrStub> bundleMgr = new (std::nothrow) MockBundleMgrStub();
    ASSERT_NE(bundleMgr, nullptr);
    ApplicationInfo appInfo;
    appInfo.isSystemApp = true;
    EXPECT_CALL(*bundleMgr, GetApplicationInfoV9(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));

    auto result = FormPublishAdapter::GetInstance().CheckIsSystemAppByBundleName(
        bundleMgr, TEST_USER_ID, TEST_BUNDLE_NAME);
    EXPECT_TRUE(result);

    GTEST_LOG_(INFO) << "CheckIsSystemAppByBundleName_002 end";
}

/**
 * @tc.name: CheckIsSystemAppByBundleName_003
 * @tc.desc: Verify isSystemApp=false returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, CheckIsSystemAppByBundleName_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckIsSystemAppByBundleName_003 start";

    sptr<MockBundleMgrStub> bundleMgr = new (std::nothrow) MockBundleMgrStub();
    ASSERT_NE(bundleMgr, nullptr);
    ApplicationInfo appInfo;
    appInfo.isSystemApp = false;
    EXPECT_CALL(*bundleMgr, GetApplicationInfoV9(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<3>(appInfo), Return(ERR_OK)));

    auto result = FormPublishAdapter::GetInstance().CheckIsSystemAppByBundleName(
        bundleMgr, TEST_USER_ID, TEST_BUNDLE_NAME);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "CheckIsSystemAppByBundleName_003 end";
}

// ========== IsValidPublishEvent Tests ==========

/**
 * @tc.name: IsValidPublishEvent_001
 * @tc.desc: Verify needCheckFormPermission=true and not system app returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IsValidPublishEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsValidPublishEvent_001 start";

    sptr<MockBundleMgrStub> bundleMgr = new (std::nothrow) MockBundleMgrStub();
    ASSERT_NE(bundleMgr, nullptr);
    EXPECT_CALL(*bundleMgr, GetApplicationInfoV9(_, _, _, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_INVALID_PARAM));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingPid())
        .WillRepeatedly(Return(TEST_CALLING_PID));

    Want want;
    auto result = FormPublishAdapter::GetInstance().IsValidPublishEvent(
        bundleMgr, TEST_BUNDLE_NAME, want, true);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "IsValidPublishEvent_001 end";
}

// ========== GetCallerType Tests ==========

/**
 * @tc.name: GetCallerType_001
 * @tc.desc: Verify null IBundleMgr returns TYPE_INVALID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, GetCallerType_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetCallerType_001 start";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));

    auto result = FormPublishAdapter::GetInstance().GetCallerType(TEST_BUNDLE_NAME);
    EXPECT_EQ(result, FormErmsCallerInfo::TYPE_INVALID);

    GTEST_LOG_(INFO) << "GetCallerType_001 end";
}

/**
 * @tc.name: GetCallerType_002
 * @tc.desc: Verify GetApplicationInfo fails returns TYPE_INVALID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, GetCallerType_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetCallerType_002 start";

    sptr<MockBundleMgrStub> bundleMgr = new (std::nothrow) MockBundleMgrStub();
    ASSERT_NE(bundleMgr, nullptr);
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(bundleMgr));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormPublishAdapter::GetInstance().GetCallerType(TEST_BUNDLE_NAME);
    EXPECT_EQ(result, FormErmsCallerInfo::TYPE_INVALID);

    GTEST_LOG_(INFO) << "GetCallerType_002 end";
}

/**
 * @tc.name: GetCallerType_005
 * @tc.desc: Verify default bundleType returns TYPE_INVALID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, GetCallerType_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetCallerType_005 start";

    sptr<MockBundleMgrStub> bundleMgr = new (std::nothrow) MockBundleMgrStub();
    ASSERT_NE(bundleMgr, nullptr);
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(bundleMgr));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormPublishAdapter::GetInstance().GetCallerType(TEST_BUNDLE_NAME);
    EXPECT_EQ(result, FormErmsCallerInfo::TYPE_INVALID);

    GTEST_LOG_(INFO) << "GetCallerType_005 end";
}

// ========== IncreaseAddFormRequestTimeOutTask Tests ==========

/**
 * @tc.name: IncreaseAddFormRequestTimeOutTask_001
 * @tc.desc: Verify null serialQueue_ returns early without crash
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IncreaseAddFormRequestTimeOutTask_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IncreaseAddFormRequestTimeOutTask_001 start";

    auto origQueue = std::move(FormPublishAdapter::GetInstance().serialQueue_);
    FormPublishAdapter::GetInstance().serialQueue_ = nullptr;

    FormPublishAdapter::GetInstance().IncreaseAddFormRequestTimeOutTask(TEST_FORM_ID);
    EXPECT_EQ(FormPublishAdapter::GetInstance().formIdMap_.size(), 0u);

    FormPublishAdapter::GetInstance().serialQueue_ = std::move(origQueue);

    GTEST_LOG_(INFO) << "IncreaseAddFormRequestTimeOutTask_001 end";
}

/**
 * @tc.name: IncreaseAddFormRequestTimeOutTask_002
 * @tc.desc: Verify serialQueue_ is valid and task is scheduled without crash
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IncreaseAddFormRequestTimeOutTask_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IncreaseAddFormRequestTimeOutTask_002 start";

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::UNKNOWN;

    auto &instance = FormPublishAdapter::GetInstance();
    ASSERT_NE(instance.serialQueue_, nullptr);

    instance.IncreaseAddFormRequestTimeOutTask(TEST_FORM_ID);

    // Verify the formIdMap_ still contains the entry (timer hasn't fired yet)
    auto iter = instance.formIdMap_.find(TEST_FORM_ID);
    ASSERT_NE(iter, instance.formIdMap_.end());
    EXPECT_EQ(iter->second, AddFormResultErrorCodes::UNKNOWN);

    // Clean up: cancel the pending timer to avoid interference with other tests
    instance.serialQueue_->CancelDelayTask(
        std::make_pair(static_cast<int64_t>(AddFormTaskType::ADD_FORM_TIMER), TEST_FORM_ID));

    GTEST_LOG_(INFO) << "IncreaseAddFormRequestTimeOutTask_002 end";
}

/**
 * @tc.name: IncreaseAddFormRequestTimeOutTask_003
 * @tc.desc: Verify formId NOT in formIdMap_ does not change state
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IncreaseAddFormRequestTimeOutTask_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IncreaseAddFormRequestTimeOutTask_003 start";

    auto &instance = FormPublishAdapter::GetInstance();
    ASSERT_NE(instance.serialQueue_, nullptr);
    EXPECT_EQ(instance.formIdMap_.size(), 0u);

    instance.IncreaseAddFormRequestTimeOutTask(TEST_FORM_ID);

    EXPECT_EQ(instance.formIdMap_.size(), 0u);

    GTEST_LOG_(INFO) << "IncreaseAddFormRequestTimeOutTask_003 end";
}

// ========== RequestPublishForm Tests ==========
/**
 * @tc.name: RequestPublishForm_001
 * @tc.desc: Verify CheckPublishForm fails returns error code
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishForm_001 start";

    Want want;
    want.SetBundle(TEST_BUNDLE_NAME);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, TEST_MODULE_NAME);
    std::unique_ptr<FormProviderData> formBindingData = std::make_unique<FormProviderData>();
    int64_t formId = 0;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(nullptr));

    auto result = FormPublishAdapter::GetInstance().RequestPublishForm(
        want, true, formBindingData, formId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    GTEST_LOG_(INFO) << "RequestPublishForm_001 end";
}

// ========== RequestPublishFormToHost (1-arg) Tests ==========

/**
 * @tc.name: RequestPublishFormToHost_001
 * @tc.desc: Verify StartAbility fails returns error code
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormToHost_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormToHost_001 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(TEST_FORM_ID));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    AbilityInfo abilityInfo;
    abilityInfo.name = TEST_ABILITY_NAME;
    abilityInfo.bundleName = "com.host.bundle";
    ExtensionAbilityInfo emptyExtAbilityInfo;
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(abilityInfo), SetArgReferee<3>(emptyExtAbilityInfo),
            Return(true)));
    EXPECT_CALL(*MockFormAmsHelper::obj, StartAbility(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockFormCallbackAdapter::obj, GetFormPublishInterceptor())
        .WillRepeatedly(Return(nullptr));

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::SUCCESS;

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormToHost(want);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "RequestPublishFormToHost_001 end";
}

/**
 * @tc.name: RequestPublishFormToHost_002
 * @tc.desc: Verify formId parse fails returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormToHost_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormToHost_002 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::string("invalid_form_id"));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(Return(false));

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormToHost(want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RequestPublishFormToHost_002 end";
}

/**
 * @tc.name: RequestPublishFormToHost_003
 * @tc.desc: Verify interceptor nullptr calls AcquireAddFormResult
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormToHost_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormToHost_003 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(TEST_FORM_ID));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormCallbackAdapter::obj, GetFormPublishInterceptor())
        .WillOnce(Return(nullptr));

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::SUCCESS;

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormToHost(want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RequestPublishFormToHost_003 end";
}

/**
 * @tc.name: RequestPublishFormToHost_004
 * @tc.desc: Verify interceptor ProcessPublishForm succeeds calls AcquireAddFormResult
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormToHost_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormToHost_004 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(TEST_FORM_ID));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(Return(false));

    sptr<MockFormPublishInterceptor> mockInterceptor = new (std::nothrow) MockFormPublishInterceptor();
    ASSERT_NE(mockInterceptor, nullptr);
    EXPECT_CALL(*mockInterceptor, ProcessPublishForm(_))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockFormCallbackAdapter::obj, GetFormPublishInterceptor())
        .WillOnce(Return(mockInterceptor));

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::SUCCESS;

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormToHost(want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RequestPublishFormToHost_004 end";
}

/**
 * @tc.name: RequestPublishFormToHost_005
 * @tc.desc: Verify success path with QueryPublishFormToHost and StartAbility succeeding
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormToHost_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormToHost_005 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(TEST_FORM_ID));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    AbilityInfo abilityInfo;
    abilityInfo.name = TEST_ABILITY_NAME;
    abilityInfo.bundleName = "com.host.bundle";
    ExtensionAbilityInfo emptyExtAbilityInfo;
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(abilityInfo), SetArgReferee<3>(emptyExtAbilityInfo),
            Return(true)));
    EXPECT_CALL(*MockFormAmsHelper::obj, StartAbility(_, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockFormCallbackAdapter::obj, GetFormPublishInterceptor())
        .WillOnce(Return(nullptr));

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::SUCCESS;

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormToHost(want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RequestPublishFormToHost_005 end";
}

// ========== RequestPublishFormToHost (2-arg) Tests ==========

/**
 * @tc.name: RequestPublishFormToHost_006
 * @tc.desc: Verify 2-arg overload with QueryPublishFormToHost success and StartAbility fail
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormToHost_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormToHost_006 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(TEST_FORM_ID));

    AbilityInfo abilityInfo;
    abilityInfo.name = TEST_ABILITY_NAME;
    abilityInfo.bundleName = "com.host.bundle";
    ExtensionAbilityInfo emptyExtAbilityInfo;
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(abilityInfo), SetArgReferee<3>(emptyExtAbilityInfo),
            Return(true)));
    EXPECT_CALL(*MockFormAmsHelper::obj, StartAbility(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    EXPECT_CALL(*MockFormCallbackAdapter::obj, GetFormPublishInterceptor())
        .WillRepeatedly(Return(nullptr));

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::SUCCESS;

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormToHost(want, TEST_USER_ID);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "RequestPublishFormToHost_006 end";
}

/**
 * @tc.name: RequestPublishFormToHost_007
 * @tc.desc: Verify 2-arg overload with formId parse failure
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormToHost_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormToHost_007 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::string("invalid_id"));

    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(Return(false));

    auto result = FormPublishAdapter::GetInstance().RequestPublishFormToHost(want, TEST_USER_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RequestPublishFormToHost_007 end";
}

/**
 * @tc.name: RequestPublishFormToHost_008
 * @tc.desc: Verify 2-arg overload success path with interceptor nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, RequestPublishFormToHost_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestPublishFormToHost_008 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    want.SetParam(Constants::PARAM_FORM_IDENTITY_KEY, std::to_string(TEST_FORM_ID));

    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormCallbackAdapter::obj, GetFormPublishInterceptor())
        .WillOnce(Return(nullptr));

    FormPublishAdapter::GetInstance().formIdMap_[TEST_FORM_ID] = AddFormResultErrorCodes::SUCCESS;
    auto result = FormPublishAdapter::GetInstance().RequestPublishFormToHost(want, TEST_USER_ID);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RequestPublishFormToHost_008 end";
}

// ========== GetBundleName Additional Tests ==========
 
/**
 * @tc.name: GetBundleName_002
 * @tc.desc: Verify non-system app with needCheckFormPermission=true returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, GetBundleName_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetBundleName_002 start";
 
    std::string bundleName;
    sptr<MockBundleMgrStub> bundleMgr = new MockBundleMgrStub();
 
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(bundleMgr));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*bundleMgr, CheckIsSystemAppByUid(TEST_CALLING_UID))
        .WillOnce(Return(false));
 
    auto result = FormPublishAdapter::GetInstance().GetBundleName(bundleName, true);
    EXPECT_FALSE(result);
 
    GTEST_LOG_(INFO) << "GetBundleName_002 end";
}
 
/**
 * @tc.name: GetBundleName_003
 * @tc.desc: Verify GetNameForUid failure returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, GetBundleName_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetBundleName_003 start";
 
    std::string bundleName;
    sptr<MockBundleMgrStub> bundleMgr = new MockBundleMgrStub();
 
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(bundleMgr));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(SYSTEM_UID));
    EXPECT_CALL(*bundleMgr, CheckIsSystemAppByUid(SYSTEM_UID))
        .WillOnce(Return(true));
    EXPECT_CALL(*bundleMgr, GetNameForUid(SYSTEM_UID, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
 
    auto result = FormPublishAdapter::GetInstance().GetBundleName(bundleName, true);
    EXPECT_FALSE(result);
 
    GTEST_LOG_(INFO) << "GetBundleName_003 end";
}
 
/**
 * @tc.name: GetBundleName_004
 * @tc.desc: Verify success returns true and sets bundleName
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, GetBundleName_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetBundleName_004 start";
 
    std::string bundleName;
    sptr<MockBundleMgrStub> bundleMgr = new MockBundleMgrStub();
 
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(bundleMgr));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(SYSTEM_UID));
    EXPECT_CALL(*bundleMgr, CheckIsSystemAppByUid(SYSTEM_UID))
        .WillOnce(Return(true));
    EXPECT_CALL(*bundleMgr, GetNameForUid(SYSTEM_UID, _))
        .WillOnce(DoAll(SetArgReferee<1>(TEST_BUNDLE_NAME), Return(ERR_OK)));
 
    auto result = FormPublishAdapter::GetInstance().GetBundleName(bundleName, true);
    EXPECT_TRUE(result);
    EXPECT_EQ(bundleName, TEST_BUNDLE_NAME);
 
    GTEST_LOG_(INFO) << "GetBundleName_004 end";
}
 
// ========== IsRequestPublishFormSupported Additional Tests ==========
 
/**
 * @tc.name: IsRequestPublishFormSupported_002
 * @tc.desc: Verify IsErmsSupportPublishForm returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormPublishAdapterTest, IsRequestPublishFormSupported_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsRequestPublishFormSupported_002 start";
 
    sptr<MockBundleMgrStub> bundleMgr = new MockBundleMgrStub();
 
    EXPECT_CALL(*MockFormBmsHelper::obj, GetBundleMgr())
        .WillOnce(Return(bundleMgr));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));
    EXPECT_CALL(*bundleMgr, CheckIsSystemAppByUid(TEST_CALLING_UID))
        .WillOnce(Return(false));

    auto result = FormPublishAdapter::GetInstance().IsRequestPublishFormSupported();
    EXPECT_FALSE(result);
 
    GTEST_LOG_(INFO) << "IsRequestPublishFormSupported_002 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
