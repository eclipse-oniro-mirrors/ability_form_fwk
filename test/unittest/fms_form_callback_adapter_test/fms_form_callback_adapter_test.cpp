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
#include "form_mgr/form_callback_adapter.h"
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
#include "template_form_detail_info.h"
#include "form_publish_interceptor_interface.h"

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

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TEST_USER_ID = 100;
constexpr int32_t TEST_CALLING_UID = 20000000;
constexpr int64_t TEST_FORM_ID = 123456789L;
constexpr int32_t TEST_DIMENSION_ID = 2;
constexpr int32_t INVALID_UID = 99999999;
constexpr int64_t INVALID_FORM_ID = -1L;
constexpr int64_t ZERO_FORM_ID = 0L;
}

class FmsFormCallbackAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormCallbackAdapterTest::SetUpTestCase()
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
}

void FmsFormCallbackAdapterTest::TearDownTestCase()
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
}

void FmsFormCallbackAdapterTest::SetUp()
{
}

void FmsFormCallbackAdapterTest::TearDown()
{
}

// ========== RegisterFormRouterProxy Tests ==========

/**
 * @tc.name: RegisterFormRouterProxy_001
 * @tc.desc: Verify null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterFormRouterProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_001 start";

    std::vector<int64_t> formIds = { TEST_FORM_ID };
    sptr<IRemoteObject> callerToken = nullptr;

    auto result = FormCallbackAdapter::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_001 end";
}

/**
 * @tc.name: RegisterFormRouterProxy_002
 * @tc.desc: Verify formId <= 0 returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterFormRouterProxy_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_002 start";

    std::vector<int64_t> formIds = { INVALID_FORM_ID, ZERO_FORM_ID };
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_002 end";
}

/**
 * @tc.name: RegisterFormRouterProxy_003
 * @tc.desc: Verify no matching form record returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterFormRouterProxy_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_003 start";

    std::vector<int64_t> formIds = { TEST_FORM_ID };
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(Return(false));

    auto result = FormCallbackAdapter::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_003 end";
}

/**
 * @tc.name: RegisterFormRouterProxy_004
 * @tc.desc: Verify not self owned returns ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterFormRouterProxy_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_004 start";

    std::vector<int64_t> formIds = { TEST_FORM_ID };
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    FormRecord record;
    record.providerUserId = TEST_USER_ID;
    record.formUserUids = { INVALID_UID };

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormCallbackAdapter::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);

    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_004 end";
}

/**
 * @tc.name: RegisterFormRouterProxy_005
 * @tc.desc: Verify not matching providerUserId returns ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterFormRouterProxy_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_005 start";

    std::vector<int64_t> formIds = { TEST_FORM_ID };
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    FormRecord record;
    record.providerUserId = TEST_USER_ID + 1;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormCallbackAdapter::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);

    GTEST_LOG_(INFO) << "RegisterFormRouterProxy_005 end";
}

// ========== UnregisterFormRouterProxy Tests ==========

/**
 * @tc.name: UnregisterFormRouterProxy_001
 * @tc.desc: Verify formId <= 0 returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterFormRouterProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_001 start";

    std::vector<int64_t> formIds = { INVALID_FORM_ID, ZERO_FORM_ID };

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_001 end";
}

/**
 * @tc.name: UnregisterFormRouterProxy_002
 * @tc.desc: Verify no matching record returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterFormRouterProxy_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_002 start";

    std::vector<int64_t> formIds = { TEST_FORM_ID };

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(Return(false));

    auto result = FormCallbackAdapter::GetInstance().UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_002 end";
}

/**
 * @tc.name: UnregisterFormRouterProxy_003
 * @tc.desc: Verify not self owned returns ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterFormRouterProxy_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_003 start";

    std::vector<int64_t> formIds = { TEST_FORM_ID };

    FormRecord record;
    record.providerUserId = TEST_USER_ID;
    record.formUserUids = { INVALID_UID };

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormCallbackAdapter::GetInstance().UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);

    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_003 end";
}

// ========== RegisterPublishFormInterceptor Tests ==========

/**
 * @tc.name: RegisterPublishFormInterceptor_001
 * @tc.desc: Verify null interceptorCallback returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterPublishFormInterceptor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterPublishFormInterceptor_001 start";

    sptr<IRemoteObject> interceptorCallback = nullptr;

    auto result = FormCallbackAdapter::GetInstance().RegisterPublishFormInterceptor(interceptorCallback);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RegisterPublishFormInterceptor_001 end";
}

// ========== UnregisterPublishFormInterceptor Tests ==========

/**
 * @tc.name: UnregisterPublishFormInterceptor_001
 * @tc.desc: Verify null interceptorCallback returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterPublishFormInterceptor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterPublishFormInterceptor_001 start";

    sptr<IRemoteObject> interceptorCallback = nullptr;

    auto result = FormCallbackAdapter::GetInstance().UnregisterPublishFormInterceptor(interceptorCallback);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "UnregisterPublishFormInterceptor_001 end";
}

// ========== RegisterOverflowProxy Tests ==========

/**
 * @tc.name: RegisterOverflowProxy_001
 * @tc.desc: Verify successful registration with valid callerToken
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterOverflowProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterOverflowProxy_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().RegisterOverflowProxy(callerToken);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().overflowRegistry_.Clear();

    GTEST_LOG_(INFO) << "RegisterOverflowProxy_001 end";
}

// ========== UnregisterOverflowProxy Tests ==========

/**
 * @tc.name: UnregisterOverflowProxy_001
 * @tc.desc: Verify successful unregistration after registration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterOverflowProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterOverflowProxy_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // Register first
    auto regResult = FormCallbackAdapter::GetInstance().RegisterOverflowProxy(callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    // Then unregister
    auto unregResult = FormCallbackAdapter::GetInstance().UnregisterOverflowProxy();
    EXPECT_EQ(unregResult, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterOverflowProxy_001 end";
}

// ========== RequestOverflow Tests ==========

/**
 * @tc.name: RequestOverflow_001
 * @tc.desc: Verify SceneAnimationCheck failure returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RequestOverflow_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestOverflow_001 start";

    int32_t callingUid = TEST_CALLING_UID;
    OverflowInfo overflowInfo;
    bool isOverflow = false;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(Return(false));

    auto result = FormCallbackAdapter::GetInstance().RequestOverflow(
        INVALID_FORM_ID, callingUid, overflowInfo, isOverflow);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RequestOverflow_001 end";
}

/**
 * @tc.name: RequestOverflow_003
 * @tc.desc: Verify no host registered returns ERR_APPEXECFWK_FORM_GET_HOST_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RequestOverflow_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestOverflow_003 start";

    int32_t callingUid = TEST_CALLING_UID;
    OverflowInfo overflowInfo;
    bool isOverflow = false;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = "com.test.bundle";
    record.abilityName = "MainAbility";
    record.moduleName = "entry";
    record.uid = callingUid;
    record.providerUserId = TEST_USER_ID;
    record.formUserUids = { callingUid };

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillRepeatedly(Return(ERR_APPEXECFWK_FORM_GET_INFO_FAILED));

    auto result = FormCallbackAdapter::GetInstance().RequestOverflow(
        TEST_FORM_ID, callingUid, overflowInfo, isOverflow);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "RequestOverflow_003 end";
}

// ========== RegisterChangeSceneAnimationStateProxy Tests ==========

/**
 * @tc.name: RegisterChangeSceneAnimationStateProxy_001
 * @tc.desc: Verify successful registration with valid callerToken
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterChangeSceneAnimationStateProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterChangeSceneAnimationStateProxy_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().RegisterChangeSceneAnimationStateProxy(callerToken);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().sceneAnimationRegistry_.Clear();

    GTEST_LOG_(INFO) << "RegisterChangeSceneAnimationStateProxy_001 end";
}

// ========== UnregisterChangeSceneAnimationStateProxy Tests ==========

/**
 * @tc.name: UnregisterChangeSceneAnimationStateProxy_001
 * @tc.desc: Verify successful unregistration after registration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterChangeSceneAnimationStateProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterChangeSceneAnimationStateProxy_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto regResult = FormCallbackAdapter::GetInstance().RegisterChangeSceneAnimationStateProxy(callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    auto unregResult = FormCallbackAdapter::GetInstance().UnregisterChangeSceneAnimationStateProxy();
    EXPECT_EQ(unregResult, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterChangeSceneAnimationStateProxy_001 end";
}

// ========== ChangeSceneAnimationState Tests ==========

/**
 * @tc.name: ChangeSceneAnimationState_001
 * @tc.desc: Verify invalid formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, ChangeSceneAnimationState_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ChangeSceneAnimationState_001 start";

    int32_t callingUid = TEST_CALLING_UID;
    int32_t state = 1;

    auto result = FormCallbackAdapter::GetInstance().ChangeSceneAnimationState(
        INVALID_FORM_ID, callingUid, state);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ChangeSceneAnimationState_001 end";
}

// ========== RegisterGetFormRectProxy Tests ==========

/**
 * @tc.name: RegisterGetFormRectProxy_001
 * @tc.desc: Verify successful registration with valid callerToken
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterGetFormRectProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterGetFormRectProxy_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().RegisterGetFormRectProxy(callerToken);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().formRectRegistry_.Clear();

    GTEST_LOG_(INFO) << "RegisterGetFormRectProxy_001 end";
}

// ========== UnregisterGetFormRectProxy Tests ==========

/**
 * @tc.name: UnregisterGetFormRectProxy_001
 * @tc.desc: Verify successful unregistration after registration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterGetFormRectProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterGetFormRectProxy_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto regResult = FormCallbackAdapter::GetInstance().RegisterGetFormRectProxy(callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    auto unregResult = FormCallbackAdapter::GetInstance().UnregisterGetFormRectProxy();
    EXPECT_EQ(unregResult, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterGetFormRectProxy_001 end";
}

// ========== GetFormRect Tests ==========

/**
 * @tc.name: GetFormRect_001
 * @tc.desc: Verify invalid formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetFormRect_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormRect_001 start";

    int32_t callingUid = TEST_CALLING_UID;
    Rect rect;

    auto result = FormCallbackAdapter::GetInstance().GetFormRect(INVALID_FORM_ID, callingUid, rect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "GetFormRect_001 end";
}

/**
 * @tc.name: GetFormRect_002
 * @tc.desc: Verify form not exist returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetFormRect_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormRect_002 start";

    int32_t callingUid = TEST_CALLING_UID;
    Rect rect;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = callingUid;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)))
        .WillOnce(Return(false));

    auto result = FormCallbackAdapter::GetInstance().GetFormRect(TEST_FORM_ID, callingUid, rect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "GetFormRect_002 end";
}

// ========== RegisterGetLiveFormStatusProxy Tests ==========

/**
 * @tc.name: RegisterGetLiveFormStatusProxy_001
 * @tc.desc: Verify successful registration with valid callerToken
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterGetLiveFormStatusProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterGetLiveFormStatusProxy_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().RegisterGetLiveFormStatusProxy(callerToken);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Clear();

    GTEST_LOG_(INFO) << "RegisterGetLiveFormStatusProxy_001 end";
}

// ========== UnregisterGetLiveFormStatusProxy Tests ==========

/**
 * @tc.name: UnregisterGetLiveFormStatusProxy_001
 * @tc.desc: Verify successful unregistration after registration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterGetLiveFormStatusProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterGetLiveFormStatusProxy_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto regResult = FormCallbackAdapter::GetInstance().RegisterGetLiveFormStatusProxy(callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    auto unregResult = FormCallbackAdapter::GetInstance().UnregisterGetLiveFormStatusProxy();
    EXPECT_EQ(unregResult, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterGetLiveFormStatusProxy_001 end";
}

// ========== GetLiveFormStatus Tests ==========

/**
 * @tc.name: GetLiveFormStatus_001
 * @tc.desc: Verify no proxy registered returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetLiveFormStatus_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetLiveFormStatus_001 start";

    std::unordered_map<std::string, std::string> liveFormStatusMap;

    // Clear registry to ensure no proxies
    FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Clear();

    auto result = FormCallbackAdapter::GetInstance().GetLiveFormStatus(liveFormStatusMap);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "GetLiveFormStatus_001 end";
}

// ========== RegisterPublishFormCrossBundleControl Tests ==========

/**
 * @tc.name: RegisterPublishFormCrossBundleControl_001
 * @tc.desc: Verify successful registration with valid callerToken
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterPublishFormCrossBundleControl_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterPublishFormCrossBundleControl_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().RegisterPublishFormCrossBundleControl(callerToken);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().crossBundleControlRegistry_.Clear();

    GTEST_LOG_(INFO) << "RegisterPublishFormCrossBundleControl_001 end";
}

// ========== UnregisterPublishFormCrossBundleControl Tests ==========

/**
 * @tc.name: UnregisterPublishFormCrossBundleControl_001
 * @tc.desc: Verify successful unregistration after registration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterPublishFormCrossBundleControl_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterPublishFormCrossBundleControl_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto regResult = FormCallbackAdapter::GetInstance().RegisterPublishFormCrossBundleControl(callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    auto unregResult = FormCallbackAdapter::GetInstance().UnregisterPublishFormCrossBundleControl();
    EXPECT_EQ(unregResult, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterPublishFormCrossBundleControl_001 end";
}

// ========== PublishFormCrossBundleControl Tests ==========

/**
 * @tc.name: PublishFormCrossBundleControl_001
 * @tc.desc: Verify no proxy registered returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, PublishFormCrossBundleControl_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PublishFormCrossBundleControl_001 start";

    PublishFormCrossBundleInfo bundleInfo;
    bundleInfo.callerBundleName = "com.test.caller";
    bundleInfo.targetBundleName = "com.test.target";

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    // Clear registry to ensure no proxies
    FormCallbackAdapter::GetInstance().crossBundleControlRegistry_.Clear();

    auto result = FormCallbackAdapter::GetInstance().PublishFormCrossBundleControl(bundleInfo);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "PublishFormCrossBundleControl_001 end";
}

// ========== RegisterTemplateFormDetailInfoChange Tests ==========

/**
 * @tc.name: RegisterTemplateFormDetailInfoChange_001
 * @tc.desc: Verify successful registration with valid callerToken
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterTemplateFormDetailInfoChange_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterTemplateFormDetailInfoChange_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().RegisterTemplateFormDetailInfoChange(callerToken);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().templateFormDetailInfoRegistry_.Clear();

    GTEST_LOG_(INFO) << "RegisterTemplateFormDetailInfoChange_001 end";
}

// ========== UnregisterTemplateFormDetailInfoChange Tests ==========

/**
 * @tc.name: UnregisterTemplateFormDetailInfoChange_001
 * @tc.desc: Verify successful unregistration after registration
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterTemplateFormDetailInfoChange_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterTemplateFormDetailInfoChange_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto regResult = FormCallbackAdapter::GetInstance().RegisterTemplateFormDetailInfoChange(callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    auto unregResult = FormCallbackAdapter::GetInstance().UnregisterTemplateFormDetailInfoChange();
    EXPECT_EQ(unregResult, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterTemplateFormDetailInfoChange_001 end";
}

// ========== UpdateTemplateFormDetailInfo Tests ==========

/**
 * @tc.name: UpdateTemplateFormDetailInfo_001
 * @tc.desc: Verify no proxy registered returns ERR_APPEXECFWK_TEMPLATE_UNSUPPORTED_OPERATION
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UpdateTemplateFormDetailInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateTemplateFormDetailInfo_001 start";

    std::vector<TemplateFormDetailInfo> templateFormInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    // Clear registry to ensure no proxies
    FormCallbackAdapter::GetInstance().templateFormDetailInfoRegistry_.Clear();

    auto result = FormCallbackAdapter::GetInstance().UpdateTemplateFormDetailInfo(templateFormInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_TEMPLATE_UNSUPPORTED_OPERATION);

    GTEST_LOG_(INFO) << "UpdateTemplateFormDetailInfo_001 end";
}

// ========== SetFormPublishInterceptor Tests ==========

/**
 * @tc.name: SetFormPublishInterceptor_001
 * @tc.desc: Verify setting nullptr interceptor
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, SetFormPublishInterceptor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SetFormPublishInterceptor_001 start";

    FormCallbackAdapter::GetInstance().SetFormPublishInterceptor(nullptr);

    auto interceptor = FormCallbackAdapter::GetInstance().GetFormPublishInterceptor();
    EXPECT_EQ(interceptor, nullptr);

    GTEST_LOG_(INFO) << "SetFormPublishInterceptor_001 end";
}

// ========== GetFormPublishInterceptor Tests ==========

/**
 * @tc.name: GetFormPublishInterceptor_001
 * @tc.desc: Verify initial interceptor is null
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetFormPublishInterceptor_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormPublishInterceptor_001 start";

    FormCallbackAdapter::GetInstance().formPublishInterceptor_ = nullptr;

    auto interceptor = FormCallbackAdapter::GetInstance().GetFormPublishInterceptor();
    EXPECT_EQ(interceptor, nullptr);

    GTEST_LOG_(INFO) << "GetFormPublishInterceptor_001 end";
}

// ========== CallerCheck Tests ==========

/**
 * @tc.name: CallerCheck_001
 * @tc.desc: Verify invalid formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, CallerCheck_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallerCheck_001 start";

    auto result = FormCallbackAdapter::GetInstance().CallerCheck(INVALID_FORM_ID, TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CallerCheck_001 end";
}

/**
 * @tc.name: CallerCheck_002
 * @tc.desc: Verify form not exist returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, CallerCheck_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallerCheck_002 start";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(Return(false));

    auto result = FormCallbackAdapter::GetInstance().CallerCheck(TEST_FORM_ID, TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "CallerCheck_002 end";
}

/**
 * @tc.name: CallerCheck_003
 * @tc.desc: Verify uid mismatch returns ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, CallerCheck_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallerCheck_003 start";

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = INVALID_UID;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormCallbackAdapter::GetInstance().CallerCheck(TEST_FORM_ID, TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);

    GTEST_LOG_(INFO) << "CallerCheck_003 end";
}

/**
 * @tc.name: CallerCheck_004
 * @tc.desc: Verify matching uid returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, CallerCheck_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallerCheck_004 start";

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = TEST_CALLING_UID;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormCallbackAdapter::GetInstance().CallerCheck(TEST_FORM_ID, TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "CallerCheck_004 end";
}

// ========== SceneAnimationCheck Tests ==========

/**
 * @tc.name: SceneAnimationCheck_001
 * @tc.desc: Verify CallerCheck failure propagates error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, SceneAnimationCheck_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SceneAnimationCheck_001 start";

    auto result = FormCallbackAdapter::GetInstance().SceneAnimationCheck(INVALID_FORM_ID, TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "SceneAnimationCheck_001 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
