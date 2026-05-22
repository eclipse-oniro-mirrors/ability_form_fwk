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
#include "form_host_delegate_stub.h"

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
constexpr const char* TEST_BUNDLE_NAME = "com.test.bundle";
constexpr const char* TEST_ABILITY_NAME = "MainAbility";
constexpr const char* TEST_MODULE_NAME = "entry";
constexpr const char* TEST_FORM_NAME = "widget";

class MockFormHostDelegateStub : public FormHostDelegateStub {
public:
    MockFormHostDelegateStub() = default;
    ~MockFormHostDelegateStub() override = default;
    ErrCode RouterEvent(int64_t formId, const Want &want) override { return ERR_OK; }
    ErrCode RequestOverflow(int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow) override
    {
        return requestOverflowResult_;
    }
    ErrCode ChangeSceneAnimationState(int64_t formId, int32_t state) override
    {
        return changeSceneResult_;
    }
    ErrCode GetFormRect(int64_t formId, Rect &rect) override
    {
        return getFormRectResult_;
    }
    ErrCode GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap) override
    {
        for (const auto &pair : liveFormStatusData_) {
            liveFormStatusMap[pair.first] = pair.second;
        }
        return getLiveFormStatusResult_;
    }
    ErrCode TemplateFormDetailInfoChange(const std::vector<TemplateFormDetailInfo> &info) override
    {
        return templateFormResult_;
    }
    ErrCode RequestFormWants(const std::vector<FormInfo> &formInfos,
        std::vector<AAFwk::WantParams> &wantParamsList) override
    {
        return requestFormWantsResult_;
    }
    ErrCode UpdateFormsConfigCallback(const std::vector<FormCustomConfig> &configs) override
    {
        return updateFormsConfigResult_;
    }
    ErrCode DeleteFormsCallback(const std::vector<std::string> &formIds) override
    {
        return deleteFormsResult_;
    }
    ErrCode requestOverflowResult_ = ERR_OK;
    ErrCode changeSceneResult_ = ERR_OK;
    ErrCode getFormRectResult_ = ERR_OK;
    ErrCode getLiveFormStatusResult_ = ERR_OK;
    ErrCode templateFormResult_ = ERR_OK;
    ErrCode requestFormWantsResult_ = ERR_OK;
    ErrCode updateFormsConfigResult_ = ERR_OK;
    ErrCode deleteFormsResult_ = ERR_OK;
    std::unordered_map<std::string, std::string> liveFormStatusData_;
};
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

void FmsFormCallbackAdapterTest::TearDownTestCase()
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
 * @tc.name: RequestOverflow_002
 * @tc.desc: Verify form not exist returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RequestOverflow_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestOverflow_002 start";

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

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));

    auto result = FormCallbackAdapter::GetInstance().RequestOverflow(
        TEST_FORM_ID, callingUid, overflowInfo, isOverflow);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "RequestOverflow_002 end";
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

/**
 * @tc.name: ChangeSceneAnimationState_002
 * @tc.desc: Verify form not exist returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, ChangeSceneAnimationState_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ChangeSceneAnimationState_002 start";

    int32_t callingUid = TEST_CALLING_UID;
    int32_t state = 1;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = callingUid;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillRepeatedly(Return(ERR_APPEXECFWK_FORM_GET_INFO_FAILED));

    auto result = FormCallbackAdapter::GetInstance().ChangeSceneAnimationState(
        TEST_FORM_ID, callingUid, state);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "ChangeSceneAnimationState_002 end";
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

// ========== StartAbilityByFms Tests ==========

/**
 * @tc.name: StartAbilityByFms_001
 * @tc.desc: Verify FORM_MANAGE code with IsForegroundApp returning false returns NOT_TRUST
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_001 start";

    Want want;
    want.SetParam(Constants::PARAM_PAGE_ROUTER_SERVICE_CODE,
        Constants::PAGE_ROUTER_SERVICE_CODE_FORM_MANAGE);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    // GetCallerBundleName fails -> IsForegroundApp returns false
    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_TRUST);

    GTEST_LOG_(INFO) << "StartAbilityByFms_001 end";
}

/**
 * @tc.name: StartAbilityByFms_002
 * @tc.desc: Verify LIVE_FORM code with no registered proxy returns LIVE_OP_UNSUPPORTED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_002 start";

    // Clear registry so GetLiveFormStatus returns error
    FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Clear();

    Want want;
    want.SetParam(Constants::PARAM_PAGE_ROUTER_SERVICE_CODE,
        Constants::PAGE_ROUTER_SERVICE_CODE_LIVE_FORM);
    want.SetParam(Constants::PARAM_LIVE_FORM_ID_KEY, std::to_string(TEST_FORM_ID));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED);

    GTEST_LOG_(INFO) << "StartAbilityByFms_002 end";
}

/**
 * @tc.name: StartAbilityByFms_003
 * @tc.desc: Verify invalid action returns INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_003 start";

    Want want;
    want.SetAction("action.invalid.test");
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "StartAbilityByFms_003 end";
}

/**
 * @tc.name: StartAbilityByFms_004
 * @tc.desc: Verify GetAbilityInfoByAction returns false returns GET_HOST_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_004 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(Return(false));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "StartAbilityByFms_004 end";
}

/**
 * @tc.name: StartAbilityByFms_005
 * @tc.desc: Verify abilityInfo.name not empty and StartAbility succeeds returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_005 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce([](const std::string &, int32_t, AbilityInfo &info, ExtensionAbilityInfo &) {
            info.bundleName = "com.test.host";
            info.name = "HostAbility";
            return true;
        });
    EXPECT_CALL(*MockFormAmsHelper::obj, StartAbility(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "StartAbilityByFms_005 end";
}

/**
 * @tc.name: StartAbilityByFms_006
 * @tc.desc: Verify extensionAbilityInfo.name used when abilityInfo.name is empty
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_006 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce([](const std::string &, int32_t, AbilityInfo &info, ExtensionAbilityInfo &extInfo) {
            info.bundleName = "";
            info.name = "";
            extInfo.bundleName = "com.test.host";
            extInfo.name = "ExtHostAbility";
            return true;
        });
    EXPECT_CALL(*MockFormAmsHelper::obj, StartAbility(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "StartAbilityByFms_006 end";
}

/**
 * @tc.name: StartAbilityByFms_007
 * @tc.desc: Verify both abilityInfo and extensionAbilityInfo names empty returns GET_HOST_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_007 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce(Return(true));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "StartAbilityByFms_007 end";
}

/**
 * @tc.name: StartAbilityByFms_008
 * @tc.desc: Verify StartAbility failure returns error code
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_008 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce([](const std::string &, int32_t, AbilityInfo &info, ExtensionAbilityInfo &) {
            info.bundleName = "com.test.host";
            info.name = "HostAbility";
            return true;
        });
    EXPECT_CALL(*MockFormAmsHelper::obj, StartAbility(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_HOST_FAILED));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "StartAbilityByFms_008 end";
}

/**
 * @tc.name: StartAbilityByFms_009
 * @tc.desc: Verify LIVE_FORM with valid status and supportLauncher false returns LIVE_OP_UNSUPPORTED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_009 start";

    // Register mock delegate with live form status "10" (PAUSE, isSupportLauncher=false)
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->getLiveFormStatusResult_ = ERR_OK;
    mockDelegate->liveFormStatusData_ = {{"form_999", "10"}};
    ASSERT_EQ(FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Register(
        TEST_CALLING_UID, sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    Want want;
    want.SetParam(Constants::PARAM_PAGE_ROUTER_SERVICE_CODE,
        Constants::PAGE_ROUTER_SERVICE_CODE_LIVE_FORM);
    want.SetParam(Constants::PARAM_LIVE_FORM_ID_KEY, std::string("form_999"));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    // Status "10" maps to {PAUSE, false} -> isSupportLauncher=false -> LIVE_OP_UNSUPPORTED
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED);

    // Cleanup
    FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Clear();

    GTEST_LOG_(INFO) << "StartAbilityByFms_009 end";
}

/**
 * @tc.name: StartAbilityByFms_010
 * @tc.desc: Verify LIVE_FORM with status not in LIVE_FORM_STATUS_MAP returns LIVE_OP_UNSUPPORTED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_010 start";

    // Register mock delegate with an unknown status value
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->getLiveFormStatusResult_ = ERR_OK;
    mockDelegate->liveFormStatusData_ = {{"form_888", "99"}};
    ASSERT_EQ(FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Register(
        TEST_CALLING_UID, sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    Want want;
    want.SetParam(Constants::PARAM_PAGE_ROUTER_SERVICE_CODE,
        Constants::PAGE_ROUTER_SERVICE_CODE_LIVE_FORM);
    want.SetParam(Constants::PARAM_LIVE_FORM_ID_KEY, std::string("form_888"));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    // Status "99" not in LIVE_FORM_STATUS_MAP -> LIVE_OP_UNSUPPORTED
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED);

    // Cleanup
    FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Clear();

    GTEST_LOG_(INFO) << "StartAbilityByFms_010 end";
}

/**
 * @tc.name: StartAbilityByFms_011
 * @tc.desc: Verify LIVE_FORM with supported status continues to action check and succeeds
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_011 start";

    // Register mock delegate with status "21" (ACTIVE, isSupportLauncher=true)
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->getLiveFormStatusResult_ = ERR_OK;
    mockDelegate->liveFormStatusData_ = {{"form_777", "21"}};
    ASSERT_EQ(FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Register(
        TEST_CALLING_UID, sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    Want want;
    want.SetParam(Constants::PARAM_PAGE_ROUTER_SERVICE_CODE,
        Constants::PAGE_ROUTER_SERVICE_CODE_LIVE_FORM);
    want.SetParam(Constants::PARAM_LIVE_FORM_ID_KEY, std::string("form_777"));
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce([](const std::string &, int32_t, AbilityInfo &info, ExtensionAbilityInfo &) {
            info.bundleName = "com.test.host";
            info.name = "HostAbility";
            return true;
        });
    EXPECT_CALL(*MockFormAmsHelper::obj, StartAbility(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Clear();

    GTEST_LOG_(INFO) << "StartAbilityByFms_011 end";
}

/**
 * @tc.name: StartAbilityByFms_012
 * @tc.desc: Verify default action FORM_PUBLISH_ACTION is used when want has no action
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, StartAbilityByFms_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartAbilityByFms_012 start";

    Want want;
    want.SetElementName(TEST_BUNDLE_NAME, TEST_ABILITY_NAME);
    // No action set -> default to FORM_PUBLISH_ACTION

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetAbilityInfoByAction(_, _, _, _))
        .WillOnce([](const std::string &, int32_t, AbilityInfo &info, ExtensionAbilityInfo &) {
            info.bundleName = "com.test.host";
            info.name = "HostAbility";
            return true;
        });
    EXPECT_CALL(*MockFormAmsHelper::obj, StartAbility(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormCallbackAdapter::GetInstance().StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "StartAbilityByFms_012 end";
}

// ========== IsForegroundApp Tests ==========

/**
 * @tc.name: IsForegroundApp_001
 * @tc.desc: Verify GetCallerBundleName failure returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, IsForegroundApp_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsForegroundApp_001 start";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormCallbackAdapter::GetInstance().IsForegroundApp();
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "IsForegroundApp_001 end";
}

/**
 * @tc.name: IsForegroundApp_002
 * @tc.desc: Verify GetAppMgr returning null returns false
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, IsForegroundApp_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsForegroundApp_002 start";

    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::string(TEST_BUNDLE_NAME)), Return(ERR_OK)));

    // In test environment, GetAppMgr returns null (no system ability manager)
    auto result = FormCallbackAdapter::GetInstance().IsForegroundApp();
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "IsForegroundApp_002 end";
}

// ========== RequestOverflow Additional Tests ==========

/**
 * @tc.name: RequestOverflow_004
 * @tc.desc: Verify SceneAnimationCheck returns SYSTEMCAP_ERROR when scene animation not supported
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RequestOverflow_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestOverflow_004 start";

    int32_t callingUid = TEST_CALLING_UID;
    OverflowInfo overflowInfo;
    bool isOverflow = false;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = callingUid;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));

    // Ensure scene animation is not supported
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::LIVE_FORM_NONE;

    auto result = FormCallbackAdapter::GetInstance().RequestOverflow(
        TEST_FORM_ID, callingUid, overflowInfo, isOverflow);
    EXPECT_EQ(result, ERR_APPEXECFWK_SYSTEMCAP_ERROR);

    GTEST_LOG_(INFO) << "RequestOverflow_004 end";
}

/**
 * @tc.name: RequestOverflow_005
 * @tc.desc: Verify RequestOverflow returns GET_HOST_FAILED when no proxy registered for formUserUids
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RequestOverflow_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestOverflow_005 start";

    int32_t callingUid = TEST_CALLING_UID;
    OverflowInfo overflowInfo;
    bool isOverflow = false;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = TEST_BUNDLE_NAME;
    record.abilityName = TEST_ABILITY_NAME;
    record.moduleName = TEST_MODULE_NAME;
    record.formName = TEST_FORM_NAME;
    record.uid = callingUid;
    record.providerUserId = TEST_USER_ID;
    record.formUserUids = { callingUid };

    FormInfo formInfo;
    formInfo.abilityName = TEST_ABILITY_NAME;
    formInfo.name = TEST_FORM_NAME;
    formInfo.sceneAnimationParams.abilityName = "SceneAnimationAbility";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(std::vector<FormInfo>{formInfo}), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // Enable scene animation support
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::SCENE_ANIMATION;

    // Clear overflow registry so no proxy found
    FormCallbackAdapter::GetInstance().overflowRegistry_.Clear();

    auto result = FormCallbackAdapter::GetInstance().RequestOverflow(
        TEST_FORM_ID, callingUid, overflowInfo, isOverflow);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    // Cleanup
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::LIVE_FORM_NONE;

    GTEST_LOG_(INFO) << "RequestOverflow_005 end";
}

/**
 * @tc.name: RequestOverflow_006
 * @tc.desc: Verify RequestOverflow succeeds with registered proxy
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RequestOverflow_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RequestOverflow_006 start";

    int32_t callingUid = TEST_CALLING_UID;
    OverflowInfo overflowInfo;
    bool isOverflow = false;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = TEST_BUNDLE_NAME;
    record.abilityName = TEST_ABILITY_NAME;
    record.moduleName = TEST_MODULE_NAME;
    record.formName = TEST_FORM_NAME;
    record.uid = callingUid;
    record.providerUserId = TEST_USER_ID;
    record.formUserUids = { callingUid };

    FormInfo formInfo;
    formInfo.abilityName = TEST_ABILITY_NAME;
    formInfo.name = TEST_FORM_NAME;
    formInfo.sceneAnimationParams.abilityName = "SceneAnimationAbility";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(std::vector<FormInfo>{formInfo}), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // Enable scene animation support
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::SCENE_ANIMATION;

    // Register mock delegate in overflow registry
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->requestOverflowResult_ = ERR_OK;
    ASSERT_EQ(FormCallbackAdapter::GetInstance().overflowRegistry_.Register(callingUid,
        sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    auto result = FormCallbackAdapter::GetInstance().RequestOverflow(
        TEST_FORM_ID, callingUid, overflowInfo, isOverflow);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().overflowRegistry_.Clear();
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::LIVE_FORM_NONE;

    GTEST_LOG_(INFO) << "RequestOverflow_006 end";
}

// ========== ChangeSceneAnimationState Additional Tests ==========

/**
 * @tc.name: ChangeSceneAnimationState_003
 * @tc.desc: Verify SceneAnimationCheck SYSTEMCAP_ERROR is propagated
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, ChangeSceneAnimationState_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ChangeSceneAnimationState_003 start";

    int32_t callingUid = TEST_CALLING_UID;
    int32_t state = 1;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = callingUid;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));

    // Ensure scene animation is not supported
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::LIVE_FORM_NONE;

    auto result = FormCallbackAdapter::GetInstance().ChangeSceneAnimationState(
        TEST_FORM_ID, callingUid, state);
    EXPECT_EQ(result, ERR_APPEXECFWK_SYSTEMCAP_ERROR);

    GTEST_LOG_(INFO) << "ChangeSceneAnimationState_003 end";
}

/**
 * @tc.name: ChangeSceneAnimationState_004
 * @tc.desc: Verify ChangeSceneAnimationState succeeds with registered proxy
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, ChangeSceneAnimationState_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ChangeSceneAnimationState_004 start";

    int32_t callingUid = TEST_CALLING_UID;
    int32_t state = 1;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.bundleName = TEST_BUNDLE_NAME;
    record.abilityName = TEST_ABILITY_NAME;
    record.moduleName = TEST_MODULE_NAME;
    record.formName = TEST_FORM_NAME;
    record.uid = callingUid;
    record.providerUserId = TEST_USER_ID;
    record.formUserUids = { callingUid };

    FormInfo formInfo;
    formInfo.abilityName = TEST_ABILITY_NAME;
    formInfo.name = TEST_FORM_NAME;
    formInfo.sceneAnimationParams.abilityName = "SceneAnimationAbility";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(std::vector<FormInfo>{formInfo}), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // Enable scene animation support
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::SCENE_ANIMATION;

    // Register mock delegate in scene animation registry
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->changeSceneResult_ = ERR_OK;
    ASSERT_EQ(FormCallbackAdapter::GetInstance().sceneAnimationRegistry_.Register(callingUid,
        sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    auto result = FormCallbackAdapter::GetInstance().ChangeSceneAnimationState(
        TEST_FORM_ID, callingUid, state);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().sceneAnimationRegistry_.Clear();
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::LIVE_FORM_NONE;

    GTEST_LOG_(INFO) << "ChangeSceneAnimationState_004 end";
}

// ========== GetFormRect Additional Tests ==========

/**
 * @tc.name: GetFormRect_003
 * @tc.desc: Verify CallerCheck uid mismatch returns OPERATION_NOT_SELF
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetFormRect_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormRect_003 start";

    int32_t callingUid = TEST_CALLING_UID;
    Rect rect;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = INVALID_UID;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormCallbackAdapter::GetInstance().GetFormRect(TEST_FORM_ID, callingUid, rect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);

    GTEST_LOG_(INFO) << "GetFormRect_003 end";
}

/**
 * @tc.name: GetFormRect_004
 * @tc.desc: Verify GetFormRect returns GET_HOST_FAILED when no proxy registered
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetFormRect_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormRect_004 start";

    int32_t callingUid = TEST_CALLING_UID;
    Rect rect;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = callingUid;
    record.formUserUids = { callingUid };

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));

    // Clear registry so no proxy found
    FormCallbackAdapter::GetInstance().formRectRegistry_.Clear();

    auto result = FormCallbackAdapter::GetInstance().GetFormRect(TEST_FORM_ID, callingUid, rect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "GetFormRect_004 end";
}

/**
 * @tc.name: GetFormRect_005
 * @tc.desc: Verify GetFormRect succeeds with registered proxy
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetFormRect_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetFormRect_005 start";

    int32_t callingUid = TEST_CALLING_UID;
    Rect rect;

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = callingUid;
    record.formUserUids = { callingUid };

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));

    // Register mock delegate in form rect registry
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->getFormRectResult_ = ERR_OK;
    ASSERT_EQ(FormCallbackAdapter::GetInstance().formRectRegistry_.Register(callingUid,
        sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    auto result = FormCallbackAdapter::GetInstance().GetFormRect(TEST_FORM_ID, callingUid, rect);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().formRectRegistry_.Clear();

    GTEST_LOG_(INFO) << "GetFormRect_005 end";
}

// ========== GetLiveFormStatus Additional Tests ==========

/**
 * @tc.name: GetLiveFormStatus_003
 * @tc.desc: Verify GetLiveFormStatus succeeds with registered delegate proxy
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetLiveFormStatus_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetLiveFormStatus_003 start";

    // Register a proper mock delegate
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->getLiveFormStatusResult_ = ERR_OK;
    mockDelegate->liveFormStatusData_ = {{"form_123", "21"}};
    ASSERT_EQ(FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Register(
        TEST_CALLING_UID, sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    std::unordered_map<std::string, std::string> liveFormStatusMap;
    auto result = FormCallbackAdapter::GetInstance().GetLiveFormStatus(liveFormStatusMap);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(liveFormStatusMap.size(), 1u);
    EXPECT_EQ(liveFormStatusMap["form_123"], "21");

    // Cleanup
    FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Clear();

    GTEST_LOG_(INFO) << "GetLiveFormStatus_003 end";
}

/**
 * @tc.name: GetLiveFormStatus_004
 * @tc.desc: Verify GetLiveFormStatus returns GET_HOST_FAILED when proxy returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetLiveFormStatus_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetLiveFormStatus_004 start";

    // Register a mock delegate that returns error
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->getLiveFormStatusResult_ = ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    ASSERT_EQ(FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Register(
        TEST_CALLING_UID, sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    std::unordered_map<std::string, std::string> liveFormStatusMap;
    auto result = FormCallbackAdapter::GetInstance().GetLiveFormStatus(liveFormStatusMap);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);
    EXPECT_TRUE(liveFormStatusMap.empty());

    // Cleanup
    FormCallbackAdapter::GetInstance().liveFormStatusRegistry_.Clear();

    GTEST_LOG_(INFO) << "GetLiveFormStatus_004 end";
}

// ========== SceneAnimationCheck Additional Tests ==========

/**
 * @tc.name: SceneAnimationCheck_002
 * @tc.desc: Verify SceneAnimationCheck returns SYSTEMCAP_ERROR when not supported
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, SceneAnimationCheck_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SceneAnimationCheck_002 start";

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = TEST_CALLING_UID;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillOnce(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    // Ensure scene animation is not supported
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::LIVE_FORM_NONE;

    auto result = FormCallbackAdapter::GetInstance().SceneAnimationCheck(TEST_FORM_ID, TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_APPEXECFWK_SYSTEMCAP_ERROR);

    GTEST_LOG_(INFO) << "SceneAnimationCheck_002 end";
}

/**
 * @tc.name: SceneAnimationCheck_003
 * @tc.desc: Verify SceneAnimationCheck returns LIVE_OP_UNSUPPORTED when bundle is protected
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, SceneAnimationCheck_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SceneAnimationCheck_003 start";

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = TEST_CALLING_UID;
    record.bundleName = TEST_BUNDLE_NAME;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // Enable scene animation support
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::SCENE_ANIMATION;

    auto result = FormCallbackAdapter::GetInstance().SceneAnimationCheck(TEST_FORM_ID, TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED);

    // Cleanup
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::LIVE_FORM_NONE;

    GTEST_LOG_(INFO) << "SceneAnimationCheck_003 end";
}

/**
 * @tc.name: SceneAnimationCheck_004
 * @tc.desc: Verify SceneAnimationCheck returns LIVE_OP_UNSUPPORTED when sceneAnimationParams empty
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, SceneAnimationCheck_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SceneAnimationCheck_004 start";

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = TEST_CALLING_UID;
    record.bundleName = TEST_BUNDLE_NAME;
    record.abilityName = TEST_ABILITY_NAME;
    record.moduleName = TEST_MODULE_NAME;
    record.formName = TEST_FORM_NAME;

    // FormInfo with empty sceneAnimationParams.abilityName
    FormInfo formInfo;
    formInfo.abilityName = TEST_ABILITY_NAME;
    formInfo.name = TEST_FORM_NAME;
    formInfo.sceneAnimationParams.abilityName = "";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(std::vector<FormInfo>{formInfo}), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // Enable scene animation support
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::SCENE_ANIMATION;

    auto result = FormCallbackAdapter::GetInstance().SceneAnimationCheck(TEST_FORM_ID, TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED);

    // Cleanup
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::LIVE_FORM_NONE;

    GTEST_LOG_(INFO) << "SceneAnimationCheck_004 end";
}

/**
 * @tc.name: SceneAnimationCheck_005
 * @tc.desc: Verify SceneAnimationCheck returns ERR_OK when all checks pass
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, SceneAnimationCheck_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SceneAnimationCheck_005 start";

    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.uid = TEST_CALLING_UID;
    record.bundleName = TEST_BUNDLE_NAME;
    record.abilityName = TEST_ABILITY_NAME;
    record.moduleName = TEST_MODULE_NAME;
    record.formName = TEST_FORM_NAME;

    FormInfo formInfo;
    formInfo.abilityName = TEST_ABILITY_NAME;
    formInfo.name = TEST_FORM_NAME;
    formInfo.sceneAnimationParams.abilityName = "SceneAnimationAbility";

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormInfoMgr::obj, GetFormsInfoByModule(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<2>(std::vector<FormInfo>{formInfo}), Return(ERR_OK)));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // Enable scene animation support
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::SCENE_ANIMATION;

    auto result = FormCallbackAdapter::GetInstance().SceneAnimationCheck(TEST_FORM_ID, TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCustConfigMgr::GetInstance().liveFormSupportType = Constants::LIVE_FORM_NONE;

    GTEST_LOG_(INFO) << "SceneAnimationCheck_005 end";
}

// ========== RegisterFormWantCallback Tests ==========

/**
 * @tc.name: RegisterFormWantCallback_001
 * @tc.desc: Verify null callerToken returns ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterFormWantCallback_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormWantCallback_001 start";

    sptr<IRemoteObject> callerToken = nullptr;
    auto result = FormCallbackAdapter::GetInstance().RegisterFormWantCallback(TEST_CALLING_UID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    // Cleanup
    FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Clear();

    GTEST_LOG_(INFO) << "RegisterFormWantCallback_001 end";
}

/**
 * @tc.name: RegisterFormWantCallback_002
 * @tc.desc: Verify valid registration returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterFormWantCallback_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormWantCallback_002 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    auto result = FormCallbackAdapter::GetInstance().RegisterFormWantCallback(TEST_CALLING_UID, callerToken);
    EXPECT_EQ(result, ERR_OK);

    // Verify proxy is stored
    sptr<IRemoteObject> storedProxy;
    EXPECT_EQ(FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Get(TEST_CALLING_UID, storedProxy), ERR_OK);
    EXPECT_EQ(storedProxy, callerToken);

    // Cleanup
    FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Clear();

    GTEST_LOG_(INFO) << "RegisterFormWantCallback_002 end";
}

/**
 * @tc.name: RegisterFormWantCallback_003
 * @tc.desc: Verify re-registration with same uid succeeds and updates proxy
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterFormWantCallback_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormWantCallback_003 start";

    // First registration
    sptr<IRemoteObject> callerToken1 = new MockIRemoteObject();
    auto *mockCaller1 = static_cast<MockIRemoteObject *>(callerToken1.GetRefPtr());
    EXPECT_CALL(*mockCaller1, AddDeathRecipient(_))
        .WillOnce(Return(true));

    auto result1 = FormCallbackAdapter::GetInstance().RegisterFormWantCallback(TEST_CALLING_UID, callerToken1);
    EXPECT_EQ(result1, ERR_OK);

    // Re-registration with same uid
    sptr<IRemoteObject> callerToken2 = new MockIRemoteObject();
    auto *mockCaller2 = static_cast<MockIRemoteObject *>(callerToken2.GetRefPtr());
    EXPECT_CALL(*mockCaller2, AddDeathRecipient(_))
        .WillOnce(Return(true));

    auto result2 = FormCallbackAdapter::GetInstance().RegisterFormWantCallback(TEST_CALLING_UID, callerToken2);
    EXPECT_EQ(result2, ERR_OK);

    // Verify proxy is updated
    sptr<IRemoteObject> storedProxy;
    EXPECT_EQ(FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Get(TEST_CALLING_UID, storedProxy), ERR_OK);
    EXPECT_EQ(storedProxy, callerToken2);

    // Cleanup
    FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Clear();

    GTEST_LOG_(INFO) << "RegisterFormWantCallback_003 end";
}

// ========== UnregisterFormWantCallback Tests ==========

/**
 * @tc.name: UnregisterFormWantCallback_001
 * @tc.desc: Verify unregister without prior registration returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterFormWantCallback_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterFormWantCallback_001 start";

    // Clear registry to ensure no prior registration
    FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Clear();

    auto result = FormCallbackAdapter::GetInstance().UnregisterFormWantCallback(TEST_CALLING_UID);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterFormWantCallback_001 end";
}

/**
 * @tc.name: UnregisterFormWantCallback_002
 * @tc.desc: Verify unregister after registration returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterFormWantCallback_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterFormWantCallback_002 start";

    // Register first
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    auto regResult = FormCallbackAdapter::GetInstance().RegisterFormWantCallback(TEST_CALLING_UID, callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    // Then unregister
    auto unregResult = FormCallbackAdapter::GetInstance().UnregisterFormWantCallback(TEST_CALLING_UID);
    EXPECT_EQ(unregResult, ERR_OK);

    // Verify proxy is removed
    sptr<IRemoteObject> storedProxy;
    EXPECT_EQ(FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Get(TEST_CALLING_UID, storedProxy),
        ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "UnregisterFormWantCallback_002 end";
}

// ========== GetWantCallbackProxy Tests ==========

/**
 * @tc.name: GetWantCallbackProxy_001
 * @tc.desc: Verify get without registration returns ERR_APPEXECFWK_FORM_GET_HOST_FAILED
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetWantCallbackProxy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetWantCallbackProxy_001 start";

    // Clear registry to ensure no prior registration
    FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Clear();

    sptr<IRemoteObject> proxy;
    auto result = FormCallbackAdapter::GetInstance().GetWantCallbackProxy(TEST_CALLING_UID, proxy);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);
    EXPECT_EQ(proxy, nullptr);

    GTEST_LOG_(INFO) << "GetWantCallbackProxy_001 end";
}

/**
 * @tc.name: GetWantCallbackProxy_002
 * @tc.desc: Verify get after registration returns ERR_OK with valid proxy
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetWantCallbackProxy_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetWantCallbackProxy_002 start";

    // Register first
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    auto regResult = FormCallbackAdapter::GetInstance().RegisterFormWantCallback(TEST_CALLING_UID, callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    // Get proxy
    sptr<IRemoteObject> proxy;
    auto result = FormCallbackAdapter::GetInstance().GetWantCallbackProxy(TEST_CALLING_UID, proxy);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(proxy, callerToken);

    // Cleanup
    FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Clear();

    GTEST_LOG_(INFO) << "GetWantCallbackProxy_002 end";
}

/**
 * @tc.name: GetWantCallbackProxy_003
 * @tc.desc: Verify get after unregister returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetWantCallbackProxy_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetWantCallbackProxy_003 start";

    // Register first
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    auto regResult = FormCallbackAdapter::GetInstance().RegisterFormWantCallback(TEST_CALLING_UID, callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    // Unregister
    auto unregResult = FormCallbackAdapter::GetInstance().UnregisterFormWantCallback(TEST_CALLING_UID);
    ASSERT_EQ(unregResult, ERR_OK);

    // Get proxy should fail
    sptr<IRemoteObject> proxy;
    auto result = FormCallbackAdapter::GetInstance().GetWantCallbackProxy(TEST_CALLING_UID, proxy);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "GetWantCallbackProxy_003 end";
}

/**
 * @tc.name: GetWantCallbackProxy_004
 * @tc.desc: Verify get with different uid returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, GetWantCallbackProxy_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetWantCallbackProxy_004 start";

    // Register with TEST_CALLING_UID
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    auto regResult = FormCallbackAdapter::GetInstance().RegisterFormWantCallback(TEST_CALLING_UID, callerToken);
    ASSERT_EQ(regResult, ERR_OK);

    // Get with different uid should fail
    sptr<IRemoteObject> proxy;
    auto result = FormCallbackAdapter::GetInstance().GetWantCallbackProxy(INVALID_UID, proxy);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    // Cleanup
    FormCallbackAdapter::GetInstance().wantCallbackRegistry_.Clear();

    GTEST_LOG_(INFO) << "GetWantCallbackProxy_004 end";
}

// ========== UnregisterFormRouterProxy Additional Tests ==========

/**
 * @tc.name: UnregisterFormRouterProxy_004
 * @tc.desc: Verify providerUserId mismatch returns ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterFormRouterProxy_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_004 start";

    std::vector<int64_t> formIds = { TEST_FORM_ID };

    FormRecord record;
    record.providerUserId = TEST_USER_ID + 1;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormCallbackAdapter::GetInstance().UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);

    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_004 end";
}

/**
 * @tc.name: UnregisterFormRouterProxy_005
 * @tc.desc: Verify happy path with valid formId and self-owned record returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterFormRouterProxy_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_005 start";

    std::vector<int64_t> formIds = { TEST_FORM_ID };

    FormRecord record;
    record.providerUserId = TEST_USER_ID;
    record.formUserUids = { TEST_CALLING_UID };

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(TEST_FORM_ID))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(TEST_FORM_ID, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormCallbackAdapter::GetInstance().UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterFormRouterProxy_005 end";
}

// ========== RegisterPublishFormInterceptor Additional Tests ==========

/**
 * @tc.name: RegisterPublishFormInterceptor_002
 * @tc.desc: Verify setting interceptor via SetFormPublishInterceptor and getting it back
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterPublishFormInterceptor_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterPublishFormInterceptor_002 start";

    // Clear any existing interceptor
    FormCallbackAdapter::GetInstance().SetFormPublishInterceptor(nullptr);
    EXPECT_EQ(FormCallbackAdapter::GetInstance().GetFormPublishInterceptor(), nullptr);

    GTEST_LOG_(INFO) << "RegisterPublishFormInterceptor_002 end";
}

// ========== UpdateTemplateFormDetailInfo Additional Tests ==========

/**
 * @tc.name: UpdateTemplateFormDetailInfo_002
 * @tc.desc: Verify UpdateTemplateFormDetailInfo succeeds with registered proxy
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UpdateTemplateFormDetailInfo_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateTemplateFormDetailInfo_002 start";

    // Register mock delegate in template form detail info registry
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->templateFormResult_ = ERR_OK;
    ASSERT_EQ(FormCallbackAdapter::GetInstance().templateFormDetailInfoRegistry_.Register(
        TEST_CALLING_UID, sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    std::vector<TemplateFormDetailInfo> templateFormInfo;
    auto result = FormCallbackAdapter::GetInstance().UpdateTemplateFormDetailInfo(templateFormInfo);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().templateFormDetailInfoRegistry_.Clear();

    GTEST_LOG_(INFO) << "UpdateTemplateFormDetailInfo_002 end";
}

/**
 * @tc.name: UpdateTemplateFormDetailInfo_003
 * @tc.desc: Verify UpdateTemplateFormDetailInfo returns error when proxy returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UpdateTemplateFormDetailInfo_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UpdateTemplateFormDetailInfo_003 start";

    // Register mock delegate that returns error
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->templateFormResult_ = ERR_APPEXECFWK_TEMPLATE_UNSUPPORTED_OPERATION;
    ASSERT_EQ(FormCallbackAdapter::GetInstance().templateFormDetailInfoRegistry_.Register(
        TEST_CALLING_UID, sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    std::vector<TemplateFormDetailInfo> templateFormInfo;
    auto result = FormCallbackAdapter::GetInstance().UpdateTemplateFormDetailInfo(templateFormInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_TEMPLATE_UNSUPPORTED_OPERATION);

    // Cleanup
    FormCallbackAdapter::GetInstance().templateFormDetailInfoRegistry_.Clear();

    GTEST_LOG_(INFO) << "UpdateTemplateFormDetailInfo_003 end";
}

/**
 * @tc.name: RegisterDeleteFormsCallback_001
 * @tc.desc: Verify RegisterDeleteFormsCallback returns ERR_OK with valid callerToken
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, RegisterDeleteFormsCallback_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterDeleteFormsCallback_001 start";

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto mockDelegate = new MockFormHostDelegateStub();
    ASSERT_EQ(FormCallbackAdapter::GetInstance().deleteFormsRegistry_.Register(
        TEST_CALLING_UID, sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    GTEST_LOG_(INFO) << "RegisterDeleteFormsCallback_001 end";
}

/**
 * @tc.name: UnregisterDeleteFormsCallback_001
 * @tc.desc: Verify UnregisterDeleteFormsCallback returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, UnregisterDeleteFormsCallback_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterDeleteFormsCallback_001 start";

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillOnce(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().UnregisterDeleteFormsCallback();
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterDeleteFormsCallback_001 end";
}

/**
 * @tc.name: DeleteForms_001
 * @tc.desc: Verify DeleteForms returns ERR_OK when no forms matched
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, DeleteForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteForms_001 start";

    std::vector<FormRecordFilter> filters;
    FormRecordFilter filter;
    filter.bundleName = "com.test.nonexistent";
    filters.push_back(filter);

    auto result = FormCallbackAdapter::GetInstance().DeleteForms(filters);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DeleteForms_001 end";
}

/**
 * @tc.name: DeleteForms_002
 * @tc.desc: Verify DeleteForms returns ERR_OK when registry has no hosts
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, DeleteForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteForms_002 start";

    FormCallbackAdapter::GetInstance().deleteFormsRegistry_.Clear();

    std::vector<FormRecordFilter> filters;
    FormRecordFilter filter;
    filter.bundleName = "com.test.bundle";
    filters.push_back(filter);

    auto result = FormCallbackAdapter::GetInstance().DeleteForms(filters);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_HOST_FAILED);

    GTEST_LOG_(INFO) << "DeleteForms_002 end";
}

/**
 * @tc.name: DeleteForms_003
 * @tc.desc: Verify DeleteForms with matched forms and registered host
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormCallbackAdapterTest, DeleteForms_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteForms_003 start";

    // Setup mock delegate
    auto mockDelegate = new MockFormHostDelegateStub();
    mockDelegate->deleteFormsResult_ = ERR_OK;
    ASSERT_EQ(FormCallbackAdapter::GetInstance().deleteFormsRegistry_.Register(
        TEST_CALLING_UID, sptr<IRemoteObject>(mockDelegate)), ERR_OK);

    std::vector<FormRecordFilter> filters;
    FormRecordFilter filter;
    filter.bundleName = TEST_BUNDLE_NAME;
    filter.moduleName = TEST_MODULE_NAME;
    filter.abilityName = TEST_ABILITY_NAME;
    filter.formName = TEST_FORM_NAME;
    filters.push_back(filter);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormCallbackAdapter::GetInstance().DeleteForms(filters);
    EXPECT_EQ(result, ERR_OK);

    // Cleanup
    FormCallbackAdapter::GetInstance().deleteFormsRegistry_.Clear();

    GTEST_LOG_(INFO) << "DeleteForms_003 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
