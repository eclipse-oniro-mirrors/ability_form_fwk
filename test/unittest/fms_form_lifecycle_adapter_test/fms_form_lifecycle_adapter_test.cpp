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
#include "form_mgr/form_lifecycle_adapter.h"
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
#include "configuration.h"

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
constexpr int64_t INVALID_NEGATIVE_FORM_ID = -1;
constexpr int64_t INVALID_ZERO_FORM_ID = 0;
constexpr int32_t TEST_DIMENSION_ID = 2;
constexpr int32_t SYSTEM_UID = 1000;
}

class FmsFormLifecycleAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormLifecycleAdapterTest::SetUpTestCase()
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

void FmsFormLifecycleAdapterTest::TearDownTestCase()
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

void FmsFormLifecycleAdapterTest::SetUp()
{
}

void FmsFormLifecycleAdapterTest::TearDown()
{
}

// ========== AddForm Tests ==========

/**
 * @tc.name: AddForm_001
 * @tc.desc: Verify AddForm with negative formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, AddForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddForm_001 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormJsInfo formJsInfo;

    auto result = FormLifecycleAdapter::GetInstance().AddForm(
        INVALID_NEGATIVE_FORM_ID, want, callerToken, formJsInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AddForm_001 end";
}

/**
 * @tc.name: AddForm_002
 * @tc.desc: Verify AddForm with null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, AddForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddForm_002 start";

    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formJsInfo;

    auto result = FormLifecycleAdapter::GetInstance().AddForm(
        TEST_FORM_ID, want, callerToken, formJsInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AddForm_002 end";
}

/**
 * @tc.name: AddForm_003
 * @tc.desc: Verify AddForm with formId 0 and null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, AddForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddForm_003 start";

    Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    FormJsInfo formJsInfo;

    auto result = FormLifecycleAdapter::GetInstance().AddForm(
        INVALID_ZERO_FORM_ID, want, callerToken, formJsInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "AddForm_003 end";
}

// ========== DeleteForm Tests ==========

/**
 * @tc.name: DeleteForm_001
 * @tc.desc: Verify DeleteForm with formId <= 0 returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, DeleteForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteForm_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormLifecycleAdapter::GetInstance().DeleteForm(
        INVALID_ZERO_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "DeleteForm_001 end";
}

/**
 * @tc.name: DeleteForm_002
 * @tc.desc: Verify DeleteForm with negative formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, DeleteForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteForm_002 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormLifecycleAdapter::GetInstance().DeleteForm(
        INVALID_NEGATIVE_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "DeleteForm_002 end";
}

/**
 * @tc.name: DeleteForm_003
 * @tc.desc: Verify DeleteForm with null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, DeleteForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteForm_003 start";

    sptr<IRemoteObject> callerToken = nullptr;

    auto result = FormLifecycleAdapter::GetInstance().DeleteForm(
        TEST_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "DeleteForm_003 end";
}

// ========== ReleaseForm Tests ==========

/**
 * @tc.name: ReleaseForm_001
 * @tc.desc: Verify ReleaseForm with formId <= 0 returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ReleaseForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseForm_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormLifecycleAdapter::GetInstance().ReleaseForm(
        INVALID_ZERO_FORM_ID, callerToken, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ReleaseForm_001 end";
}

/**
 * @tc.name: ReleaseForm_002
 * @tc.desc: Verify ReleaseForm with null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ReleaseForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseForm_002 start";

    sptr<IRemoteObject> callerToken = nullptr;

    auto result = FormLifecycleAdapter::GetInstance().ReleaseForm(
        TEST_FORM_ID, callerToken, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ReleaseForm_002 end";
}

/**
 * @tc.name: ReleaseForm_003
 * @tc.desc: Verify ReleaseForm with negative formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ReleaseForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseForm_003 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormLifecycleAdapter::GetInstance().ReleaseForm(
        INVALID_NEGATIVE_FORM_ID, callerToken, false);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ReleaseForm_003 end";
}

// ========== CastTempForm Tests ==========

/**
 * @tc.name: CastTempForm_001
 * @tc.desc: Verify CastTempForm with formId <= 0 returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CastTempForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CastTempForm_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormLifecycleAdapter::GetInstance().CastTempForm(
        INVALID_ZERO_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CastTempForm_001 end";
}

/**
 * @tc.name: CastTempForm_002
 * @tc.desc: Verify CastTempForm with null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CastTempForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CastTempForm_002 start";

    sptr<IRemoteObject> callerToken = nullptr;

    auto result = FormLifecycleAdapter::GetInstance().CastTempForm(
        TEST_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CastTempForm_002 end";
}

/**
 * @tc.name: CastTempForm_003
 * @tc.desc: Verify CastTempForm with negative formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CastTempForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CastTempForm_003 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    auto result = FormLifecycleAdapter::GetInstance().CastTempForm(
        INVALID_NEGATIVE_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CastTempForm_003 end";
}

// ========== StopRenderingForm Tests ==========

/**
 * @tc.name: StopRenderingForm_001
 * @tc.desc: Verify StopRenderingForm with formId <= 0 returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, StopRenderingForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StopRenderingForm_001 start";

    std::string compId = "comp_123";

    auto result = FormLifecycleAdapter::GetInstance().StopRenderingForm(
        INVALID_ZERO_FORM_ID, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "StopRenderingForm_001 end";
}

/**
 * @tc.name: StopRenderingForm_002
 * @tc.desc: Verify StopRenderingForm with empty compId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, StopRenderingForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StopRenderingForm_002 start";

    std::string compId;

    auto result = FormLifecycleAdapter::GetInstance().StopRenderingForm(
        TEST_FORM_ID, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "StopRenderingForm_002 end";
}

/**
 * @tc.name: StopRenderingForm_003
 * @tc.desc: Verify StopRenderingForm with negative formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, StopRenderingForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StopRenderingForm_003 start";

    std::string compId = "comp_123";

    auto result = FormLifecycleAdapter::GetInstance().StopRenderingForm(
        INVALID_NEGATIVE_FORM_ID, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "StopRenderingForm_003 end";
}

// ========== ReleaseRenderer Tests ==========

/**
 * @tc.name: ReleaseRenderer_001
 * @tc.desc: Verify ReleaseRenderer with formId <= 0 returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ReleaseRenderer_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_001 start";

    std::string compId = "comp_123";

    auto result = FormLifecycleAdapter::GetInstance().ReleaseRenderer(
        INVALID_ZERO_FORM_ID, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ReleaseRenderer_001 end";
}

/**
 * @tc.name: ReleaseRenderer_002
 * @tc.desc: Verify ReleaseRenderer with empty compId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ReleaseRenderer_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_002 start";

    std::string compId;

    auto result = FormLifecycleAdapter::GetInstance().ReleaseRenderer(
        TEST_FORM_ID, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ReleaseRenderer_002 end";
}

// ========== DeleteInvalidForms Tests ==========

/**
 * @tc.name: DeleteInvalidForms_001
 * @tc.desc: Verify DeleteInvalidForms with null callerToken returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, DeleteInvalidForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteInvalidForms_001 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t numFormsDeleted = 0;

    auto result = FormLifecycleAdapter::GetInstance().DeleteInvalidForms(
        formIds, callerToken, numFormsDeleted);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "DeleteInvalidForms_001 end";
}

// ========== CreateForm Tests ==========

/**
 * @tc.name: CreateForm_001
 * @tc.desc: Verify CreateForm with non-theme form returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CreateForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateForm_001 start";

    Want want;
    // PARAM_THEME_KEY defaults to false, so this is a non-theme form request
    RunningFormInfo runningFormInfo;

    auto result = FormLifecycleAdapter::GetInstance().CreateForm(want, runningFormInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CreateForm_001 end";
}

// ========== ProtectLockForms Tests ==========

/**
 * @tc.name: ProtectLockForms_001
 * @tc.desc: Verify ProtectLockForms returns ERR_OK when lock service initialized and status unchanged
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ProtectLockForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProtectLockForms_001 start";

    std::string bundleName = "com.test.bundle";
    bool protect = true;

    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsLockServiceInitialized())
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true));

    auto result = FormLifecycleAdapter::GetInstance().ProtectLockForms(bundleName, TEST_USER_ID, protect);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProtectLockForms_001 end";
}

/**
 * @tc.name: ProtectLockForms_002
 * @tc.desc: Verify ProtectLockForms returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID when no form records
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ProtectLockForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProtectLockForms_002 start";

    std::string bundleName = "com.test.bundle";
    bool protect = false;

    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsLockServiceInitialized())
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true));

    auto result = FormLifecycleAdapter::GetInstance().ProtectLockForms(bundleName, TEST_USER_ID, protect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "ProtectLockForms_002 end";
}

// ========== SwitchLockForms Tests ==========

/**
 * @tc.name: SwitchLockForms_001
 * @tc.desc: Verify SwitchLockForms returns ERR_OK when lock status unchanged
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, SwitchLockForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SwitchLockForms_001 start";

    std::string bundleName = "com.test.bundle";
    bool lock = true;

    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleLock(_, _, _))
        .WillOnce(Return(true));

    auto result = FormLifecycleAdapter::GetInstance().SwitchLockForms(bundleName, TEST_USER_ID, lock);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "SwitchLockForms_001 end";
}

/**
 * @tc.name: SwitchLockForms_002
 * @tc.desc: Verify SwitchLockForms returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID when no form records
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, SwitchLockForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SwitchLockForms_002 start";

    std::string bundleName = "com.test.bundle";
    bool lock = false;

    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleLock(_, _, _))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, SetBundleLockStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().SwitchLockForms(bundleName, TEST_USER_ID, lock);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "SwitchLockForms_002 end";
}

// ========== RecycleForms Tests ==========

/**
 * @tc.name: RecycleForms_001
 * @tc.desc: Verify RecycleForms with empty formIds returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecycleForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForms_001 start";

    std::vector<int64_t> formIds;
    Want want;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecycleForms_001 end";
}

/**
 * @tc.name: RecycleForms_002
 * @tc.desc: Verify RecycleForms with negative formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecycleForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForms_002 start";

    std::vector<int64_t> formIds = {INVALID_NEGATIVE_FORM_ID};
    Want want;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecycleForms_002 end";
}

// ========== RecoverForms Tests ==========

/**
 * @tc.name: RecoverForms_001
 * @tc.desc: Verify RecoverForms with empty formIds returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecoverForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForms_001 start";

    std::vector<int64_t> formIds;
    Want want;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecoverForms_001 end";
}

/**
 * @tc.name: RecoverForms_002
 * @tc.desc: Verify RecoverForms with negative formId returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecoverForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForms_002 start";

    std::vector<int64_t> formIds = {INVALID_NEGATIVE_FORM_ID};
    Want want;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecoverForms_002 end";
}

// ========== BatchNotifyFormsConfigurationUpdate Tests ==========

/**
 * @tc.name: BatchNotifyFormsConfigurationUpdate_001
 * @tc.desc: Verify BatchNotifyFormsConfigurationUpdate returns ERR_OK with no visible/invisible records
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, BatchNotifyFormsConfigurationUpdate_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BatchNotifyFormsConfigurationUpdate_001 start";

    AppExecFwk::Configuration configuration;

    auto result = FormLifecycleAdapter::GetInstance().BatchNotifyFormsConfigurationUpdate(configuration);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "BatchNotifyFormsConfigurationUpdate_001 end";
}

// ========== HandleFormRemoveObserver Tests ==========

/**
 * @tc.name: HandleFormRemoveObserver_001
 * @tc.desc: Verify HandleFormRemoveObserver returns early when GetCallerBundleName fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, HandleFormRemoveObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFormRemoveObserver_001 start";

    RunningFormInfo runningFormInfo;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    FormLifecycleAdapter::GetInstance().HandleFormRemoveObserver(runningFormInfo);
    // FormDataMgr::HandleFormRemoveObserver should NOT be called when GetCallerBundleName fails
    EXPECT_CALL(*MockFormDataMgr::obj, HandleFormRemoveObserver(_, _))
        .Times(0);
    // Re-verify: calling again with the same mock setup confirms early return
    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));
    FormLifecycleAdapter::GetInstance().HandleFormRemoveObserver(runningFormInfo);

    GTEST_LOG_(INFO) << "HandleFormRemoveObserver_001 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
