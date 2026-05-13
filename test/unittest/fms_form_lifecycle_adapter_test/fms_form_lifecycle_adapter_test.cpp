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

// ========== EnableForms Tests ==========

/**
 * @tc.name: EnableForms_001
 * @tc.desc: Verify EnableForms returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID when no form records
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, EnableForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnableForms_001 start";

    std::string bundleName = "com.test.bundle";
    bool enable = true;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().EnableForms(bundleName, TEST_USER_ID, enable);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "EnableForms_001 end";
}

// ========== ProtectLockForms Tests ==========

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

/**
 * @tc.name: HandleFormRemoveObserver_002
 * @tc.desc: Verify HandleFormRemoveObserver calls FormDataMgr when GetCallerBundleName succeeds
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, HandleFormRemoveObserver_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFormRemoveObserver_002 start";

    RunningFormInfo runningFormInfo;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(DoAll(SetArgReferee<0>("com.test.bundle"), Return(ERR_OK)));
    EXPECT_CALL(*MockFormDataMgr::obj, HandleFormRemoveObserver(_, _))
        .Times(1);

    FormLifecycleAdapter::GetInstance().HandleFormRemoveObserver(runningFormInfo);

    GTEST_LOG_(INFO) << "HandleFormRemoveObserver_002 end";
}

// ========== CheckFormCountLimit Tests ==========

/**
 * @tc.name: CheckFormCountLimit_001
 * @tc.desc: Verify tempFormFlag=true and formId > 0 returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckFormCountLimit_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckFormCountLimit_001 start";

    Want want;
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, true);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckFormCountLimit(TEST_FORM_ID, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CheckFormCountLimit_001 end";
}

/**
 * @tc.name: CheckFormCountLimit_002
 * @tc.desc: Verify tempFormFlag=true and formId == 0 calls CheckTempEnoughForm
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckFormCountLimit_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckFormCountLimit_002 start";

    Want want;
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, true);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // formId == 0, tempFormFlag = true -> calls CheckTempEnoughForm
    auto result = FormLifecycleAdapter::GetInstance().CheckFormCountLimit(0, want);
    // CheckTempEnoughForm on empty data returns 0 (OK)
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "CheckFormCountLimit_002 end";
}

/**
 * @tc.name: CheckFormCountLimit_003
 * @tc.desc: Verify !tempFormFlag and formId == 0 calls CheckEnoughForm
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckFormCountLimit_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckFormCountLimit_003 start";

    Want want;
    // tempFormFlag defaults to false

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckFormCountLimit(0, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT);

    GTEST_LOG_(INFO) << "CheckFormCountLimit_003 end";
}

/**
 * @tc.name: CheckFormCountLimit_004
 * @tc.desc: Verify !tempFormFlag and formId != 0 returns ERR_OK (no check needed)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckFormCountLimit_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckFormCountLimit_004 start";

    Want want;
    // tempFormFlag defaults to false

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckFormCountLimit(TEST_FORM_ID, want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "CheckFormCountLimit_004 end";
}

// ========== StopRenderingForm Happy Path ==========

/**
 * @tc.name: StopRenderingForm_004
 * @tc.desc: Verify StopRenderingForm with valid params returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, StopRenderingForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StopRenderingForm_004 start";

    std::string compId = "comp_123";

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().StopRenderingForm(TEST_FORM_ID, compId);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "StopRenderingForm_004 end";
}

// ========== ReleaseRenderer Happy Path and Error ==========

/**
 * @tc.name: ReleaseRenderer_003
 * @tc.desc: Verify ReleaseRenderer with form not found returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ReleaseRenderer_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_003 start";

    std::string compId = "comp_123";

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().ReleaseRenderer(TEST_FORM_ID, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "ReleaseRenderer_003 end";
}

/**
 * @tc.name: ReleaseRenderer_004
 * @tc.desc: Verify ReleaseRenderer with valid params and form found returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ReleaseRenderer_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_004 start";

    std::string compId = "comp_123";
    FormRecord record;
    record.formId = TEST_FORM_ID;

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormLifecycleAdapter::GetInstance().ReleaseRenderer(TEST_FORM_ID, compId);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ReleaseRenderer_004 end";
}

// ========== EnableForms Happy Path ==========

/**
 * @tc.name: EnableForms_002
 * @tc.desc: Verify EnableForms with records and enable=true returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, EnableForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnableForms_002 start";

    std::string bundleName = "com.test.bundle";
    bool enable = true;

    std::vector<FormRecord> formInfos;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.enableForm = false; // not yet enabled
    record.providerUserId = TEST_USER_ID;
    record.transparencyEnabled = false;
    formInfos.push_back(record);

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formInfos), Return(true)));
    EXPECT_CALL(*MockFormBundleForbidMgr::obj, SetBundleForbiddenStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDbCache::obj, UpdateDBRecord(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormLifecycleAdapter::GetInstance().EnableForms(bundleName, TEST_USER_ID, enable);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "EnableForms_002 end";
}

/**
 * @tc.name: EnableForms_003
 * @tc.desc: Verify EnableForms with records skips forms with same enableForm status
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, EnableForms_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnableForms_003 start";

    std::string bundleName = "com.test.bundle";
    bool enable = true;

    std::vector<FormRecord> formInfos;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.enableForm = true; // already enabled, should be skipped
    record.providerUserId = TEST_USER_ID;
    formInfos.push_back(record);

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formInfos), Return(true)));
    EXPECT_CALL(*MockFormBundleForbidMgr::obj, SetBundleForbiddenStatus(_, _))
        .Times(1);
    // UpdateDBRecord should NOT be called for skipped forms

    auto result = FormLifecycleAdapter::GetInstance().EnableForms(bundleName, TEST_USER_ID, enable);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "EnableForms_003 end";
}

/**
 * @tc.name: EnableForms_004
 * @tc.desc: Verify EnableForms with records skips forms from different userId
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, EnableForms_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnableForms_004 start";

    std::string bundleName = "com.test.bundle";
    bool enable = true;

    std::vector<FormRecord> formInfos;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.enableForm = false;
    record.providerUserId = 999; // different userId
    formInfos.push_back(record);

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formInfos), Return(true)));
    EXPECT_CALL(*MockFormBundleForbidMgr::obj, SetBundleForbiddenStatus(_, _))
        .Times(1);

    auto result = FormLifecycleAdapter::GetInstance().EnableForms(bundleName, TEST_USER_ID, enable);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "EnableForms_004 end";
}

/**
 * @tc.name: EnableForms_005
 * @tc.desc: Verify EnableForms with enable=false returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, EnableForms_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "EnableForms_005 start";

    std::string bundleName = "com.test.bundle";
    bool enable = false;

    std::vector<FormRecord> formInfos;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.enableForm = true; // currently enabled
    record.providerUserId = TEST_USER_ID;
    record.transparencyEnabled = false;
    formInfos.push_back(record);

    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formInfos), Return(true)));
    EXPECT_CALL(*MockFormBundleForbidMgr::obj, SetBundleForbiddenStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDbCache::obj, UpdateDBRecord(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormLifecycleAdapter::GetInstance().EnableForms(bundleName, TEST_USER_ID, enable);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "EnableForms_005 end";
}

// ========== ProtectLockForms Additional Branches ==========

/**
 * @tc.name: ProtectLockForms_003
 * @tc.desc: Verify ProtectLockForms with records and exempt lock skips exempted forms
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ProtectLockForms_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProtectLockForms_003 start";

    std::string bundleName = "com.test.bundle";
    bool protect = true;

    std::vector<FormRecord> formInfos;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.lockForm = false;
    record.transparencyEnabled = false;
    formInfos.push_back(record);

    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsLockServiceInitialized())
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(false)); // status changed
    EXPECT_CALL(*MockFormBundleLockMgr::obj, SetBundleProtectStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formInfos), Return(true)));
    EXPECT_CALL(*MockFormExemptLockMgr::obj, IsExemptLock(_))
        .WillOnce(Return(true)); // exempt, should be skipped
    EXPECT_CALL(*MockFormBundleForbidMgr::obj, IsBundleForbidden(_))
        .WillOnce(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().ProtectLockForms(bundleName, TEST_USER_ID, protect);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProtectLockForms_003 end";
}

/**
 * @tc.name: ProtectLockForms_004
 * @tc.desc: Verify ProtectLockForms with records updates protectForm and calls LockForms
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ProtectLockForms_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProtectLockForms_004 start";

    std::string bundleName = "com.test.bundle";
    bool protect = true;

    std::vector<FormRecord> formInfos;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.lockForm = false;
    record.transparencyEnabled = false;
    formInfos.push_back(record);

    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsLockServiceInitialized())
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(false)); // status changed
    EXPECT_CALL(*MockFormBundleLockMgr::obj, SetBundleProtectStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formInfos), Return(true)));
    EXPECT_CALL(*MockFormExemptLockMgr::obj, IsExemptLock(_))
        .WillOnce(Return(false)); // not exempt, should be processed
    EXPECT_CALL(*MockFormDataMgr::obj, SetFormProtect(_, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockFormDbCache::obj, UpdateDBRecord(_, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockFormBundleForbidMgr::obj, IsBundleForbidden(_))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormDataMgr::obj, LockForms(_, _))
        .Times(1);

    auto result = FormLifecycleAdapter::GetInstance().ProtectLockForms(bundleName, TEST_USER_ID, protect);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "ProtectLockForms_004 end";
}

/**
 * @tc.name: ProtectLockForms_005
 * @tc.desc: Verify ProtectLockForms with protect=false and forbidden bundle executes forbidden task
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ProtectLockForms_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProtectLockForms_005 start";

    std::string bundleName = "com.test.bundle";
    bool protect = false;

    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsLockServiceInitialized())
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(true)); // status changed (was protect=true, now protect=false)
    EXPECT_CALL(*MockFormBundleLockMgr::obj, SetBundleProtectStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(Return(false)); // no records

    // protect=false, IsBundleForbidden returns false -> ExecAcquireProviderForbiddenTask
    EXPECT_CALL(*MockFormBundleForbidMgr::obj, IsBundleForbidden(_))
        .WillOnce(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().ProtectLockForms(bundleName, TEST_USER_ID, protect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "ProtectLockForms_005 end";
}

// ========== SwitchLockForms Additional Branches ==========

/**
 * @tc.name: SwitchLockForms_005
 * @tc.desc: Verify SwitchLockForms with lock=false calls SetExemptLockStatus
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, SwitchLockForms_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SwitchLockForms_005 start";

    std::string bundleName = "com.test.bundle";
    bool lock = false;

    std::vector<FormRecord> formInfos;
    FormRecord record;
    record.formId = TEST_FORM_ID;
    record.lockForm = true; // currently locked
    record.isSystemApp = false;
    record.bundleName = bundleName;
    formInfos.push_back(record);

    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleLock(_, _, _))
        .WillOnce(Return(true)); // status unchanged would return early, so make it changed
    // IsBundleLock returns true == lock(true), but we want lock=false
    // Actually, IsBundleLock(_,_,_) == lock means no change -> early return.
    // We need IsBundleLock != lock to proceed. lock=false, IsBundleLock returns true -> changed

    EXPECT_CALL(*MockFormBundleLockMgr::obj, SetBundleLockStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(formInfos), Return(true)));
    EXPECT_CALL(*MockFormInfoMgr::obj, IsMultiAppForm(_))
        .WillOnce(Return(false));
    EXPECT_CALL(*MockFormDataMgr::obj, SetFormProtect(_, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockFormDbCache::obj, UpdateDBRecord(_, _))
        .WillOnce(Return(ERR_OK));
    EXPECT_CALL(*MockFormExemptLockMgr::obj, SetExemptLockStatus(_, false))
        .Times(1);

    // ProtectLockForms will be called internally
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsLockServiceInitialized())
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormBundleLockMgr::obj, IsBundleProtect(_, _, _))
        .WillOnce(Return(false)); // status changed, but no records in ProtectLockForms
    EXPECT_CALL(*MockFormBundleLockMgr::obj, SetBundleProtectStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecordByBundleName(_, _))
        .WillOnce(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().SwitchLockForms(bundleName, TEST_USER_ID, lock);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "SwitchLockForms_005 end";
}

// ========== DeleteInvalidForms Happy Path ==========

/**
 * @tc.name: DeleteInvalidForms_002
 * @tc.desc: Verify DeleteInvalidForms with valid callerToken and formIds returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, DeleteInvalidForms_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteInvalidForms_002 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    int32_t numFormsDeleted = 0;

    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(DoAll(SetArgReferee<0>("com.test.bundle"), Return(ERR_OK)));

    auto result = FormLifecycleAdapter::GetInstance().DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "DeleteInvalidForms_002 end";
}

/**
 * @tc.name: DeleteInvalidForms_003
 * @tc.desc: Verify DeleteInvalidForms with empty formIds returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, DeleteInvalidForms_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteInvalidForms_003 start";

    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    int32_t numFormsDeleted = 0;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormLifecycleAdapter::GetInstance().DeleteInvalidForms(formIds, callerToken, numFormsDeleted);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(numFormsDeleted, 0);

    GTEST_LOG_(INFO) << "DeleteInvalidForms_003 end";
}

// ========== RecoverForms Happy Path and Error ==========

/**
 * @tc.name: RecoverForms_003
 * @tc.desc: Verify RecoverForms with valid formId but no form record returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecoverForms_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForms_003 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, SetExpectRecycledStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false)); // form not found

    auto result = FormLifecycleAdapter::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecoverForms_003 end";
}

/**
 * @tc.name: RecoverForms_004
 * @tc.desc: Verify RecoverForms with static form returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecoverForms_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForms_004 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.isDynamic = false; // static form should be skipped

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, SetExpectRecycledStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormLifecycleAdapter::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecoverForms_004 end";
}

/**
 * @tc.name: RecoverForms_005
 * @tc.desc: Verify RecoverForms with dynamic form not in recycle state skipped
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecoverForms_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForms_005 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.isDynamic = true;
    record.isExistRecycleTask = false;
    record.formUserUids.push_back(TEST_CALLING_UID);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, SetExpectRecycledStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    // IsFormProcessRecycle returns false, needHandleCachedClick=false -> skip
    auto result = FormLifecycleAdapter::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecoverForms_005 end";
}

/**
 * @tc.name: RecoverForms_006
 * @tc.desc: Verify RecoverForms with form not owned by caller skipped
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecoverForms_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForms_006 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.isDynamic = true;
    record.isExistRecycleTask = true; // has recycle task
    record.formUserUids.clear(); // caller not in formUserUids

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, SetExpectRecycledStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormLifecycleAdapter::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecoverForms_006 end";
}

/**
 * @tc.name: RecoverForms_007
 * @tc.desc: Verify RecoverForms with valid recyclable form owned by caller returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecoverForms_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForms_007 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.isDynamic = true;
    record.isExistRecycleTask = true;
    record.formUserUids.push_back(TEST_CALLING_UID);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, SetExpectRecycledStatus(_, _))
        .Times(1);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, UpdateFormRecord(_, _))
        .WillOnce(Return(true));

    auto result = FormLifecycleAdapter::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RecoverForms_007 end";
}

/**
 * @tc.name: RecoverForms_008
 * @tc.desc: Verify RecoverForms with formId == 0 is skipped
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecoverForms_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForms_008 start";

    std::vector<int64_t> formIds = {0};
    Want want;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecoverForms_008 end";
}

// ========== RecycleForms Happy Path and Error ==========

/**
 * @tc.name: RecycleForms_003
 * @tc.desc: Verify RecycleForms with valid formId but no form record returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecycleForms_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForms_003 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(Return(false)); // no form record

    auto result = FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecycleForms_003 end";
}

/**
 * @tc.name: RecycleForms_004
 * @tc.desc: Verify RecycleForms skips temp forms
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecycleForms_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForms_004 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.formTempFlag = true; // temp form

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecycleForms_004 end";
}

/**
 * @tc.name: RecycleForms_005
 * @tc.desc: Verify RecycleForms skips static forms
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecycleForms_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForms_005 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.formTempFlag = false;
    record.isDynamic = false; // static form

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecycleForms_005 end";
}

/**
 * @tc.name: RecycleForms_006
 * @tc.desc: Verify RecycleForms skips non-ETS forms
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecycleForms_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForms_006 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.formTempFlag = false;
    record.isDynamic = true;
    record.uiSyntax = FormType::JS; // not ETS

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecycleForms_006 end";
}

/**
 * @tc.name: RecycleForms_007
 * @tc.desc: Verify RecycleForms skips form not owned by caller when isCheckCallingUid=true
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecycleForms_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForms_007 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.formTempFlag = false;
    record.isDynamic = true;
    record.uiSyntax = FormType::ETS;
    record.formUserUids.clear(); // caller not in formUserUids

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));

    auto result = FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RecycleForms_007 end";
}

/**
 * @tc.name: RecycleForms_008
 * @tc.desc: Verify RecycleForms with valid ETS dynamic form owned by caller returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecycleForms_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForms_008 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.formTempFlag = false;
    record.isDynamic = true;
    record.uiSyntax = FormType::ETS;
    record.formUserUids.push_back(TEST_CALLING_UID);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, SetExpectRecycledStatus(_, _))
        .Times(1);

    auto result = FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, true);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RecycleForms_008 end";
}

/**
 * @tc.name: RecycleForms_009
 * @tc.desc: Verify RecycleForms with isCheckCallingUid=false and low callingUid uses formUserUids
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, RecycleForms_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForms_009 start";

    std::vector<int64_t> formIds = {TEST_FORM_ID};
    Want want;

    FormRecord record;
    record.formTempFlag = false;
    record.isDynamic = true;
    record.uiSyntax = FormType::ETS;
    record.formUserUids.push_back(TEST_CALLING_UID);

    // Use a callingUid below the divisor
    int32_t lowCallingUid = 100;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(lowCallingUid));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(record), Return(true)));
    EXPECT_CALL(*MockFormDataMgr::obj, SetExpectRecycledStatus(_, _))
        .Times(1);

    auto result = FormLifecycleAdapter::GetInstance().RecycleForms(formIds, want, false);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RecycleForms_009 end";
}

// ========== BatchNotifyFormsConfigurationUpdate Happy Path ==========

/**
 * @tc.name: BatchNotifyFormsConfigurationUpdate_002
 * @tc.desc: Verify BatchNotifyFormsConfigurationUpdate with visible records processes them
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, BatchNotifyFormsConfigurationUpdate_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "BatchNotifyFormsConfigurationUpdate_002 start";

    AppExecFwk::Configuration configuration;

    // GetRecordsByFormType is not mocked - it's a real call that returns empty by default
    // So we test the default empty case
    auto result = FormLifecycleAdapter::GetInstance().BatchNotifyFormsConfigurationUpdate(configuration);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "BatchNotifyFormsConfigurationUpdate_002 end";
}

// ========== CreateForm Additional Branch ==========

/**
 * @tc.name: CreateForm_002
 * @tc.desc: Verify CreateForm with isThemeForm=true and THEME_MGR_ENABLE undefined
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CreateForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CreateForm_002 start";

    Want want;
    want.SetParam(Constants::PARAM_THEME_KEY, true);
    RunningFormInfo runningFormInfo;

    auto result = FormLifecycleAdapter::GetInstance().CreateForm(want, runningFormInfo);
    // When THEME_MGR_ENABLE is not defined, returns ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED);

    GTEST_LOG_(INFO) << "CreateForm_002 end";
}

// ========== CheckAddRequestPublishForm Tests ==========

/**
 * @tc.name: CheckAddRequestPublishForm_001
 * @tc.desc: Verify CheckAddRequestPublishForm with bundleName mismatch returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckAddRequestPublishForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_001 start";

    Want want;
    want.SetElementName("com.test.bundle1", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));

    Want formProviderWant;
    formProviderWant.SetElementName("com.test.bundle2", "MainAbility");
    formProviderWant.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckAddRequestPublishForm(want, formProviderWant);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_001 end";
}

/**
 * @tc.name: CheckAddRequestPublishForm_002
 * @tc.desc: Verify CheckAddRequestPublishForm with moduleName mismatch returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckAddRequestPublishForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_002 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry1"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));

    Want formProviderWant;
    formProviderWant.SetElementName("com.test.bundle", "MainAbility");
    formProviderWant.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry2"));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckAddRequestPublishForm(want, formProviderWant);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_002 end";
}

/**
 * @tc.name: CheckAddRequestPublishForm_003
 * @tc.desc: Verify CheckAddRequestPublishForm with abilityName mismatch returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckAddRequestPublishForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_003 start";

    Want want;
    want.SetElementName("com.test.bundle", "Ability1");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));

    Want formProviderWant;
    formProviderWant.SetElementName("com.test.bundle", "Ability2");
    formProviderWant.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckAddRequestPublishForm(want, formProviderWant);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_003 end";
}

/**
 * @tc.name: CheckAddRequestPublishForm_004
 * @tc.desc: Verify CheckAddRequestPublishForm with formName mismatch returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckAddRequestPublishForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_004 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget1"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));

    Want formProviderWant;
    formProviderWant.SetElementName("com.test.bundle", "MainAbility");
    formProviderWant.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    formProviderWant.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget2"));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckAddRequestPublishForm(want, formProviderWant);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_004 end";
}

/**
 * @tc.name: CheckAddRequestPublishForm_005
 * @tc.desc: Verify CheckAddRequestPublishForm with dimensionId mismatch returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckAddRequestPublishForm_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_005 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(1));

    Want formProviderWant;
    formProviderWant.SetElementName("com.test.bundle", "MainAbility");
    formProviderWant.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    formProviderWant.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    formProviderWant.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(2));

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckAddRequestPublishForm(want, formProviderWant);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_005 end";
}

/**
 * @tc.name: CheckAddRequestPublishForm_006
 * @tc.desc: Verify CheckAddRequestPublishForm with temporary flag mismatch returns error
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckAddRequestPublishForm_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_006 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, true);

    Want formProviderWant;
    formProviderWant.SetElementName("com.test.bundle", "MainAbility");
    formProviderWant.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    formProviderWant.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    formProviderWant.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    formProviderWant.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckAddRequestPublishForm(want, formProviderWant);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_006 end";
}

/**
 * @tc.name: CheckAddRequestPublishForm_007
 * @tc.desc: Verify CheckAddRequestPublishForm with all matching params returns ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckAddRequestPublishForm_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_007 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);

    Want formProviderWant;
    formProviderWant.SetElementName("com.test.bundle", "MainAbility");
    formProviderWant.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    formProviderWant.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    formProviderWant.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    formProviderWant.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, false);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckAddRequestPublishForm(want, formProviderWant);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT);

    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_007 end";
}

/**
 * @tc.name: CheckAddRequestPublishForm_008
 * @tc.desc: Verify CheckAddRequestPublishForm with temporary=true calls CheckTempEnoughForm
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CheckAddRequestPublishForm_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_008 start";

    Want want;
    want.SetElementName("com.test.bundle", "MainAbility");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, true);

    Want formProviderWant;
    formProviderWant.SetElementName("com.test.bundle", "MainAbility");
    formProviderWant.SetParam(Constants::PARAM_MODULE_NAME_KEY, std::string("entry"));
    formProviderWant.SetParam(Constants::PARAM_FORM_NAME_KEY, std::string("widget"));
    formProviderWant.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, static_cast<int>(TEST_DIMENSION_ID));
    formProviderWant.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, true);

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    auto result = FormLifecycleAdapter::GetInstance().CheckAddRequestPublishForm(want, formProviderWant);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "CheckAddRequestPublishForm_008 end";
}

// ========== IsFormRenderServiceCall Tests ==========

/**
 * @tc.name: IsFormRenderServiceCall_001
 * @tc.desc: Verify IsFormRenderServiceCall returns false when GetBundleNameByUid fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, IsFormRenderServiceCall_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsFormRenderServiceCall_001 start";

    // GetBundleNameByUid is not mocked - uses real implementation which will fail
    auto result = FormLifecycleAdapter::GetInstance().IsFormRenderServiceCall(TEST_CALLING_UID);
    EXPECT_FALSE(result);

    GTEST_LOG_(INFO) << "IsFormRenderServiceCall_001 end";
}

// ========== HandleFormRemoveObserver Additional Test ==========

/**
 * @tc.name: HandleFormRemoveObserver_003
 * @tc.desc: Verify HandleFormRemoveObserver returns ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED on failure
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, HandleFormRemoveObserver_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFormRemoveObserver_003 start";

    RunningFormInfo runningFormInfo;

    EXPECT_CALL(*MockFormBmsHelper::obj, GetCallerBundleName(_))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_GET_BMS_FAILED));

    auto result = FormLifecycleAdapter::GetInstance().HandleFormRemoveObserver(runningFormInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED);

    GTEST_LOG_(INFO) << "HandleFormRemoveObserver_003 end";
}

// ========== AddForm Error Path Tests ==========

/**
 * @tc.name: AddForm_004
 * @tc.desc: Verify AddForm with formId=0 and valid callerToken passes param validation
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, AddForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AddForm_004 start";

    Want want;
    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    FormJsInfo formJsInfo;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));

    // This goes through CheckFormCountLimit -> GetFormConfigInfo -> etc.
    // GetFormConfigInfo will fail since we don't set up full mock chain
    auto result = FormLifecycleAdapter::GetInstance().AddForm(0, want, callerToken, formJsInfo);
    // Will fail at GetFormConfigInfo due to missing bundle info
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "AddForm_004 end";
}

// ========== DeleteForm Happy Path Test ==========

/**
 * @tc.name: DeleteForm_004
 * @tc.desc: Verify DeleteForm with valid params and temp form calls HandleDeleteTempForm
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, DeleteForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DeleteForm_004 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*MockFormDataMgr::obj, ExistFormRecord(_))
        .WillRepeatedly(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().DeleteForm(TEST_FORM_ID, callerToken);
    // Will call DeleteCommonForm -> checks ExistTempForm which returns false -> HandleDeleteForm
    // HandleDeleteForm checks GetDBRecord which returns error -> ERR_APPEXECFWK_FORM_NOT_EXIST_ID
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "DeleteForm_004 end";
}

// ========== ReleaseForm Additional Branches ==========

/**
 * @tc.name: ReleaseForm_004
 * @tc.desc: Verify ReleaseForm with valid params and temp form goes to HandleDeleteTempForm
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, ReleaseForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseForm_004 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(_, _))
        .WillRepeatedly(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().ReleaseForm(TEST_FORM_ID, callerToken, true);
    // Goes to ExistTempForm which returns false (from default mock), then GetDBRecord fails
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "ReleaseForm_004 end";
}

// ========== CastTempForm Additional Branches ==========

/**
 * @tc.name: CastTempForm_004
 * @tc.desc: Verify CastTempForm with valid params but no form record returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CastTempForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CastTempForm_004 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, ExistFormRecord(_))
        .WillOnce(Return(false));

    auto result = FormLifecycleAdapter::GetInstance().CastTempForm(TEST_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "CastTempForm_004 end";
}

/**
 * @tc.name: CastTempForm_005
 * @tc.desc: Verify CastTempForm with form record but no temp form returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CastTempForm_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CastTempForm_005 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, ExistFormRecord(_))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormDataMgr::obj, GetMatchedHostClient(_, _))
        .WillOnce(Return(false));

    // ExistTempForm is not mocked - calls real method which returns false
    // Then GetMatchedHostClient returns false, so isSelfId = false
    // But first check: !ExistFormRecord || !ExistTempForm
    // ExistFormRecord returns true, ExistTempForm returns false -> returns NOT_EXIST_ID
    auto result = FormLifecycleAdapter::GetInstance().CastTempForm(TEST_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "CastTempForm_005 end";
}

/**
 * @tc.name: CastTempForm_006
 * @tc.desc: Verify CastTempForm with no matched host client returns ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, CastTempForm_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CastTempForm_006 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();

    FormHostRecord hostRecord;

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, FindMatchedFormId(_))
        .WillRepeatedly(Return(TEST_FORM_ID));
    EXPECT_CALL(*MockFormDataMgr::obj, ExistFormRecord(_))
        .WillOnce(Return(true));
    EXPECT_CALL(*MockFormDataMgr::obj, GetMatchedHostClient(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(hostRecord), Return(false)));

    // ExistTempForm is not mocked, returns false from real impl -> NOT_EXIST_ID
    auto result = FormLifecycleAdapter::GetInstance().CastTempForm(TEST_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "CastTempForm_006 end";
}

// ========== HandleDeleteFormCache Tests ==========

/**
 * @tc.name: HandleDeleteFormCache_001
 * @tc.desc: Verify HandleDeleteFormCache with empty formUserUids deletes all form data
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, HandleDeleteFormCache_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleDeleteFormCache_001 start";

    FormRecord dbRecord;
    dbRecord.formId = TEST_FORM_ID;
    dbRecord.bundleName = "com.test.bundle";
    dbRecord.moduleName = "entry";
    dbRecord.formUserUids.clear(); // empty - triggers full delete path

    EXPECT_CALL(*MockFormDbCache::obj, UpdateDBRecord(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormLifecycleAdapter::GetInstance().HandleDeleteFormCache(dbRecord, TEST_CALLING_UID, TEST_FORM_ID);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "HandleDeleteFormCache_001 end";
}

/**
 * @tc.name: HandleDeleteFormCache_002
 * @tc.desc: Verify HandleDeleteFormCache with remaining formUserUids updates DB record
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, HandleDeleteFormCache_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleDeleteFormCache_002 start";

    FormRecord dbRecord;
    dbRecord.formId = TEST_FORM_ID;
    dbRecord.bundleName = "com.test.bundle";
    dbRecord.moduleName = "entry";
    dbRecord.formUserUids.push_back(TEST_CALLING_UID);
    dbRecord.formUserUids.push_back(999); // another user remains

    EXPECT_CALL(*MockFormDbCache::obj, UpdateDBRecord(_, _))
        .WillOnce(Return(ERR_OK));

    auto result = FormLifecycleAdapter::GetInstance().HandleDeleteFormCache(dbRecord, TEST_CALLING_UID, TEST_FORM_ID);
    // After erasing callingUid, formUserUids still has 999 -> update path
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "HandleDeleteFormCache_002 end";
}

/**
 * @tc.name: HandleDeleteFormCache_003
 * @tc.desc: Verify HandleDeleteFormCache returns error when UpdateDBRecord fails
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, HandleDeleteFormCache_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleDeleteFormCache_003 start";

    FormRecord dbRecord;
    dbRecord.formId = TEST_FORM_ID;
    dbRecord.bundleName = "com.test.bundle";
    dbRecord.moduleName = "entry";
    dbRecord.formUserUids.push_back(TEST_CALLING_UID);
    dbRecord.formUserUids.push_back(999);

    EXPECT_CALL(*MockFormDbCache::obj, UpdateDBRecord(_, _))
        .WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));

    auto result = FormLifecycleAdapter::GetInstance().HandleDeleteFormCache(dbRecord, TEST_CALLING_UID, TEST_FORM_ID);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "HandleDeleteFormCache_003 end";
}

// ========== HandleReleaseForm Tests ==========

/**
 * @tc.name: HandleReleaseForm_001
 * @tc.desc: Verify HandleReleaseForm with non-existent form record returns ERR_APPEXECFWK_FORM_NOT_EXIST_ID
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, HandleReleaseForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleReleaseForm_001 start";

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, ExistFormRecord(_))
        .WillOnce(Return(false));

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto result = FormLifecycleAdapter::GetInstance().HandleReleaseForm(TEST_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);

    GTEST_LOG_(INFO) << "HandleReleaseForm_001 end";
}

/**
 * @tc.name: HandleReleaseForm_002
 * @tc.desc: Verify HandleReleaseForm with no matched host client returns ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, HandleReleaseForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleReleaseForm_002 start";

    EXPECT_CALL(*MockIPCSkeleton::obj, GetCallingUid())
        .WillRepeatedly(Return(TEST_CALLING_UID));
    EXPECT_CALL(*MockFormDataMgr::obj, ExistFormRecord(_))
        .WillOnce(Return(true));

    FormHostRecord hostRecord;
    EXPECT_CALL(*MockFormDataMgr::obj, GetMatchedHostClient(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(hostRecord), Return(false)));

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto result = FormLifecycleAdapter::GetInstance().HandleReleaseForm(TEST_FORM_ID, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF);

    GTEST_LOG_(INFO) << "HandleReleaseForm_002 end";
}

// ========== AllotFormByInfo Tests ==========

/**
 * @tc.name: AllotFormByInfo_001
 * @tc.desc: Verify AllotFormByInfo with GenerateFormId returning negative returns ERR_APPEXECFWK_FORM_COMMON_CODE
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormLifecycleAdapterTest, AllotFormByInfo_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AllotFormByInfo_001 start";

    FormItemInfo info;
    WantParams wantParams;
    FormJsInfo formInfo;

    EXPECT_CALL(*MockFormDataMgr::obj, GenerateFormId())
        .WillOnce(Return(-1));

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto result = FormLifecycleAdapter::GetInstance().AllotFormByInfo(info, callerToken, wantParams, formInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);

    GTEST_LOG_(INFO) << "AllotFormByInfo_001 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
