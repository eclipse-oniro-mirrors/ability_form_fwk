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
#include "form_mgr/form_observer_adapter.h"
#include "form_mgr/form_common_adapter.h"
#undef private
#undef protected

#include "form_mgr_errors.h"
#include "iremote_object.h"

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

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string TEST_BUNDLE_NAME = "com.test.bundle";
const std::string TEST_EMPTY_BUNDLE_NAME = "";
const std::string TEST_FORM_EVENT_TYPE = "call";
const std::string TEST_FORM_EVENT_TYPE_ROUTER = "router";
}

class FmsFormObserverAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormObserverAdapterTest::SetUpTestCase()
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

void FmsFormObserverAdapterTest::TearDownTestCase()
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

void FmsFormObserverAdapterTest::SetUp()
{
}

void FmsFormObserverAdapterTest::TearDown()
{
}

// ========== RegisterFormAddObserverByBundle Tests ==========

/**
 * @tc.name: RegisterFormAddObserverByBundle_001
 * @tc.desc: Verify delegation to FormObserverRecord with empty bundleName
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterFormAddObserverByBundle_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormAddObserverByBundle_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto result = FormObserverAdapter::GetInstance().RegisterFormAddObserverByBundle(
        TEST_EMPTY_BUNDLE_NAME, callerToken);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterFormAddObserverByBundle_001 end";
}

/**
 * @tc.name: RegisterFormAddObserverByBundle_002
 * @tc.desc: Verify delegation to FormObserverRecord with null callerToken
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterFormAddObserverByBundle_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormAddObserverByBundle_002 start";

    sptr<IRemoteObject> callerToken = nullptr;
    auto result = FormObserverAdapter::GetInstance().RegisterFormAddObserverByBundle(
        TEST_BUNDLE_NAME, callerToken);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterFormAddObserverByBundle_002 end";
}

/**
 * @tc.name: RegisterFormAddObserverByBundle_003
 * @tc.desc: Verify successful delegation with valid params
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterFormAddObserverByBundle_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormAddObserverByBundle_003 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto result = FormObserverAdapter::GetInstance().RegisterFormAddObserverByBundle(
        TEST_BUNDLE_NAME, callerToken);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterFormAddObserverByBundle_003 end";
}

// ========== RegisterFormRemoveObserverByBundle Tests ==========

/**
 * @tc.name: RegisterFormRemoveObserverByBundle_001
 * @tc.desc: Verify delegation to FormObserverRecord with empty bundleName
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterFormRemoveObserverByBundle_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormRemoveObserverByBundle_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto result = FormObserverAdapter::GetInstance().RegisterFormRemoveObserverByBundle(
        TEST_EMPTY_BUNDLE_NAME, callerToken);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterFormRemoveObserverByBundle_001 end";
}

/**
 * @tc.name: RegisterFormRemoveObserverByBundle_002
 * @tc.desc: Verify delegation to FormObserverRecord with null callerToken
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterFormRemoveObserverByBundle_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormRemoveObserverByBundle_002 start";

    sptr<IRemoteObject> callerToken = nullptr;
    auto result = FormObserverAdapter::GetInstance().RegisterFormRemoveObserverByBundle(
        TEST_BUNDLE_NAME, callerToken);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterFormRemoveObserverByBundle_002 end";
}

/**
 * @tc.name: RegisterFormRemoveObserverByBundle_003
 * @tc.desc: Verify successful delegation with valid params
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterFormRemoveObserverByBundle_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterFormRemoveObserverByBundle_003 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto result = FormObserverAdapter::GetInstance().RegisterFormRemoveObserverByBundle(
        TEST_BUNDLE_NAME, callerToken);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterFormRemoveObserverByBundle_003 end";
}

// ========== RegisterAddObserver Tests ==========

/**
 * @tc.name: RegisterAddObserver_001
 * @tc.desc: Verify successful delegation to FormCommonAdapter with valid params
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterAddObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterAddObserver_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    auto result = FormObserverAdapter::GetInstance().RegisterAddObserver(TEST_BUNDLE_NAME, callerToken);
    EXPECT_EQ(result, ERR_OK);

    // Clean up the observer registered during test
    FormCommonAdapter::GetInstance().formObservers_.clear();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    GTEST_LOG_(INFO) << "RegisterAddObserver_001 end";
}

/**
 * @tc.name: RegisterAddObserver_002
 * @tc.desc: Verify null callerToken delegation to FormCommonAdapter
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterAddObserver_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterAddObserver_002 start";

    sptr<IRemoteObject> callerToken = nullptr;
    auto result = FormObserverAdapter::GetInstance().RegisterAddObserver(TEST_BUNDLE_NAME, callerToken);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterAddObserver_002 end";
}

// ========== RegisterRemoveObserver Tests ==========

/**
 * @tc.name: RegisterRemoveObserver_001
 * @tc.desc: Verify successful delegation to FormCommonAdapter with valid params
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterRemoveObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterRemoveObserver_001 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    // First add an observer so remove can succeed
    auto addResult = FormCommonAdapter::GetInstance().RegisterAddObserver(TEST_BUNDLE_NAME, callerToken);
    EXPECT_EQ(addResult, ERR_OK);

    auto result = FormObserverAdapter::GetInstance().RegisterRemoveObserver(TEST_BUNDLE_NAME, callerToken);
    EXPECT_EQ(result, ERR_OK);

    FormCommonAdapter::GetInstance().formObservers_.clear();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    GTEST_LOG_(INFO) << "RegisterRemoveObserver_001 end";
}

/**
 * @tc.name: RegisterRemoveObserver_002
 * @tc.desc: Verify null callerToken delegation to FormCommonAdapter
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterRemoveObserver_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterRemoveObserver_002 start";

    sptr<IRemoteObject> callerToken = nullptr;
    auto result = FormObserverAdapter::GetInstance().RegisterRemoveObserver(TEST_BUNDLE_NAME, callerToken);
    EXPECT_NE(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterRemoveObserver_002 end";
}

// ========== CleanResource Tests ==========

/**
 * @tc.name: CleanResource_001
 * @tc.desc: Verify null remote object does not crash
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, CleanResource_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CleanResource_001 start";

    wptr<IRemoteObject> remote = nullptr;
    FormObserverAdapter::GetInstance().CleanResource(remote);
    EXPECT_EQ(FormCommonAdapter::GetInstance().formObservers_.size(), 0u);

    GTEST_LOG_(INFO) << "CleanResource_001 end";
}

/**
 * @tc.name: CleanResource_002
 * @tc.desc: Verify valid remote object cleans resource
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, CleanResource_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CleanResource_002 start";

    sptr<IRemoteObject> callerToken = new MockIRemoteObject();
    auto *mockCaller = static_cast<MockIRemoteObject *>(callerToken.GetRefPtr());
    EXPECT_CALL(*mockCaller, AddDeathRecipient(_))
        .WillOnce(Return(true));

    // Register an observer first so CleanResource has something to clean
    auto addResult = FormCommonAdapter::GetInstance().RegisterAddObserver(TEST_BUNDLE_NAME, callerToken);
    EXPECT_EQ(addResult, ERR_OK);

    wptr<IRemoteObject> remote = callerToken;
    FormObserverAdapter::GetInstance().CleanResource(remote);
    EXPECT_EQ(FormCommonAdapter::GetInstance().formObservers_.count(TEST_BUNDLE_NAME), 0u);

    FormCommonAdapter::GetInstance().formObservers_.clear();
    FormCommonAdapter::GetInstance().deathRecipients_.clear();

    GTEST_LOG_(INFO) << "CleanResource_002 end";
}

// ========== RegisterClickEventObserver Tests ==========

/**
 * @tc.name: RegisterClickEventObserver_001
 * @tc.desc: Verify null observer returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterClickEventObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterClickEventObserver_001 start";

    sptr<IRemoteObject> observer = nullptr;
    auto result = FormObserverAdapter::GetInstance().RegisterClickEventObserver(
        TEST_BUNDLE_NAME, TEST_FORM_EVENT_TYPE, observer);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "RegisterClickEventObserver_001 end";
}

/**
 * @tc.name: RegisterClickEventObserver_002
 * @tc.desc: Verify valid params delegates to FormObserverRecord and returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, RegisterClickEventObserver_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RegisterClickEventObserver_002 start";

    sptr<IRemoteObject> observer = new MockIRemoteObject();
    auto result = FormObserverAdapter::GetInstance().RegisterClickEventObserver(
        TEST_BUNDLE_NAME, TEST_FORM_EVENT_TYPE, observer);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "RegisterClickEventObserver_002 end";
}

// ========== UnregisterClickEventObserver Tests ==========

/**
 * @tc.name: UnregisterClickEventObserver_001
 * @tc.desc: Verify null observer returns ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, UnregisterClickEventObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterClickEventObserver_001 start";

    sptr<IRemoteObject> observer = nullptr;
    auto result = FormObserverAdapter::GetInstance().UnregisterClickEventObserver(
        TEST_BUNDLE_NAME, TEST_FORM_EVENT_TYPE, observer);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);

    GTEST_LOG_(INFO) << "UnregisterClickEventObserver_001 end";
}

/**
 * @tc.name: UnregisterClickEventObserver_002
 * @tc.desc: Verify valid params delegates to FormObserverRecord and returns ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, UnregisterClickEventObserver_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterClickEventObserver_002 start";

    sptr<IRemoteObject> observer = new MockIRemoteObject();

    // First register so unregister can succeed
    auto registerResult = FormObserverAdapter::GetInstance().RegisterClickEventObserver(
        TEST_BUNDLE_NAME, TEST_FORM_EVENT_TYPE, observer);
    EXPECT_EQ(registerResult, ERR_OK);

    auto result = FormObserverAdapter::GetInstance().UnregisterClickEventObserver(
        TEST_BUNDLE_NAME, TEST_FORM_EVENT_TYPE, observer);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterClickEventObserver_002 end";
}

/**
 * @tc.name: UnregisterClickEventObserver_003
 * @tc.desc: Verify non-registered observer returns ERR_OK (stub behavior)
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormObserverAdapterTest, UnregisterClickEventObserver_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "UnregisterClickEventObserver_003 start";

    sptr<IRemoteObject> observer = new MockIRemoteObject();

    // Unregister without prior registration - stub returns ERR_OK
    auto result = FormObserverAdapter::GetInstance().UnregisterClickEventObserver(
        TEST_BUNDLE_NAME, TEST_FORM_EVENT_TYPE_ROUTER, observer);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "UnregisterClickEventObserver_003 end";
}

}  // namespace AppExecFwk
}  // namespace OHOS
