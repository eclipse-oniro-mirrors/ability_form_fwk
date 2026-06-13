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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#define private public
#define protected public
#include "form_provider/error_handler/provider_acquire_error_handler.h"
#include "form_provider/error_handler/provider_error_handler_factory.h"
#include "common/connection/form_ability_connection.h"
#include "common/retry_policy/retry_policy.h"
#include "common/util/form_task_common.h"
#undef private
#undef protected

#include "mock_form_data_mgr.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t FORM_ID = 200;
const int32_t IPC_ERR_DEAD_OBJECT = 32;
}

// Minimal concrete FormAbilityConnection for handler tests (state is controllable).
class TestConnection : public FormAbilityConnection {
public:
    TestConnection() = default;
protected:
    void OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject) override {}
    Want OnBuildTaskWant() override
    {
        Want want;
        return want;
    }
public:
    sptr<FormAbilityConnection> CreateRetryConnection() const override
    {
        return new TestConnection();
    }
};

class FmsProviderAcquireErrorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown();

protected:
    sptr<FormProviderAcquireErrorHandler> handler_;
    std::shared_ptr<MockFormDataMgr> mockFormDataMgr_;
};

void FmsProviderAcquireErrorHandlerTest::SetUp()
{
    handler_ = FormProviderErrorHandlerFactory::GetAcquireHandler();
    mockFormDataMgr_ = std::make_shared<MockFormDataMgr>();
    MockFormDataMgr::obj = mockFormDataMgr_;
    handler_->RemoveRetryPolicy(FORM_ID);
}

void FmsProviderAcquireErrorHandlerTest::TearDown()
{
    testing::Mock::VerifyAndClearExpectations(mockFormDataMgr_.get());
    handler_->RemoveRetryPolicy(FORM_ID);
    MockFormDataMgr::obj = nullptr;
}

/**
 * @tc.name: GetRetryTaskType_001
 * @tc.desc: Verify acquire handler returns ACQUIRE_RETRY_TASK.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, GetRetryTaskType_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetRetryTaskType_001 start";
    EXPECT_EQ(handler_->GetRetryTaskType(), TaskType::ACQUIRE_RETRY_TASK);
    GTEST_LOG_(INFO) << "GetRetryTaskType_001 end";
}

/**
 * @tc.name: OnPrepareRetryConnect_001
 * @tc.desc: Verify OnPrepareRetryConnect sets state to CONNECTING (acquire-only).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, OnPrepareRetryConnect_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnPrepareRetryConnect_001 start";
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::DISCONNECTED);
    handler_->OnPrepareRetryConnect(conn);
    ASSERT_NE(conn, nullptr);
    EXPECT_EQ(conn->GetConnectState(), ConnectState::CONNECTING);
    GTEST_LOG_(INFO) << "OnPrepareRetryConnect_001 end";
}

/**
 * @tc.name: OnRetryLimitReached_001
 * @tc.desc: Verify OnRetryLimitReached erases the policy (acquire exhaustion terminal handling).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, OnRetryLimitReached_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRetryLimitReached_001 start";
    auto &policy = handler_->EnsureRetryPolicy(FORM_ID);
    policy.SetSendRequestFailed(true);
    EXPECT_NE(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    handler_->OnRetryLimitReached(FORM_ID);
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "OnRetryLimitReached_001 end";
}

/**
 * @tc.name: HandleSendRequestFailed_DeadObject_001
 * @tc.desc: Verify path A signal 1: dead error sets sendRequestFailed and waits for disconnect.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, HandleSendRequestFailed_DeadObject_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleSendRequestFailed_DeadObject_001 start";
    Want want;
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_TRUE(it->second.IsSendRequestFailed());
    EXPECT_FALSE(it->second.IsDisconnectFailed());
    GTEST_LOG_(INFO) << "HandleSendRequestFailed_DeadObject_001 end";
}

/**
 * @tc.name: HandleDisconnectError_NotConnected_001
 * @tc.desc: Verify HandleDisconnectError returns false when connection state != CONNECTED
 *           (path B is handled by FormAcquireConnection, not the handler).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, HandleDisconnectError_NotConnected_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleDisconnectError_NotConnected_001 start";
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::DISCONNECTED);
    EXPECT_FALSE(handler_->HandleDisconnectError(FORM_ID, conn));
    GTEST_LOG_(INFO) << "HandleDisconnectError_NotConnected_001 end";
}

/**
 * @tc.name: DualSignal_SendFirst_001
 * @tc.desc: Verify path A dual-signal: send first → disconnect (CONNECTED) → confirmed retry.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, DualSignal_SendFirst_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DualSignal_SendFirst_001 start";
    Want want;
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::CONNECTED);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, conn));
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetRetryCount(), 1);
    GTEST_LOG_(INFO) << "DualSignal_SendFirst_001 end";
}

/**
 * @tc.name: DualSignal_RetryLimit_001
 * @tc.desc: Verify path A retry limit: exhaustion calls OnRetryLimitReached (erase + SendFormFailedEvent).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, DualSignal_RetryLimit_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DualSignal_RetryLimit_001 start";
    auto &policy = handler_->EnsureRetryPolicy(FORM_ID);
    policy.SetSendRequestFailed(true);
    policy.SetDisconnectFailed(true);
    for (int i = 0; i < 3; i++) { // maxRetryCount = 3 → IsRetryLimitReached
        policy.IncrementRetryCount();
    }
    EXPECT_TRUE(policy.IsRetryLimitReached());
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::CONNECTED);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, conn));
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "DualSignal_RetryLimit_001 end";
}
