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
 * @tc.name: OnRetryLimitReached_001
 * @tc.desc: Verify OnRetryLimitReached is a pure hook: reports HiSys event but does not modify map.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, OnRetryLimitReached_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRetryLimitReached_001 start";
    auto &policy = handler_->EnsureRetryPolicyLocked(FORM_ID);
    policy.SetStage(RequestStage::WAITING_DISCONNECT_CONFIRM);
    EXPECT_NE(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    handler_->OnRetryLimitReached(FORM_ID);
    EXPECT_NE(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    handler_->RemoveRetryPolicy(FORM_ID);
    GTEST_LOG_(INFO) << "OnRetryLimitReached_001 end";
}

/**
 * @tc.name: HandleSendRequestFailed_DeadObject_001
 * @tc.desc: Verify dead-object error enters WAITING_DISCONNECT_CONFIRM and waits for disconnect.
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
    EXPECT_EQ(it->second.GetStage(), RequestStage::WAITING_DISCONNECT_CONFIRM);
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
    auto &policy = handler_->EnsureRetryPolicyLocked(FORM_ID);
    policy.SetStage(RequestStage::WAITING_DISCONNECT_CONFIRM);
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

/**
 * @tc.name: HandleDisconnectError_NullConnection_001
 * @tc.desc: Verify HandleDisconnectError returns false for null connection (no crash).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, HandleDisconnectError_NullConnection_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleDisconnectError_NullConnection_001 start";
    sptr<FormAbilityConnection> nullConn = nullptr;
    EXPECT_FALSE(handler_->HandleDisconnectError(FORM_ID, nullConn));
    GTEST_LOG_(INFO) << "HandleDisconnectError_NullConnection_001 end";
}

/**
 * @tc.name: HandleSendRequestFailed_NonDeathError_001
 * @tc.desc: Verify HandleSendRequestFailed returns false for non-death error codes.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, HandleSendRequestFailed_NonDeathError_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleSendRequestFailed_NonDeathError_001 start";
    Want want;
    EXPECT_FALSE(handler_->HandleSendRequestFailed(FORM_ID, 0, want));
    EXPECT_FALSE(handler_->HandleSendRequestFailed(FORM_ID, 999, want));
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "HandleSendRequestFailed_NonDeathError_001 end";
}

/**
 * @tc.name: HandleDisconnectError_NoPriorSendRequest_001
 * @tc.desc: Verify HandleDisconnectError returns false when disconnect arrives without prior SendRequest.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, HandleDisconnectError_NoPriorSendRequest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleDisconnectError_NoPriorSendRequest_001 start";
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::CONNECTED);
    // No prior HandleSendRequestFailed → stage stays IDLE → WAITING_SEND_RESULT entry, not handled
    EXPECT_FALSE(handler_->HandleDisconnectError(FORM_ID, conn));
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::WAITING_SEND_RESULT);
    handler_->RemoveRetryPolicy(FORM_ID);
    GTEST_LOG_(INFO) << "HandleDisconnectError_NoPriorSendRequest_001 end";
}

/**
 * @tc.name: DualSignal_DisconnectFirst_001
 * @tc.desc: Verify dual-signal: disconnect first (returns false) → then sendRequest → confirmed.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, DualSignal_DisconnectFirst_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DualSignal_DisconnectFirst_001 start";
    Want want;
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::CONNECTED);

    // Disconnect first: no prior sendRequest → returns false, but records the disconnect
    EXPECT_FALSE(handler_->HandleDisconnectError(FORM_ID, conn));
    // SendRequest arrives after the disconnect: both signals confirmed, schedule retry
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));

    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetRetryCount(), 1);
    GTEST_LOG_(INFO) << "DualSignal_DisconnectFirst_001 end";
}

/**
 * @tc.name: OnSignalTimeout_StuckHalfSignal_001
 * @tc.desc: Verify OnSignalTimeout erases policy when only one signal arrived.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, OnSignalTimeout_StuckHalfSignal_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnSignalTimeout_StuckHalfSignal_001 start";
    // Simulate partial state: WAITING_DISCONNECT_CONFIRM (waiting for a disconnect that never comes)
    auto &policy = handler_->EnsureRetryPolicyLocked(FORM_ID);
    policy.SetStage(RequestStage::WAITING_DISCONNECT_CONFIRM);
    EXPECT_NE(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());

    handler_->OnSignalTimeout(FORM_ID);
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "OnSignalTimeout_StuckHalfSignal_001 end";
}

/**
 * @tc.name: OnSignalTimeout_BothSignalsSet_001
 * @tc.desc: Verify OnSignalTimeout does nothing when the stage is not a partial-signal
 *           stage (dual confirm resets the stage to IDLE before the retry is scheduled).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, OnSignalTimeout_BothSignalsSet_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnSignalTimeout_BothSignalsSet_001 start";
    auto &policy = handler_->EnsureRetryPolicyLocked(FORM_ID);
    policy.SetStage(RequestStage::IDLE);
    EXPECT_NE(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());

    handler_->OnSignalTimeout(FORM_ID);
    // Both signals confirmed resets to IDLE before retry, not stuck, policy preserved
    EXPECT_NE(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    handler_->RemoveRetryPolicy(FORM_ID);
    GTEST_LOG_(INFO) << "OnSignalTimeout_BothSignalsSet_001 end";
}

/**
 * @tc.name: StartCallbackPending_EnterWaitingStage_001
 * @tc.desc: Verify registration after SendRequest ERR_OK: enters WAITING_CALLBACK with
 *           connectId recorded and policy created.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, StartCallbackPending_EnterWaitingStage_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartCallbackPending_EnterWaitingStage_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::WAITING_CALLBACK);
    EXPECT_EQ(it->second.GetCallbackConnectId(), 100);
    GTEST_LOG_(INFO) << "StartCallbackPending_EnterWaitingStage_001 end";
}

/**
 * @tc.name: StartCallbackPending_OverwriteConnectId_001
 * @tc.desc: Verify re-registration overwrites the recorded connectId (retry cycle switch).
 *           Stale-timer misfire protection is covered by CallbackTimeout_StaleConnectId.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, StartCallbackPending_OverwriteConnectId_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StartCallbackPending_OverwriteConnectId_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    handler_->StartCallbackPending(FORM_ID, 200);
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::WAITING_CALLBACK);
    EXPECT_EQ(it->second.GetCallbackConnectId(), 200);
    GTEST_LOG_(INFO) << "StartCallbackPending_OverwriteConnectId_001 end";
}

/**
 * @tc.name: Disconnect_WaitingCallback_DirectRetry_001
 * @tc.desc: Verify WAITING_CALLBACK + disconnect (CONNECTED) retries directly
 *           (recovery delay = the provider death perception delay), count +1.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, Disconnect_WaitingCallback_DirectRetry_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Disconnect_WaitingCallback_DirectRetry_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::CONNECTED);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, conn));
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetRetryCount(), 1);
    EXPECT_EQ(it->second.GetStage(), RequestStage::IDLE);
    GTEST_LOG_(INFO) << "Disconnect_WaitingCallback_DirectRetry_001 end";
}

/**
 * @tc.name: Disconnect_WaitingCallback_RetryExhausted_001
 * @tc.desc: Verify WAITING_CALLBACK + disconnect with count exhausted erases the policy
 *           and reports OnRetryLimitReached (acquire: SendFormFailedEvent).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, Disconnect_WaitingCallback_RetryExhausted_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Disconnect_WaitingCallback_RetryExhausted_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    auto &policy = handler_->EnsureRetryPolicyLocked(FORM_ID);
    for (int i = 0; i < 3; i++) { // maxRetryCount = 3
        policy.IncrementRetryCount();
    }
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::CONNECTED);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, conn));
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "Disconnect_WaitingCallback_RetryExhausted_001 end";
}

/**
 * @tc.name: Disconnect_CallbackCompleted_ErasePolicy_001
 * @tc.desc: Verify CALLBACK_COMPLETED + disconnect erases the policy without retry
 *           (last-connection exit sequence, no zombie policy).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, Disconnect_CallbackCompleted_ErasePolicy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "Disconnect_CallbackCompleted_ErasePolicy_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    handler_->OnCallbackArrived(FORM_ID, 100);
    EXPECT_EQ(handler_->EnsureRetryPolicyLocked(FORM_ID).GetStage(), RequestStage::CALLBACK_COMPLETED);

    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::CONNECTED);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, conn));
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "Disconnect_CallbackCompleted_ErasePolicy_001 end";
}

/**
 * @tc.name: CallbackArrived_EnterCompleted_001
 * @tc.desc: Verify callback arrival with matching connectId enters CALLBACK_COMPLETED,
 *           cancels timeouts and keeps the policy in the map.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, CallbackArrived_EnterCompleted_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallbackArrived_EnterCompleted_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    handler_->OnCallbackArrived(FORM_ID, 100);
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::CALLBACK_COMPLETED);
    GTEST_LOG_(INFO) << "CallbackArrived_EnterCompleted_001 end";
}

/**
 * @tc.name: CallbackArrived_ConnectIdMismatch_001
 * @tc.desc: Verify callback arrival with a stale connectId does not advance the stage.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, CallbackArrived_ConnectIdMismatch_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallbackArrived_ConnectIdMismatch_001 start";
    handler_->StartCallbackPending(FORM_ID, 200);
    handler_->OnCallbackArrived(FORM_ID, 100); // stale round
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::WAITING_CALLBACK);
    EXPECT_EQ(it->second.GetCallbackConnectId(), 200);
    GTEST_LOG_(INFO) << "CallbackArrived_ConnectIdMismatch_001 end";
}

/**
 * @tc.name: CallbackArrived_NotWaitingStage_001
 * @tc.desc: Verify callback arrival on CALLBACK_COMPLETED is a no-op (terminal stays).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, CallbackArrived_NotWaitingStage_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallbackArrived_NotWaitingStage_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    handler_->OnCallbackArrived(FORM_ID, 100);
    handler_->OnCallbackArrived(FORM_ID, 100); // duplicate arrival
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::CALLBACK_COMPLETED);
    GTEST_LOG_(INFO) << "CallbackArrived_NotWaitingStage_001 end";
}

/**
 * @tc.name: CallbackArrived_NoPolicy_001
 * @tc.desc: Verify callback arrival without a policy is a safe no-op.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, CallbackArrived_NoPolicy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallbackArrived_NoPolicy_001 start";
    handler_->OnCallbackArrived(FORM_ID, 100);
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "CallbackArrived_NoPolicy_001 end";
}

/**
 * @tc.name: CallbackTimeout_NoEvent_OutOfScope_001
 * @tc.desc: Verify callback timeout with no event (same round, still WAITING_CALLBACK)
 *           erases the policy without retry (out of scope).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, CallbackTimeout_NoEvent_OutOfScope_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallbackTimeout_NoEvent_OutOfScope_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    handler_->OnCallbackTimeout(FORM_ID, 100);
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "CallbackTimeout_NoEvent_OutOfScope_001 end";
}

/**
 * @tc.name: CallbackTimeout_StaleConnectId_Ignored_001
 * @tc.desc: Verify callback timeout carrying a stale connectId is ignored (stale timer).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, CallbackTimeout_StaleConnectId_Ignored_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallbackTimeout_StaleConnectId_Ignored_001 start";
    handler_->StartCallbackPending(FORM_ID, 200);
    handler_->OnCallbackTimeout(FORM_ID, 100); // stale round
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::WAITING_CALLBACK);
    GTEST_LOG_(INFO) << "CallbackTimeout_StaleConnectId_Ignored_001 end";
}

/**
 * @tc.name: CallbackTimeout_NotWaiting_Ignored_001
 * @tc.desc: Verify callback timeout on a non-waiting stage is ignored (already handled).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, CallbackTimeout_NotWaiting_Ignored_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallbackTimeout_NotWaiting_Ignored_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    handler_->OnCallbackArrived(FORM_ID, 100); // -> CALLBACK_COMPLETED
    handler_->OnCallbackTimeout(FORM_ID, 100);
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::CALLBACK_COMPLETED);
    GTEST_LOG_(INFO) << "CallbackTimeout_NotWaiting_Ignored_001 end";
}

/**
 * @tc.name: ScheduleRetryWithReset_ClearsTimeoutAndStage_001
 * @tc.desc: Verify a scheduled retry resets the stage to IDLE and clears the
 *           callback connectId (double-path retry safety).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, ScheduleRetryWithReset_ClearsTimeoutAndStage_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ScheduleRetryWithReset_ClearsTimeoutAndStage_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::CONNECTED);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, conn)); // schedules retry

    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::IDLE);
    EXPECT_EQ(it->second.GetCallbackConnectId(), 0);
    EXPECT_EQ(it->second.GetRetryCount(), 1);
    GTEST_LOG_(INFO) << "ScheduleRetryWithReset_ClearsTimeoutAndStage_001 end";
}

/**
 * @tc.name: RemoveRetryPolicy_CancelsCallbackTimeout_001
 * @tc.desc: Verify RemoveRetryPolicy (form deletion path) erases the registered policy;
 *           pending timer tasks are cancelled inside CancelPendingTasks.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, RemoveRetryPolicy_CancelsCallbackTimeout_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveRetryPolicy_CancelsCallbackTimeout_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    EXPECT_NE(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    handler_->RemoveRetryPolicy(FORM_ID);
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "RemoveRetryPolicy_CancelsCallbackTimeout_001 end";
}

/**
 * @tc.name: ExecuteRetry_HasFormRecordGuard_001
 * @tc.desc: Verify ExecuteRetry aborts (erases policy, no connect) when the form record
 *           was deleted inside the retry connect window (existing behavior regression).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, ExecuteRetry_HasFormRecordGuard_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ExecuteRetry_HasFormRecordGuard_001 start";
    EXPECT_CALL(*mockFormDataMgr_, HasFormRecord(FORM_ID)).WillRepeatedly(Return(false));
    auto &policy = handler_->EnsureRetryPolicyLocked(FORM_ID);
    policy.SetStage(RequestStage::IDLE);
    sptr<FormAbilityConnection> conn = new TestConnection();
    handler_->ExecuteRetry(FORM_ID, conn);
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "ExecuteRetry_HasFormRecordGuard_001 end";
}

/**
 * @tc.name: CallbackLate_AfterRetry_001
 * @tc.desc: Verify an old-round callback arriving after a retry cycle does not advance
 *           the new round's policy (connectId guard across cycles).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, CallbackLate_AfterRetry_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallbackLate_AfterRetry_001 start";
    handler_->StartCallbackPending(FORM_ID, 100);
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::CONNECTED);
    EXPECT_TRUE(handler_->HandleDisconnectError(FORM_ID, conn)); // retry, stage -> IDLE

    handler_->StartCallbackPending(FORM_ID, 200); // new round
    handler_->OnCallbackArrived(FORM_ID, 100);    // old-round callback
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_EQ(it->second.GetStage(), RequestStage::WAITING_CALLBACK);
    EXPECT_EQ(it->second.GetCallbackConnectId(), 200);
    GTEST_LOG_(INFO) << "CallbackLate_AfterRetry_001 end";
}

/**
 * @tc.name: CallbackTimeout_NoPolicy_001
 * @tc.desc: Verify callback timeout without a policy is a safe no-op.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, CallbackTimeout_NoPolicy_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CallbackTimeout_NoPolicy_001 start";
    handler_->OnCallbackTimeout(FORM_ID, 100);
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "CallbackTimeout_NoPolicy_001 end";
}

/**
 * @tc.name: SignalTimeout_WaitingSendResult_Cleanup_001
 * @tc.desc: Verify OnSignalTimeout erases the policy in WAITING_SEND_RESULT
 *           (partial-signal stage, existing behavior).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, SignalTimeout_WaitingSendResult_Cleanup_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SignalTimeout_WaitingSendResult_Cleanup_001 start";
    auto &policy = handler_->EnsureRetryPolicyLocked(FORM_ID);
    policy.SetStage(RequestStage::WAITING_SEND_RESULT);
    handler_->OnSignalTimeout(FORM_ID);
    EXPECT_EQ(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    GTEST_LOG_(INFO) << "SignalTimeout_WaitingSendResult_Cleanup_001 end";
}

/**
 * @tc.name: SignalTimeout_NonPartialStages_NoOp_001
 * @tc.desc: Verify OnSignalTimeout preserves the policy for non-partial-signal stages
 *           (IDLE / CALLBACK_COMPLETED / WAITING_CALLBACK — the latter owns its own
 *           callback timeout, no signal timeout should be running).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderAcquireErrorHandlerTest, SignalTimeout_NonPartialStages_NoOp_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SignalTimeout_NonPartialStages_NoOp_001 start";
    auto &policy = handler_->EnsureRetryPolicyLocked(FORM_ID);
    for (auto stage : {RequestStage::IDLE, RequestStage::CALLBACK_COMPLETED, RequestStage::WAITING_CALLBACK}) {
        policy.SetStage(stage);
        handler_->OnSignalTimeout(FORM_ID);
        EXPECT_NE(handler_->retryPolicyMap_.find(FORM_ID), handler_->retryPolicyMap_.end());
    }
    handler_->RemoveRetryPolicy(FORM_ID);
    GTEST_LOG_(INFO) << "SignalTimeout_NonPartialStages_NoOp_001 end";
}
