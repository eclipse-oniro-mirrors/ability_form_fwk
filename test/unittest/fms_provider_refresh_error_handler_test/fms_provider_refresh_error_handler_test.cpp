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
#include "form_provider/error_handler/provider_refresh_error_handler.h"
#include "form_provider/error_handler/provider_error_handler_factory.h"
#include "common/connection/form_ability_connection.h"
#include "common/retry_policy/retry_policy.h"
#include "common/util/form_task_common.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t FORM_ID = 100;
const int32_t IPC_ERR_DEAD_OBJECT = 32;
}

// Minimal concrete FormAbilityConnection for handler tests.
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

class FmsProviderRefreshErrorHandlerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown();

protected:
    sptr<FormProviderRefreshErrorHandler> handler_;
};

void FmsProviderRefreshErrorHandlerTest::SetUp()
{
    handler_ = FormProviderErrorHandlerFactory::GetRefreshHandler();
    handler_->RemoveRetryPolicy(FORM_ID);
}

void FmsProviderRefreshErrorHandlerTest::TearDown()
{
    handler_->RemoveRetryPolicy(FORM_ID);
}

/**
 * @tc.name: GetRetryTaskType_001
 * @tc.desc: Verify refresh handler returns REFRESH_RETRY_TASK.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, GetRetryTaskType_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "GetRetryTaskType_001 start";
    EXPECT_EQ(handler_->GetRetryTaskType(), TaskType::REFRESH_RETRY_TASK);
    GTEST_LOG_(INFO) << "GetRetryTaskType_001 end";
}

/**
 * @tc.name: HandleSendRequestFailed_DeadObject_001
 * @tc.desc: Verify dead error sets sendRequestFailed and waits for disconnect (signal 1).
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, HandleSendRequestFailed_DeadObject_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleSendRequestFailed_DeadObject_001 start";
    Want want;
    EXPECT_TRUE(handler_->HandleSendRequestFailed(FORM_ID, IPC_ERR_DEAD_OBJECT, want));
    auto it = handler_->retryPolicyMap_.find(FORM_ID);
    ASSERT_NE(it, handler_->retryPolicyMap_.end());
    EXPECT_TRUE(it->second.IsSendRequestFailed());
    GTEST_LOG_(INFO) << "HandleSendRequestFailed_DeadObject_001 end";
}

/**
 * @tc.name: HandleDisconnectError_NotConnected_001
 * @tc.desc: Verify HandleDisconnectError returns false when state != CONNECTED.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, HandleDisconnectError_NotConnected_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleDisconnectError_NotConnected_001 start";
    sptr<FormAbilityConnection> conn = new TestConnection();
    conn->SetConnectState(ConnectState::DISCONNECTED);
    EXPECT_FALSE(handler_->HandleDisconnectError(FORM_ID, conn));
    GTEST_LOG_(INFO) << "HandleDisconnectError_NotConnected_001 end";
}

/**
 * @tc.name: DualSignal_SendFirst_001
 * @tc.desc: Verify dual-signal: send first → disconnect (CONNECTED) → confirmed retry.
 * @tc.type: FUNC
 * @tc.require: issueI5NQJG
 */
HWTEST_F(FmsProviderRefreshErrorHandlerTest, DualSignal_SendFirst_001, TestSize.Level1)
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
