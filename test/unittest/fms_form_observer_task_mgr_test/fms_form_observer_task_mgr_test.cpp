/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include <memory>
#include <atomic>
#define private public
#include "form_observer/form_observer_task_mgr.h"
#undef private
#include "configuration.h"
#include "js_form_state_observer_interface.h"
#include "mock_form_provider_client.h"
#include "mock_form_mgr_adapter_facade.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "queue/form_singleton_queue_base.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
// Stub override: execute task synchronously so mock facade calls are reachable
std::atomic<int32_t> g_scheduleTaskCount(0);
}

namespace OHOS {
namespace AppExecFwk {
namespace Common {
// Override FormSingletonQueueBase::ScheduleTask for unit test: run synchronously
// ponytail: link-time override via --allow-multiple-definition, no need for full queue
FormSingletonQueueBase::FormSingletonQueueBase(const std::string &queueName,
    std::shared_ptr<ITaskWrapperStrategy> strategy)
    : queueName_(queueName), serialQueue_(nullptr), strategy_(nullptr) {}

FormSingletonQueueBase::~FormSingletonQueueBase() {}

bool FormSingletonQueueBase::ScheduleTask(uint64_t ms, std::function<void()> func, TaskQos qos)
{
    g_scheduleTaskCount.fetch_add(1, std::memory_order_relaxed);
    if (func) {
        func();
    }
    return true;
}

bool FormSingletonQueueBase::ScheduleDelayTask(
    const TaskKey &taskKey, uint64_t ms, std::function<void()> func, TaskQos qos)
{
    if (func) {
        func();
    }
    return true;
}

bool FormSingletonQueueBase::CancelDelayTask(const TaskKey &taskKey)
{
    return true;
}
} // namespace Common
} // namespace AppExecFwk
} // namespace OHOS

namespace {
class FormObserverTaskMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::shared_ptr<MockFormMgrAdapterFacade> mockFacade_;
};

void FormObserverTaskMgrTest::SetUpTestCase()
{}

void FormObserverTaskMgrTest::TearDownTestCase()
{}

void FormObserverTaskMgrTest::SetUp()
{
    g_scheduleTaskCount.store(0, std::memory_order_relaxed);
    mockFacade_ = std::make_shared<MockFormMgrAdapterFacade>();
    MockFormMgrAdapterFacade::obj = mockFacade_;
}

void FormObserverTaskMgrTest::TearDown()
{
    MockFormMgrAdapterFacade::obj = nullptr;
    mockFacade_.reset();
}
}  // namespace

/**
 * @tc.name: PostBatchColorModeUpdateForms_001
 * @tc.desc: Verify PostBatchColorModeUpdateForms schedules task and calls BatchNotifyFormsColorModeUpdate
 *           with correct userId for normal user.
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, PostBatchColorModeUpdateForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PostBatchColorModeUpdateForms_001 start";

    constexpr int32_t testUserId = 100;
    AppExecFwk::Configuration configuration;
    EXPECT_CALL(*mockFacade_, BatchNotifyFormsColorModeUpdate(testUserId, testing::_))
        .Times(1)
        .WillOnce(testing::Return(ERR_OK));
    FormObserverTaskMgr::GetInstance().PostBatchColorModeUpdateForms(testUserId, configuration);
    EXPECT_EQ(g_scheduleTaskCount.load(std::memory_order_relaxed), 1);
    testing::Mock::VerifyAndClearExpectations(mockFacade_.get());

    GTEST_LOG_(INFO) << "PostBatchColorModeUpdateForms_001 end";
}

/**
 * @tc.name: PostBatchColorModeUpdateForms_002
 * @tc.desc: Verify PostBatchColorModeUpdateForms schedules task and calls BatchNotifyFormsColorModeUpdate
 *           with userId=0 (default user).
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, PostBatchColorModeUpdateForms_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "PostBatchColorModeUpdateForms_002 start";

    constexpr int32_t testUserId = 0;
    AppExecFwk::Configuration configuration;
    EXPECT_CALL(*mockFacade_, BatchNotifyFormsColorModeUpdate(testUserId, testing::_))
        .Times(1)
        .WillOnce(testing::Return(ERR_OK));
    FormObserverTaskMgr::GetInstance().PostBatchColorModeUpdateForms(testUserId, configuration);
    EXPECT_EQ(g_scheduleTaskCount.load(std::memory_order_relaxed), 1);
    testing::Mock::VerifyAndClearExpectations(mockFacade_.get());

    GTEST_LOG_(INFO) << "PostBatchColorModeUpdateForms_002 end";
}

/**
 * @tc.name: PostBatchConfigurationUpdateForms_001
 * @tc.desc: Verify PostBatchConfigurationUpdateForms schedules task and calls
 *           BatchNotifyFormsConfigurationUpdate.
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, PostBatchConfigurationUpdateForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PostBatchConfigurationUpdateForms_001 start";

    AppExecFwk::Configuration configuration;
    EXPECT_CALL(*mockFacade_, BatchNotifyFormsConfigurationUpdate(testing::_))
        .Times(1)
        .WillOnce(testing::Return(ERR_OK));
    FormObserverTaskMgr::GetInstance().PostBatchConfigurationUpdateForms(configuration);
    EXPECT_EQ(g_scheduleTaskCount.load(std::memory_order_relaxed), 1);
    testing::Mock::VerifyAndClearExpectations(mockFacade_.get());

    GTEST_LOG_(INFO) << "PostBatchConfigurationUpdateForms_001 end";
}
    