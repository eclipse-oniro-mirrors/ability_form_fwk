/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define private public
#include "status_mgr_center/form_event_timeout_queue.h"
#undef private
#include "status_mgr_center/form_status_common.h"
#include "common/util/form_serial_queue.h"
#include "fms_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormEventTimeoutQueueTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormEventTimeoutQueueTest::SetUpTestCase()
{}

void FormEventTimeoutQueueTest::TearDownTestCase()
{}

void FormEventTimeoutQueueTest::SetUp()
{}

void FormEventTimeoutQueueTest::TearDown()
{}

/**
 * @tc.name: FormEventTimeoutQueueTest_0001
 * @tc.desc: Verify ScheduleTask
 * @tc.type: FUNC
 */
HWTEST_F(FormEventTimeoutQueueTest, FormEventTimeoutQueueTest_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventTimeoutQueueTest_0001 start";

    std::shared_ptr<FormEventTimeoutQueue> queue = std::make_shared<FormEventTimeoutQueue>();
    auto task = []() { GTEST_LOG_(INFO) << "FormEventTimeoutQueueTest_0001 Task called"; };
    queue->serialQueue_ = nullptr;
    EXPECT_EQ(false, queue->ScheduleTask(0, task));
    std::string timeoutQueue = "FormEventTimeoutQueue";
    queue->serialQueue_ = std::make_shared<FormSerialQueue>(timeoutQueue.c_str());
    EXPECT_EQ(true, queue->ScheduleTask(0, task));

    GTEST_LOG_(INFO) << "FormEventTimeoutQueueTest_0001 end";
}

/**
 * @tc.name: FormEventTimeoutQueueTest_0002
 * @tc.desc: Verify ScheduleDelayTask
 * @tc.type: FUNC
 */
HWTEST_F(FormEventTimeoutQueueTest, FormEventTimeoutQueueTest_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventTimeoutQueueTest_0002 start";

    std::shared_ptr<FormEventTimeoutQueue> queue = std::make_shared<FormEventTimeoutQueue>();
    auto task = []() { GTEST_LOG_(INFO) << "FormEventTimeoutQueueTest_0002 Task called"; };
    int64_t msg = 1;
    std::string eventId = "123";
    queue->serialQueue_ = nullptr;
    queue->ScheduleDelayTask(std::make_pair(msg, eventId), 0, task);

    std::string timeoutQueue = "FormEventTimeoutQueue";
    queue->serialQueue_ = std::make_shared<FormSerialQueue>(timeoutQueue.c_str());
    queue->ScheduleDelayTask(std::make_pair(msg, eventId), 0, task);

    GTEST_LOG_(INFO) << "FormEventTimeoutQueueTest_0002 end";
}

/**
 * @tc.name: FormEventTimeoutQueueTest_0003
 * @tc.desc: Verify CancelDelayTask
 * @tc.type: FUNC
 */
HWTEST_F(FormEventTimeoutQueueTest, FormEventTimeoutQueueTest_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventTimeoutQueueTest_0003 start";

    std::shared_ptr<FormEventTimeoutQueue> queue = std::make_shared<FormEventTimeoutQueue>();
    auto task = []() { GTEST_LOG_(INFO) << "FormEventTimeoutQueueTest_0003 Task called"; };
    int64_t msg = 1;
    std::string eventId = "123";
    queue->serialQueue_ = nullptr;
    queue->CancelDelayTask(std::make_pair(msg, eventId));

    std::string timeoutQueue = "FormEventTimeoutQueue";
    queue->serialQueue_ = std::make_shared<FormSerialQueue>(timeoutQueue.c_str());
    queue->CancelDelayTask(std::make_pair(msg, eventId));

    GTEST_LOG_(INFO) << "FormEventTimeoutQueueTest_0003 end";
}
}  // namespace