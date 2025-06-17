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
#include "status_mgr_center/form_status_queue.h"
#include "status_mgr_center/form_status_common.h"
#include "common/util/form_serial_queue.h"
#undef private
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormStatusQueueTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormStatusQueueTest::SetUpTestCase()
{}

void FormStatusQueueTest::TearDownTestCase()
{}

void FormStatusQueueTest::SetUp()
{}

void FormStatusQueueTest::TearDown()
{}

/**
 * @tc.name: FormStatusQueueTest_ScheduleTask
 * @tc.desc: Verify ScheduleTask
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusQueueTest, FormStatusQueueTest_ScheduleTask, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusQueueTest_ScheduleTask start";

    std::shared_ptr<FormStatusQueue> queue = std::make_shared<FormStatusQueue>();
    auto task = []() { GTEST_LOG_(INFO) << "FormStatusQueueTest_ScheduleTask Task called"; };
    queue->serialQueue_ = nullptr;
    EXPECT_EQ(false, queue->ScheduleTask(0, task));
    std::string statusQueue = "FormStatusQueue";
    queue->serialQueue_ = std::make_shared<FormSerialQueue>(statusQueue.c_str());
    EXPECT_EQ(true, queue->ScheduleTask(0, task));

    GTEST_LOG_(INFO) << "FormStatusQueueTest_ScheduleTask end";
}

/**
 * @tc.name: FormStatusQueueTest_ScheduleDelayTask
 * @tc.desc: Verify ScheduleDelayTask
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusQueueTest, FormStatusQueueTest_ScheduleDelayTask, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusQueueTest_ScheduleDelayTask start";

    std::shared_ptr<FormStatusQueue> queue = std::make_shared<FormStatusQueue>();
    auto task = []() { GTEST_LOG_(INFO) << "FormStatusQueueTest_ScheduleDelayTask Task called"; };
    int64_t msg = 1;
    int64_t eventId = 123;
    queue->serialQueue_ = nullptr;
    queue->ScheduleDelayTask(std::make_pair(msg, eventId), 0, task);

    std::string statusQueue = "FormStatusQueue";
    queue->serialQueue_ = std::make_shared<FormSerialQueue>(statusQueue.c_str());
    queue->ScheduleDelayTask(std::make_pair(msg, eventId), 0, task);

    GTEST_LOG_(INFO) << "FormStatusQueueTest_ScheduleDelayTask end";
}

/**
 * @tc.name: FormStatusQueueTest_CancelDelayTask
 * @tc.desc: Verify CancelDelayTask
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusQueueTest, FormStatusQueueTest_CancelDelayTask, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusQueueTest_CancelDelayTask start";

    std::shared_ptr<FormStatusQueue> queue = std::make_shared<FormStatusQueue>();
    auto task = []() { GTEST_LOG_(INFO) << "FormStatusQueueTest_CancelDelayTask Task called"; };
    int64_t msg = 1;
    int64_t eventId = 123;
    queue->serialQueue_ = nullptr;
    queue->CancelDelayTask(std::make_pair(msg, eventId));

    std::string statusQueue = "FormStatusQueue";
    queue->serialQueue_ = std::make_shared<FormSerialQueue>(statusQueue.c_str());
    queue->CancelDelayTask(std::make_pair(msg, eventId));

    GTEST_LOG_(INFO) << "FormStatusQueueTest_CancelDelayTask end";
}
}  // namespace