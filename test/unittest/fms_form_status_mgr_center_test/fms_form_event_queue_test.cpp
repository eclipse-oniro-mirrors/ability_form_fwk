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
#include "status_mgr_center/form_event_queue.h"
#include "status_mgr_center/form_status_common.h"
#include "fms_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t EVENT_QUEUE_SIZE_MAX = 100;

class FormEventQueueTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormEventQueueTest::SetUpTestCase()
{}

void FormEventQueueTest::TearDownTestCase()
{}

void FormEventQueueTest::SetUp()
{}

void FormEventQueueTest::TearDown()
{}

/**
 * @tc.name: FormEventQueueTest_0001
 * @tc.desc: Verify FormEventQueue PopFormEvent and PushFormEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormEventQueueTest, FormEventQueueTest_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventQueueTest_0001 start";

    int64_t formId = 123;
    std::shared_ptr<FormEventQueue> formEventQueue = std::make_shared<FormEventQueue>(formId);
    ASSERT_NE(formEventQueue, nullptr);
    FormEventTaskInfo eventTaskInfo{};
    EXPECT_EQ(formEventQueue->IsEventQueueEmpty(), true);
    EXPECT_EQ(formEventQueue->PopFormEvent(eventTaskInfo), false);

    auto task = []() { GTEST_LOG_(INFO) << "FmsFormHostQueueTest_001 Task called"; };
    FormEventTaskInfo taskInfo{formId, FormFsmEvent::RENDER_FORM, task};
    bool ret = formEventQueue->PushFormEvent(taskInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(formEventQueue->IsEventQueueEmpty(), false);
    EXPECT_EQ(formEventQueue->PopFormEvent(eventTaskInfo), true);

    for (int i = 0; i < EVENT_QUEUE_SIZE_MAX; i++) {
        formEventQueue->PushFormEvent(taskInfo);
    }
    ret = formEventQueue->PushFormEvent(taskInfo);
    EXPECT_EQ(ret, false);

    formId = 321;
    FormEventTaskInfo eTaskInfo{formId, FormFsmEvent::RENDER_FORM, task};
    ret = formEventQueue->PushFormEvent(eTaskInfo);
    EXPECT_EQ(ret, false);

    GTEST_LOG_(INFO) << "FormEventQueueTest_0001 end";
}

/**
 * @tc.name: FormEventQueueTest_0002
 * @tc.desc: Verify FormEventTaskInfo func
 * @tc.type: FUNC
 */
HWTEST_F(FormEventQueueTest, FormEventQueueTest_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventQueueTest_0002 start";

    int64_t formId = 1;
    FormFsmEvent formEvent = FormFsmEvent::RENDER_FORM;
    auto task = []() { GTEST_LOG_(INFO) << "FormEventQueueTest_0002 Task called"; };
    FormEventTaskInfo taskInfo{formId, formEvent, task};
    taskInfo.getFunc();

    EXPECT_EQ(taskInfo.getFormId(), formId);
    EXPECT_EQ(taskInfo.getFormEvent(), formEvent);

    GTEST_LOG_(INFO) << "FormEventQueueTest_0002 end";
}
}  // namespace