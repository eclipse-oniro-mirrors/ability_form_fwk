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
#include "status_mgr_center/form_status_mgr.h"
#include "status_mgr_center/form_status.h"
#include "status_mgr_center/form_status_common.h"
#include "status_mgr_center/form_event_queue.h"
#include "status_mgr_center/form_event_retry_mgr.h"
#include "status_mgr_center/form_status.h"
#undef private
#include "fms_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t FORM_ID = 123;
class FormStatusMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormStatusMgrTest::SetUpTestCase()
{}

void FormStatusMgrTest::TearDownTestCase()
{}

void FormStatusMgrTest::SetUp()
{}

void FormStatusMgrTest::TearDown()
{}

/**
 * @tc.name: FormStatusMgrTest_0001
 * @tc.desc: Verify CancelFormEventTimeout
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_0001 start";

    int64_t formId = FORM_ID;
    std::string eventId = "123";
    FormStatusMgr::GetInstance().CancelFormEventTimeout(formId, eventId);

    GTEST_LOG_(INFO) << "FormStatusMgrTest_0001 end";
}

/**
 * @tc.name: FormStatusMgrTest_0002
 * @tc.desc: Verify PostFormEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_0002 start";

    int64_t formId = FORM_ID;
    auto task = []() { GTEST_LOG_(INFO) << "FormStatusMgrTest_0002 Task called"; };
    FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RENDER_FORM, task);
    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RENDERED);
    FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RENDER_FORM, task);
    FormStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RENDER_FORM_DONE, task);

    GTEST_LOG_(INFO) << "FormStatusMgrTest_0002 end";
}

/**
 * @tc.name: FormStatusMgrTest_0003
 * @tc.desc: Verify ExecFormTaskTimeout
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_0003 start";

    int64_t formId = FORM_ID;
    FormEventTimeout timeoutMs = FormEventTimeout::TIMEOUT_NO_NEED;
    FormFsmEvent event = FormFsmEvent::RENDER_FORM;
    FormFsmStatus status = FormFsmStatus::RENDERED;
    FormStatusMgr::GetInstance().ExecFormTaskTimeout(formId, timeoutMs, event, status);

    FormStatusMgr::GetInstance().DeleteFormEventId(formId);
    std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(formId);
    EXPECT_EQ(eventId, "");

    timeoutMs = FormEventTimeout::TIMEOUT_3_S;
    FormStatusMgr::GetInstance().ExecFormTaskTimeout(formId, timeoutMs, event, status);

    FormStatusMgr::GetInstance().SetFormEventId(formId);
    FormStatusMgr::GetInstance().ExecFormTaskTimeout(formId, timeoutMs, event, status);

    GTEST_LOG_(INFO) << "FormStatusMgrTest_0003 end";
}

/**
 * @tc.name: FormStatusMgrTest_0004
 * @tc.desc: Verify ExecFormTask
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_0004 start";

    FormFsmProcessType processType = FormFsmProcessType::PROCESS_TASK_DIRECT;
    int64_t formId = FORM_ID;
    FormFsmEvent event = FormFsmEvent::RENDER_FORM;
    auto task = []() { GTEST_LOG_(INFO) << "FormStatusMgrTest_0004 Task called"; };
    FormStatusMgr::GetInstance().ExecFormTask(processType, formId, event, task);
    processType = FormFsmProcessType::ADD_TASK_TO_QUEUE_UNIQUE;
    FormStatusMgr::GetInstance().ExecFormTask(processType, formId, event, task);
    processType = FormFsmProcessType::ADD_TASK_TO_QUEUE_PUSH;
    FormStatusMgr::GetInstance().ExecFormTask(processType, formId, event, task);
    processType = FormFsmProcessType::ADD_TASK_TO_QUEUE_DELETE;
    FormStatusMgr::GetInstance().ExecFormTask(processType, formId, event, task);
    processType = FormFsmProcessType::PROCESS_TASK_FROM_QUEUE;
    FormStatusMgr::GetInstance().ExecFormTask(processType, formId, event, task);
    processType = FormFsmProcessType::PROCESS_TASK_DELETE;
    FormStatusMgr::GetInstance().ExecFormTask(processType, formId, event, task);
    processType = FormFsmProcessType::PROCESS_TASK_RETRY;
    FormStatusMgr::GetInstance().ExecFormTask(processType, formId, event, task);
    FormStatusMgr::GetInstance().ExecFormTask(static_cast<FormFsmProcessType>(100), formId, event, task);

    GTEST_LOG_(INFO) << "FormStatusMgrTest_0004 end";
}

/**
 * @tc.name: FormStatusMgrTest_0005
 * @tc.desc: Verify ProcessTaskDirect
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_0005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_0005 start";

    int64_t formId = FORM_ID;
    FormFsmEvent event = FormFsmEvent::RENDER_FORM;
    FormStatusMgr::GetInstance().ProcessTaskDirect(formId, event, nullptr);

    auto task = []() { GTEST_LOG_(INFO) << "FormStatusMgrTest_0005 Task called"; };
    FormStatusMgr::GetInstance().ProcessTaskDirect(formId, event, task);

    GTEST_LOG_(INFO) << "FormStatusMgrTest_0005 end";
}

/**
 * @tc.name: FormStatusMgrTest_0006
 * @tc.desc: Verify FormStatusMgr
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_0006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_0006 start";

    int64_t formId = FORM_ID;
    FormFsmEvent event = FormFsmEvent::RECYCLE_FORM;
    auto task = []() { GTEST_LOG_(INFO) << "FormStatusMgrTest_0006 Task called"; };
    FormStatusMgr::GetInstance().AddTaskToQueueUnique(formId, event, task);
    std::shared_ptr<FormEventQueue> formEventQueue = FormStatusMgr::GetInstance().GetFormEventQueue(formId);
    FormEventTaskInfo taskInfo{formId, event, task};
    formEventQueue->PushFormEvent(taskInfo);
    FormStatusMgr::GetInstance().AddTaskToQueueUnique(formId, event, task);
    FormStatusMgr::GetInstance().AddTaskToQueuePush(formId, event, task);

    formEventQueue = FormStatusMgr::GetInstance().GetFormEventQueue(formId);
    while (!formEventQueue->IsEventQueueEmpty()) {
        FormEventTaskInfo eventTaskInfo{};
        if (!formEventQueue->PopFormEvent(eventTaskInfo)) {
            break;
        }
    }
    FormStatusMgr::GetInstance().AddTaskToQueueDelete(formId, event, task);
    formEventQueue->PushFormEvent(taskInfo);
    FormStatusMgr::GetInstance().AddTaskToQueueDelete(formId, event, task);

    FormStatusMgr::GetInstance().ProcessTaskFromQueue(456);
    FormStatusMgr::GetInstance().ProcessTaskFromQueue(formId);
    FormEventTaskInfo eventTaskInfo{};
    formEventQueue->PopFormEvent(eventTaskInfo);
    FormStatusMgr::GetInstance().ProcessTaskFromQueue(formId);

    FormStatusMgr::GetInstance().ProcessTaskFromRetry(formId);
    FormEventRetryMgr::GetInstance().SetRetryCount(formId, 1);
    FormStatusMgr::GetInstance().ProcessTaskFromRetry(formId);
    FormEventRetryMgr::GetInstance().SetLastFormEvent(formId, taskInfo);
    FormStatusMgr::GetInstance().ProcessTaskFromRetry(formId);

    GTEST_LOG_(INFO) << "FormStatusMgrTest_0006 end";
}

/**
 * @tc.name: FormStatusMgrTest_0007
 * @tc.desc: Verify FormStatusMgr
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_0007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_0007 start";

    int64_t formId = FORM_ID;
    FormStatusMgr::GetInstance().DeleteFormEventId(formId);
    std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(formId);
    EXPECT_EQ(eventId, "");

    FormStatusMgr::GetInstance().SetFormEventId(formId);
    eventId = FormStatusMgr::GetInstance().GetFormEventId(formId);
    FormStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormStatusMgr::GetInstance().DeleteFormEventId(formId);

    eventId = FormStatusMgr::GetInstance().GetFormEventId(formId);
    EXPECT_EQ(eventId, "");

    GTEST_LOG_(INFO) << "FormStatusMgrTest_0007 end";
}

/**
 * @tc.name: FormStatusMgrTest_ExecStatusMachineTask
 * @tc.desc: Verify ExecStatusMachineTask
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_ExecStatusMachineTask, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_ExecStatusMachineTask start";

    int64_t formId = FORM_ID;
    FormStatusMgr::GetInstance().DeleteFormEventId(formId);
    static bool result = false;
    auto task = []() {
        GTEST_LOG_(INFO) << "FormStatusMgrTest_ExecStatusMachineTask Task called zlx";
        result = true;
    };
    bool ret = FormStatusMgr::GetInstance().ExecStatusMachineTask(formId, FormFsmEvent::RENDER_FORM_DONE, task);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(result, false);

    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RENDERED);
    ret = FormStatusMgr::GetInstance().ExecStatusMachineTask(formId, FormFsmEvent::RENDER_FORM, task);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(result, true);

    GTEST_LOG_(INFO) << "FormStatusMgrTest_ExecStatusMachineTask end";
}
}  // namespace