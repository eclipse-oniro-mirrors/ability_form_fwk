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
#include "status_mgr_center/form_render_status_mgr.h"
#include "status_mgr_center/form_render_status.h"
#include "status_mgr_center/form_status_common.h"
#include "status_mgr_center/form_render_status_table.h"
#undef private
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormRenderStatusMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormRenderStatusMgrTest::SetUpTestCase()
{}

void FormRenderStatusMgrTest::TearDownTestCase()
{}

void FormRenderStatusMgrTest::SetUp()
{}

void FormRenderStatusMgrTest::TearDown()
{}

/**
 * @tc.name: FormRenderStatusMgrTest_0001
 * @tc.desc: Verify PostFormEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusMgrTest, FormRenderStatusMgrTest_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0001 start";

    int64_t formId = 123;
    auto task = []() {
        GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0001 Task called";
        return 0;
    };
    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RENDER_FORM, task);
    FormRenderStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RENDERED);
    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, FormFsmEvent::RENDER_FORM, task);

    GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0001 end";
}

/**
 * @tc.name: FormRenderStatusMgrTest_0002
 * @tc.desc: Verify ExecFormTask
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusMgrTest, FormRenderStatusMgrTest_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0002 start";

    FormFsmProcessType processType = FormFsmProcessType::PROCESS_TASK_DIRECT;
    int64_t formId = 123;
    FormFsmEvent event = FormFsmEvent::RENDER_FORM;
    FormFsmStatus status = FormFsmStatus::RENDERED;
    auto task = []() {
        GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0002 Task called";
        return 0;
    };
    int32_t ret = FormRenderStatusMgr::GetInstance().ExecFormTask(processType, formId, event, status, task);
    EXPECT_EQ(ret, 0);
    processType = FormFsmProcessType::PROCESS_TASK_DELETE;
    ret = FormRenderStatusMgr::GetInstance().ExecFormTask(processType, formId, event, status, task);
    EXPECT_EQ(ret, 0);
    ret = FormRenderStatusMgr::GetInstance().ExecFormTask(
        static_cast<FormFsmProcessType>(100), formId, event, status, task);
    EXPECT_EQ(ret, -1);

    GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0002 end";
}

/**
 * @tc.name: FormRenderStatusMgrTest_0003
 * @tc.desc: Verify ProcessTaskDirect ProcessTaskDelete and PrintTaskInfo
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusMgrTest, FormRenderStatusMgrTest_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0003 start";

    int64_t formId = 123;
    FormFsmEvent event = FormFsmEvent::RENDER_FORM;
    FormFsmStatus status = FormFsmStatus::RENDERED;
    auto task = []() {
        GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0003 Task called";
        return 0;
    };
    int32_t ret = FormRenderStatusMgr::GetInstance().ProcessTaskDirect(task);
    EXPECT_EQ(ret, 0);
    ret = FormRenderStatusMgr::GetInstance().ProcessTaskDelete(formId);
    EXPECT_EQ(ret, 0);
    ret = FormRenderStatusMgr::GetInstance().PrintTaskInfo(formId, event, status);
    EXPECT_EQ(ret, -1);

    GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0003 end";
}

/**
 * @tc.name: FormRenderStatusMgrTest_0004
 * @tc.desc: Verify GetFormEventId SetFormEventId and DeleteFormEventId
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusMgrTest, FormRenderStatusMgrTest_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0004 start";

    int64_t formId = 123;
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    std::string eventId = FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    EXPECT_EQ(eventId, "");

    eventId = "eventId";
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    eventId = "eventIdNew";
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    eventId = FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    EXPECT_EQ(eventId, "eventIdNew");

    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    eventId = FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    EXPECT_EQ(eventId, "");

    GTEST_LOG_(INFO) << "FormRenderStatusMgrTest_0004 end";
}
}  // namespace