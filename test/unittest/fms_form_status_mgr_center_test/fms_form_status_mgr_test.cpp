/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "util/form_status_common.h"
#include "status_mgr_center/form_event_queue.h"
#include "status_mgr_center/form_event_retry_mgr.h"
#include "status_mgr_center/form_status.h"
#undef private
#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"
#include "util/form_status_print.h"

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
    FormStatus::GetInstance().DeleteFormStatus(formId);
    bool result = false;
    auto task = [&result]() mutable {
        GTEST_LOG_(INFO) << "FormStatusMgrTest_ExecStatusMachineTask Task called";
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

/**
 * @tc.name: FormStatusMgrTest_FormStatusToString
 * @tc.desc: Verify FormStatusToString
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_FormStatusToString, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_FormStatusToString start";
 
    std::string status = FormStatusPrint::FormStatusToString(FormFsmStatus::INIT).c_str();
    EXPECT_EQ(status, "[INIT]");
 
    GTEST_LOG_(INFO) << "FormStatusMgrTest_FormStatusToString end";
}
 
/**
 * @tc.name: FormStatusMgrTest_FormEventToString
 * @tc.desc: Verify FormEventToString
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_FormEventToString, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_FormEventToString start";
 
    std::string event = FormStatusPrint::FormEventToString(FormFsmEvent::RENDER_FORM).c_str();
    EXPECT_EQ(event, "[RENDER_FORM]");
 
    GTEST_LOG_(INFO) << "FormStatusMgrTest_FormEventToString end";
}

/**
 * @tc.name: FormStatusMgrTest_ReportStatusInfoError
 * @tc.desc: Verify ReportStatusInfoError func
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusMgrTest, FormStatusMgrTest_ReportStatusInfoError, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusMgrTest_ReportStatusInfoError start";

    int64_t formId = 1;
    FormFsmStatus status = FormFsmStatus::RENDERED;
    FormFsmEvent event = FormFsmEvent::RENDER_FORM;
    FormDataMgr::GetInstance().DeleteFormRecord(formId);

    bool ret = FormStatusMgr::GetInstance().ReportStatusInfoError(formId, status, event);
    EXPECT_EQ(ret, false);

    FormItemInfo formInfo;
    formInfo.SetFormId(formId);
    formInfo.SetProviderBundleName("bundleName");
    formInfo.SetFormName("formName");
    FormRecord formRecord = FormDataMgr::GetInstance().AllotFormRecord(formInfo, 100, 100);
    EXPECT_EQ(formId, formRecord.formId);
    ret = FormStatusMgr::GetInstance().ReportStatusInfoError(formId, status, event);
    EXPECT_EQ(ret, true);

    GTEST_LOG_(INFO) << "FormStatusMgrTest_ReportStatusInfoError end";
}
}  // namespace