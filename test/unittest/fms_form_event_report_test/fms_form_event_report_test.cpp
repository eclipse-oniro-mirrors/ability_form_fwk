/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#include "form_event_report.h"
#include "form_event_report_define.h"
#include "form_constants.h"
#include "inner/mock_form_hisysevent_wrapper.h"
#include "inner/mock_form_file_util.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int64_t TEST_FORM_ID = 100;
constexpr int32_t TEST_ERROR_TYPE = 1;
constexpr int32_t TEST_ERROR_CODE = 200;
}

class FmsFormEventReportTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void FmsFormEventReportTest::SetUpTestCase(void)
{}

void FmsFormEventReportTest::TearDownTestCase(void)
{}

void FmsFormEventReportTest::SetUp()
{
    ResetFormHiSysEventWrapperMock();
    ResetFormFileUtilMock();
}

void FmsFormEventReportTest::TearDown()
{}

/**
 * @tc.name: ConvertEventName_001
 * @tc.desc: Verify ConvertEventName with valid event name in map.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, ConvertEventName_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ConvertEventName_001 start";
    FormEventReport report;
    std::string result = report.ConvertEventName(FormEventName::ADD_FORM);
    EXPECT_EQ(result, "ADD_FORM");
    GTEST_LOG_(INFO) << "ConvertEventName_001 end";
}

/**
 * @tc.name: ConvertEventName_002
 * @tc.desc: Verify ConvertEventName with event name not in map (LAUNCH_FORM_APP).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, ConvertEventName_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ConvertEventName_002 start";
    FormEventReport report;
    std::string result = report.ConvertEventName(FormEventName::LAUNCH_FORM_APP);
    EXPECT_EQ(result, "INVALIDEVENTNAME");
    GTEST_LOG_(INFO) << "ConvertEventName_002 end";
}

/**
 * @tc.name: SendFormEvent_001
 * @tc.desc: Verify SendFormEvent with invalid event name returns early (no write).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormEvent_001 start";
    FormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    FormEventReport::SendFormEvent(FormEventName::LAUNCH_FORM_APP, HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 0);
    GTEST_LOG_(INFO) << "SendFormEvent_001 end";
}

/**
 * @tc.name: SendFormEvent_002
 * @tc.desc: Verify SendFormEvent with DELETE_INVALID_FORM calls WriteEvent.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormEvent_002 start";
    FormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    FormEventReport::SendFormEvent(FormEventName::DELETE_INVALID_FORM, HiSysEventType::FAULT, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "DELETE_INVALID_FORM");
    GTEST_LOG_(INFO) << "SendFormEvent_002 end";
}

/**
 * @tc.name: SendFormEvent_003
 * @tc.desc: Verify SendFormEvent with ADD_FORM calls builder Write.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormEvent_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SendFormEvent_003 start";
    FormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    eventInfo.bundleName = "com.test.bundle";
    eventInfo.moduleName = "entry";
    eventInfo.abilityName = "MainAbility";
    eventInfo.hostBundleName = "com.host.bundle";
    FormEventReport::SendFormEvent(FormEventName::ADD_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteDomain(), "FORM_MANAGER");
    EXPECT_EQ(GetLastWriteEventName(), "ADD_FORM");
    GTEST_LOG_(INFO) << "SendFormEvent_003 end";
}

/**
 * @tc.name: SendFormFailedEvent_001
 * @tc.desc: Verify SendFormFailedEvent(6-param) with invalid event name returns early.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormFailedEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormFailedEvent_001 start";
    FormEventReport::SendFormFailedEvent(FormEventName::LAUNCH_FORM_APP, TEST_FORM_ID,
        "com.test.bundle", "formName", TEST_ERROR_TYPE, TEST_ERROR_CODE);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 0);
    GTEST_LOG_(INFO) << "SendFormFailedEvent_001 end";
}

/**
 * @tc.name: SendFormFailedEvent_002
 * @tc.desc: Verify SendFormFailedEvent(6-param) with ADD_FORM_FAILED writes FORM_ERROR event.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormFailedEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormFailedEvent_002 start";
    FormEventReport::SendFormFailedEvent(FormEventName::ADD_FORM_FAILED, TEST_FORM_ID,
        "com.test.bundle", "formName", TEST_ERROR_TYPE, TEST_ERROR_CODE);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteDomain(), "FORM_MANAGER");
    EXPECT_EQ(GetLastWriteEventName(), "FORM_ERROR");
    GTEST_LOG_(INFO) << "SendFormFailedEvent_002 end";
}

/**
 * @tc.name: SendDiskUseEvent_001
 * @tc.desc: Verify SendDiskUseEvent when GetDirFiles returns empty (early return).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendDiskUseEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendDiskUseEvent_001 start";
    std::vector<std::string> emptyFiles;
    MockGetDirFilesResult(emptyFiles);
    FormEventReport::SendDiskUseEvent();
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 0);
    GTEST_LOG_(INFO) << "SendDiskUseEvent_001 end";
}

/**
 * @tc.name: SendDiskUseEvent_002
 * @tc.desc: Verify SendDiskUseEvent when GetDirFiles returns non-empty files.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendDiskUseEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendDiskUseEvent_002 start";
    std::vector<std::string> files = {"/data/file1", "/data/file2"};
    MockGetDirFilesResult(files);
    MockGetFilesSizeResult(2048);
    FormEventReport::SendDiskUseEvent();
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteDomain(), "FILEMANAGEMENT");
    EXPECT_EQ(GetLastWriteEventName(), "USER_DATA_SIZE");
    GTEST_LOG_(INFO) << "SendDiskUseEvent_002 end";
}

/**
 * @tc.name: SendFormRefreshCountEvent_001
 * @tc.desc: Verify SendFormRefreshCountEvent with invalid event name returns early.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormRefreshCountEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormRefreshCountEvent_001 start";
    NewFormEventInfo eventInfo;
    FormEventReport::SendFormRefreshCountEvent(FormEventName::LAUNCH_FORM_APP,
        HiSysEventType::STATISTIC, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 0);
    GTEST_LOG_(INFO) << "SendFormRefreshCountEvent_001 end";
}

/**
 * @tc.name: SendFormRefreshCountEvent_002
 * @tc.desc: Verify SendFormRefreshCountEvent with UPDATE_FORM_REFRESH_TIMES writes event.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormRefreshCountEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormRefreshCountEvent_002 start";
    NewFormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    eventInfo.bundleName = "com.test.bundle";
    eventInfo.moduleName = "entry";
    eventInfo.formName = "formName";
    FormEventReport::SendFormRefreshCountEvent(FormEventName::UPDATE_FORM_REFRESH_TIMES,
        HiSysEventType::STATISTIC, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteDomain(), "FORM_MANAGER");
    EXPECT_EQ(GetLastWriteEventName(), "UPDATE_FORM_REFRESH_TIMES");
    GTEST_LOG_(INFO) << "SendFormRefreshCountEvent_002 end";
}

/**
 * @tc.name: SendFormFwkUEEvent_001
 * @tc.desc: Verify SendFormFwkUEEvent with ADD_DISTRIBUTED_FORM writes UE event.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormFwkUEEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormFwkUEEvent_001 start";
    FormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    eventInfo.bundleName = "com.test.bundle";
    eventInfo.moduleName = "entry";
    FormEventReport::SendFormFwkUEEvent(FormEventName::ADD_DISTRIBUTED_FORM, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteDomain(), "FORM_FWK_UE");
    EXPECT_EQ(GetLastWriteEventName(), "ADD_DISTRIBUTED_FORM");
    GTEST_LOG_(INFO) << "SendFormFwkUEEvent_001 end";
}

/**
 * @tc.name: SendFormFwkUEEvent_002
 * @tc.desc: Verify SendFormFwkUEEvent with non-UE event name returns early (no write).
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormFwkUEEvent_002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "SendFormFwkUEEvent_002 start";
    FormEventInfo eventInfo;
    FormEventReport::SendFormFwkUEEvent(FormEventName::LAUNCH_FORM_APP, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 0);
    GTEST_LOG_(INFO) << "SendFormFwkUEEvent_002 end";
}

/**
 * @tc.name: SendFormEvent_004
 * @tc.desc: Verify SendFormEvent with ACQUIREFORMSTATE_FORM calls builder Write.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormEvent_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormEvent_004 start";
    FormEventInfo eventInfo;
    eventInfo.bundleName = "com.test.bundle";
    eventInfo.moduleName = "entry";
    eventInfo.abilityName = "MainAbility";
    FormEventReport::SendFormEvent(FormEventName::ACQUIREFORMSTATE_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "ACQUIREFORMSTATE_FORM");
    GTEST_LOG_(INFO) << "SendFormEvent_004 end";
}

/**
 * @tc.name: SendFormEvent_005
 * @tc.desc: Verify SendFormEvent with ROUTE_EVENT_FORM calls builder Write.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormEvent_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormEvent_005 start";
    FormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    eventInfo.bundleName = "com.test.bundle";
    eventInfo.moduleName = "entry";
    eventInfo.abilityName = "MainAbility";
    eventInfo.hostBundleName = "com.host.bundle";
    eventInfo.uri = "route://test";
    eventInfo.formLocation = 1;
    FormEventReport::SendFormEvent(FormEventName::ROUTE_EVENT_FORM, HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "ROUTE_EVENT_FORM");
    GTEST_LOG_(INFO) << "SendFormEvent_005 end";
}

/**
 * @tc.name: SendSecondFormEvent_001
 * @tc.desc: Verify SendSecondFormEvent with invalid event name returns early.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendSecondFormEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendSecondFormEvent_001 start";
    FormEventInfo eventInfo;
    FormEventReport::SendSecondFormEvent(FormEventName::LAUNCH_FORM_APP,
        HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 0);
    GTEST_LOG_(INFO) << "SendSecondFormEvent_001 end";
}

/**
 * @tc.name: SendSecondFormEvent_002
 * @tc.desc: Verify SendSecondFormEvent with DELETE_FORM writes event with host bundle name.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendSecondFormEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendSecondFormEvent_002 start";
    FormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    eventInfo.bundleName = "com.test.bundle";
    eventInfo.hostBundleName = "com.host.bundle";
    eventInfo.moduleName = "entry";
    FormEventReport::SendSecondFormEvent(FormEventName::DELETE_FORM,
        HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "DELETE_FORM");
    GTEST_LOG_(INFO) << "SendSecondFormEvent_002 end";
}

/**
 * @tc.name: SendThirdFormEvent_001
 * @tc.desc: Verify SendThirdFormEvent with UNBIND_FORM_APP writes event with timestamp and pid.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendThirdFormEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendThirdFormEvent_001 start";
    FormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    eventInfo.bundleName = "com.test.bundle";
    eventInfo.timeStamp = 1000;
    eventInfo.formAppPid = 2000;
    FormEventReport::SendThirdFormEvent(FormEventName::UNBIND_FORM_APP,
        HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "UNBIND_FORM_APP");
    GTEST_LOG_(INFO) << "SendThirdFormEvent_001 end";
}

/**
 * @tc.name: SendFormFailedEvent_003
 * @tc.desc: Verify SendFormFailedEvent(3-param) with INIT_FMS_FAILED writes event.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFormFailedEvent_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFormFailedEvent_003 start";
    FormEventReport::SendFormFailedEvent(FormEventName::INIT_FMS_FAILED,
        HiSysEventType::FAULT, TEST_ERROR_TYPE);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "INIT_FMS_FAILED");
    GTEST_LOG_(INFO) << "SendFormFailedEvent_003 end";
}

/**
 * @tc.name: SendFirstAddFormEvent_001
 * @tc.desc: Verify SendFirstAddFormEvent with FIRST_ADD_FORM_DURATION writes event.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFirstAddFormEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFirstAddFormEvent_001 start";
    NewFormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    eventInfo.bundleName = "com.test.bundle";
    eventInfo.sessionId = 100;
    eventInfo.bindDuration = 50;
    eventInfo.getDuration = 30;
    FormEventReport::SendFirstAddFormEvent(FormEventName::FIRST_ADD_FORM_DURATION,
        HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "FIRST_ADD_FORM_DURATION");
    GTEST_LOG_(INFO) << "SendFirstAddFormEvent_001 end";
}

/**
 * @tc.name: SendFourthFormEvent_001
 * @tc.desc: Verify SendFourthFormEvent with PROXY_UPDATE_FORM writes event.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFourthFormEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFourthFormEvent_001 start";
    NewFormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    eventInfo.bundleName = "com.test.bundle";
    Want want;
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, "entry");
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, "formName");
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, 2);
    FormEventReport::SendFourthFormEvent(FormEventName::PROXY_UPDATE_FORM,
        HiSysEventType::BEHAVIOR, eventInfo, want);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "PROXY_UPDATE_FORM");
    GTEST_LOG_(INFO) << "SendFourthFormEvent_001 end";
}

/**
 * @tc.name: SendFourthFormEvent_002
 * @tc.desc: Verify SendFourthFormEvent with INVALID_PUBLISH_FORM_TO_HOST writes event.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFourthFormEvent_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFourthFormEvent_002 start";
    NewFormEventInfo eventInfo;
    eventInfo.isDistributedForm = false;
    Want want;
    want.SetParam(Constants::PARAM_CALLER_BUNDLE_NAME_KEY, "com.caller.bundle");
    want.SetParam(Constants::PARAM_FORM_HOST_BUNDLENAME_KEY, "com.host.bundle");
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, "entry");
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, "formName");
    FormEventReport::SendFourthFormEvent(FormEventName::INVALID_PUBLISH_FORM_TO_HOST,
        HiSysEventType::FAULT, eventInfo, want);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "INVALID_PUBLISH_FORM_TO_HOST");
    GTEST_LOG_(INFO) << "SendFourthFormEvent_002 end";
}

/**
 * @tc.name: SendFirstUpdateFormEvent_001
 * @tc.desc: Verify SendFirstUpdateFormEvent with FIRST_UPDATE_FORM_DURATION writes event.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendFirstUpdateFormEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendFirstUpdateFormEvent_001 start";
    NewFormEventInfo eventInfo;
    eventInfo.formId = TEST_FORM_ID;
    eventInfo.sessionId = 200;
    eventInfo.duration = 80;
    eventInfo.durationType = 1;
    FormEventReport::SendFirstUpdateFormEvent(FormEventName::FIRST_UPDATE_FORM_DURATION,
        HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "FIRST_UPDATE_FORM_DURATION");
    GTEST_LOG_(INFO) << "SendFirstUpdateFormEvent_001 end";
}

/**
 * @tc.name: SendConditonUpdateFormEvent_001
 * @tc.desc: Verify SendConditonUpdateFormEvent with CONDITION_UPDATE_FORM writes event.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormEventReportTest, SendConditonUpdateFormEvent_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "SendConditonUpdateFormEvent_001 start";
    NewFormEventInfo eventInfo;
    eventInfo.conditionType = 2;
    eventInfo.bundleAndFormName = "com.test.bundle:formName";
    FormEventReport::SendConditonUpdateFormEvent(FormEventName::CONDITION_UPDATE_FORM,
        HiSysEventType::BEHAVIOR, eventInfo);
    EXPECT_EQ(GetFormHiSysEventWrapperWriteCount(), 1);
    EXPECT_EQ(GetLastWriteEventName(), "CONDITION_UPDATE_FORM");
    GTEST_LOG_(INFO) << "SendConditonUpdateFormEvent_001 end";
}
