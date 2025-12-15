/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "fms_log_wrapper.h"
#define private public
#include "form_event_report.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FormFormEventReportTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void FormFormEventReportTest::SetUpTestCase(void)
{}

void FormFormEventReportTest::TearDownTestCase(void)
{}

void FormFormEventReportTest::SetUp()
{}

void FormFormEventReportTest::TearDown()
{}

/**
 * @tc.name: SendFormEvent_0100
 * @tc.desc: Check SendFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendFormEvent_0100, TestSize.Level0)
{
    FormEventName eventName = static_cast<FormEventName>(-1);
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "INVALIDEVENTNAME");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendFormEvent_0200
 * @tc.desc: Check SendFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendFormEvent_0200, TestSize.Level0)
{
    FormEventName eventName = FormEventName::DELETE_INVALID_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "DELETE_INVALID_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendFormEvent_0300
 * @tc.desc: Check SendFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendFormEvent_0300, TestSize.Level0)
{
    FormEventName eventName = FormEventName::ACQUIREFORMSTATE_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "ACQUIREFORMSTATE_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendFormEvent_0400
 * @tc.desc: Check SendFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendFormEvent_0400, TestSize.Level0)
{
    FormEventName eventName = FormEventName::MESSAGE_EVENT_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "MESSAGE_EVENT_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendFormEvent_0500
 * @tc.desc: Check SendFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendFormEvent_0500, TestSize.Level0)
{
    FormEventName eventName = FormEventName::ADD_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "ADD_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendFormEvent_0600
 * @tc.desc: Check SendFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendFormEvent_0600, TestSize.Level0)
{
    FormEventName eventName = FormEventName::ROUTE_EVENT_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "ROUTE_EVENT_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendFormEvent_0700
 * @tc.desc: Check SendFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI6D9OM
 */
HWTEST_F(FormFormEventReportTest, SendFormEvent_0700, TestSize.Level0)
{
    FormEventName eventName = FormEventName::REQUEST_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "REQUEST_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendSecondFormEvent_0100
 * @tc.desc: Check SendSecondFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendSecondFormEvent_0100, TestSize.Level0)
{
    FormEventName eventName = static_cast<FormEventName>(-1);
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "INVALIDEVENTNAME");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendSecondFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendSecondFormEvent_0200
 * @tc.desc: Check SendSecondFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendSecondFormEvent_0200, TestSize.Level0)
{
    FormEventName eventName = FormEventName::REQUEST_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "REQUEST_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendSecondFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendSecondFormEvent_0300
 * @tc.desc: Check SendSecondFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendSecondFormEvent_0300, TestSize.Level0)
{
    FormEventName eventName = FormEventName::BACKGROUND_EVENT_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "BACKGROUND_EVENT_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendSecondFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendSecondFormEvent_0400
 * @tc.desc: Check SendSecondFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendSecondFormEvent_0400, TestSize.Level0)
{
    FormEventName eventName = FormEventName::DELETE_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "DELETE_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    eventInfo.bundleName = "testBundleName";
    eventInfo.isDistributedForm = true;
    FormEventReport::SendSecondFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendSecondFormEvent_0500
 * @tc.desc: Check SendSecondFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI67H0J
 */
HWTEST_F(FormFormEventReportTest, SendSecondFormEvent_0500, TestSize.Level0)
{
    FormEventName eventName = FormEventName::CASTTEMP_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "CASTTEMP_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendSecondFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendSecondFormEvent_0600
 * @tc.desc: Check SendSecondFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI8TDOZ
 */
HWTEST_F(FormFormEventReportTest, SendSecondFormEvent_0600, TestSize.Level0)
{
    FormEventName eventName = FormEventName::RELEASE_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "RELEASE_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendSecondFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendSecondFormEvent_0700
 * @tc.desc: Check SendSecondFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI8TDOZ
 */
HWTEST_F(FormFormEventReportTest, SendSecondFormEvent_0700, TestSize.Level0)
{
    FormEventName eventName = FormEventName::SET_NEXT_REFRESH_TIME_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "SET_NEXT_REFRESH_TIME_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendSecondFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendSecondFormEvent_0800
 * @tc.desc: Check SendSecondFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI8TDOZ
 */
HWTEST_F(FormFormEventReportTest, SendSecondFormEvent_0800, TestSize.Level0)
{
    FormEventName eventName = FormEventName::FORM_RENDER_BLOCK;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "FORM_RENDER_BLOCK");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendSecondFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendSecondFormEvent_0900
 * @tc.desc: Check SendSecondFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issueI8TDOZ
 */
HWTEST_F(FormFormEventReportTest, SendSecondFormEvent_0900, TestSize.Level0)
{
    FormEventName eventName = FormEventName::ROUTE_EVENT_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "ROUTE_EVENT_FORM");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendSecondFormEvent(eventName, type, eventInfo);
}
/**
 * @tc.name: SendThirdFormEvent_0100
 * @tc.desc: Check SendThirdFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issuesI9K1NP
 */
HWTEST_F(FormFormEventReportTest, SendThirdFormEvent_0100, TestSize.Level0)
{
    FormEventName eventName = FormEventName::UNBIND_FORM_APP;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "UNBIND_FORM_APP");
    HiSysEventType type = HiSysEventType::BEHAVIOR;
    FormEventInfo eventInfo;
    FormEventReport::SendThirdFormEvent(eventName, type, eventInfo);
}

/**
 * @tc.name: SendFormFailedEvent_0100
 * @tc.desc: Check SendFormFailedEvent Test
 * @tc.type: FUNC
 * @tc.require: issuesI9K1NP
 */
HWTEST_F(FormFormEventReportTest, SendFormFailedEvent_0100, TestSize.Level0)
{
    FormEventName eventName = FormEventName::DELETE_FORM_FAILED;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "DELETE_FORM_FAILED");
    std::string bundleName = "testBundleName";
    std::string formName = "testFormName";
    FormEventReport::SendFormFailedEvent(FormEventName::DELETE_FORM_FAILED, 0, bundleName, formName, 0, 0);
}

/**
 * @tc.name: SendFormFailedEvent_0200
 * @tc.desc: Check SendFormFailedEvent Test
 * @tc.type: FUNC
 * @tc.require: issuesI9K1NP
 */
HWTEST_F(FormFormEventReportTest, SendFormFailedEvent_0200, TestSize.Level0)
{
    FormEventName eventName = FormEventName::UPDATE_FORM_FAILED;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "UPDATE_FORM_FAILED");
    std::string bundleName = "testBundleName";
    std::string formName = "testFormName";
    FormEventReport::SendFormFailedEvent(FormEventName::UPDATE_FORM_FAILED, 0, bundleName, formName, 0, 0);
}

/**
 * @tc.name: SendFormFailedEvent_0300
 * @tc.desc: Check SendFormFailedEvent Test
 * @tc.type: FUNC
 * @tc.require: issuesI9K1NP
 */
HWTEST_F(FormFormEventReportTest, SendFormFailedEvent_0300, TestSize.Level0)
{
    FormEventName eventName = FormEventName::RECYCLE_RECOVER_FORM_FAILED;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "RECYCLE_RECOVER_FORM_FAILED");
    std::string bundleName = "testBundleName";
    std::string formName = "testFormName";
    FormEventReport::SendFormFailedEvent(FormEventName::RECYCLE_RECOVER_FORM_FAILED, 0, bundleName, formName, 0, 0);
}

/**
 * @tc.name: SendFormFailedEvent_0400
 * @tc.desc: Check SendFormFailedEvent Test
 * @tc.type: FUNC
 * @tc.require: issuesI9K1NP
 */
HWTEST_F(FormFormEventReportTest, SendFormFailedEvent_0400, TestSize.Level0)
{
    FormEventName eventName = FormEventName::ADD_FORM_FAILED;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "ADD_FORM_FAILED");
    std::string bundleName = "testBundleName";
    std::string formName = "testFormName";
    FormEventReport::SendFormFailedEvent(FormEventName::ADD_FORM_FAILED, 0, bundleName, formName, 0, 0);
}

/**
 * @tc.name: SendRequestPublicFormEvent_0100
 * @tc.desc: Check SendRequestPublicFormEvent Test
 * @tc.type: FUNC
 * @tc.require: issuesI9K1NP
 */
HWTEST_F(FormFormEventReportTest, SendRequestPublicFormEvent_0100, TestSize.Level0)
{
    FormEventName eventName = FormEventName::REQUEST_PUBLIC_FORM;
    EXPECT_EQ(FormEventReport::ConvertEventName(eventName), "REQUEST_PUBLIC_FORM");
    std::string bundleName = "testBundleName";
    std::string formName = "testFormName";
    FormEventReport::SendRequestPublicFormEvent(bundleName, formName, RequestFormType::REQUEST_PUBLISH_FORM);
}
} // namespace AppExecFwk
} // namespace OHOS
