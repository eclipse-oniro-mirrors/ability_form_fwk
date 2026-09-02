/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "form_memory_guard.h"
#include "fms_log_wrapper.h"
#define private public
#include "form_render_event_report.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FormRenderEventReportTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void FormRenderEventReportTest::SetUpTestCase(void)
{}

void FormRenderEventReportTest::TearDownTestCase(void)
{}

void FormRenderEventReportTest::SetUp()
{}

void FormRenderEventReportTest::TearDown()
{}

/**
 * @tc.name: FormRenderEventReportTest_SendFormFailedEvent
 * @tc.desc: Check SendFormFailedEvent Test
 * @tc.type: FUNC
 * @tc.require: issuesI9MVRJ
 */
HWTEST_F(FormRenderEventReportTest, FormRenderEventReportTest_SendFormFailedEvent, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderEventReportTest_SendFormFailedEvent begin";
    std::string bundleName = "testBundleName";
    std::string formName = "testFormName";
    FormEventName eventName = static_cast<FormEventName>(-1);
    EXPECT_EQ(FormRenderEventReport::ConvertEventName(eventName), "INVALIDEVENTNAME");
    FormRenderEventReport::SendFormFailedEvent(eventName, 0, bundleName, formName, 0, 0);

    eventName = FormEventName::RELOAD_FORM_FAILED;
    EXPECT_EQ(FormRenderEventReport::ConvertEventName(eventName), "RELOAD_FORM_FAILED");
    FormRenderEventReport::SendFormFailedEvent(eventName, 0, bundleName, formName, 0, 0);

    GTEST_LOG_(INFO) << "FormRenderEventReportTest_SendFormFailedEvent test ends";
}
} // namespace AppExecFwk
} // namespace OHOS
