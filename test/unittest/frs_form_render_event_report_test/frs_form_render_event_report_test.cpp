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
 * @tc.name: SendPerformanceEvent_001
 * @tc.desc: Check SendPerformanceEvent Test
 * @tc.type: FUNC
 * @tc.require: issuesI9MVRJ
 */
HWTEST_F(FormRenderEventReportTest, SendPerformanceEvent_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SendPerformanceEvent_001 begin";
    PerformanceEventInfo eventInfo;
    eventInfo.timeStamp = 123456789;
    eventInfo.bundleName = "com.ohos.test.example";
    eventInfo.sceneId = "1";
    FormRenderEventReport::SendPerformanceEvent(SceneType::CPU_SCENE_ENTRY, eventInfo);
    GTEST_LOG_(INFO) << "SendPerformanceEvent_001 test ends";
}

/**
 * @tc.name: SendPerformanceEvent_001
 * @tc.desc: Check SendPerformanceEvent Test
 * @tc.type: FUNC
 * @tc.require: issuesI9MVRJ
 */
HWTEST_F(FormRenderEventReportTest, SendBlockFaultEvent_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SendBlockFaultEvent_001 begin";
    pid_t processId = 1;
    pid_t jsThreadId = 1;
    std::string bundleName = "com.ohos.test.example";
    FormRenderEventReport::SendBlockFaultEvent(processId, jsThreadId, bundleName);
    GTEST_LOG_(INFO) << "SendBlockFaultEvent_001 test ends";
}
} // namespace AppExecFwk
} // namespace OHOS
