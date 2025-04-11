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
#include "common/util/form_report.h"
#include "want.h"
#include "common/event/form_event_report.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const std::string BUNDLE = "test_bundle";
const std::string ABILITY = "test_ability";
const std::string MODULENAME = "test_modulename";
int64_t FORMID = 12345;

class FormReportTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

    FormReport& formReport = FormReport::GetInstance();
    Want want;
    int64_t testFormId = FORMID;
};

void FormReportTest::SetUp()
{
    OHOS::AppExecFwk::ElementName element;
    element.SetBundleName(BUNDLE);
    element.SetAbilityName(ABILITY);
    element.SetModuleName(MODULENAME);
    want.SetElement(element);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, MODULENAME);
    want.SetParam(Constants::PARAM_ABILITY_NAME_KEY, ABILITY);
}

void FormReportTest::TearDown()
{
    formReport.GetStatistic().clear();
}

/**
 * @tc.name: FormReport_001
 * @tc.desc: test SetFormRecordInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_001, TestSize.Level1)
{
    formReport.SetFormRecordInfo(testFormId, want);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    ASSERT_NE(statisticIt, formReport.GetStatistic().end());
    FormStatistic &statistic = statisticIt->second;
    EXPECT_EQ(statistic.bundleName_, BUNDLE);
    EXPECT_EQ(statistic.moduleName_, MODULENAME);
    EXPECT_EQ(statistic.abilityName_, ABILITY);
}

/**
 * @tc.name: FormReport_002
 * @tc.desc: test SetStartGetTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_002, TestSize.Level1)
{
    int64_t startTime = 1000;
    formReport.SetStartGetTime(testFormId, startTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
    EXPECT_EQ(statisticIt->second.startGetTime_, startTime);
}

/**
 * @tc.name: FormReport_003
 * @tc.desc: test SetEndGetTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_003, TestSize.Level1)
{
    int64_t endTime = 2000;
    formReport.SetEndGetTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_EQ(statisticIt, formReport.GetStatistic().end());
}

/**
 * @tc.name: FormReport_004
 * @tc.desc: test SetStartGetTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_004, TestSize.Level1)
{
    int64_t endTime = 2000;
    int64_t startTime = 1000;
    formReport.SetStartGetTime(testFormId, startTime);
    formReport.SetEndGetTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
    EXPECT_EQ(statisticIt->second.endGetTime_, endTime);
}

/**
 * @tc.name: FormReport_005
 * @tc.desc: test SetStartGetTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_005, TestSize.Level1)
{
    int64_t endTime = 12 * 1000;
    int64_t startTime = 1* 1000;
    formReport.SetDurationStartTime(testFormId, startTime);
    formReport.SetDurationEndTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
}

/**
 * @tc.name: FormReport_006
 * @tc.desc: test SetDurationStartTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_006, TestSize.Level1)
{
    int64_t startTime = 1* 1000;
    formReport.SetDurationStartTime(testFormId, startTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
    EXPECT_EQ(statisticIt->second.durationStartTime_, startTime);
}

/**
 * @tc.name: FormReport_007
 * @tc.desc: test SetDurationEndTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_007, TestSize.Level1)
{
    int64_t endTime = 12 * 1000;
    formReport.SetDurationEndTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_EQ(statisticIt, formReport.GetStatistic().end());
}

/**
 * @tc.name: FormReport_008
 * @tc.desc: test SetStartAquireTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_008, TestSize.Level1)
{
    int64_t startTime = 1000;
    formReport.SetStartAquireTime(testFormId, startTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
    EXPECT_EQ(statisticIt->second.startAquireTime_, startTime);
}

/**
 * @tc.name: FormReport_009
 * @tc.desc: test SetEndAquireTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_009, TestSize.Level1)
{
    int64_t endTime = 1000;
    formReport.SetEndAquireTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_EQ(statisticIt, formReport.GetStatistic().end());
}

/**
 * @tc.name: FormReport_010
 * @tc.desc: test SetDurationEndTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_010, TestSize.Level1)
{
    int64_t endTime = 10 * 1000;
    int64_t endTime1 = 0;
    int64_t startTime = 1000;
    formReport.SetStartAquireTime(testFormId, startTime);
    formReport.SetEndAquireTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
    formReport.GetEndAquireTime(testFormId, endTime1);
    EXPECT_EQ(endTime1, endTime);
}

/**
 * @tc.name: FormReport_011
 * @tc.desc: test SetEndAquireTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_011, TestSize.Level1)
{
    int64_t startTime = 1000;
    formReport.SetStartBindTime(testFormId, startTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
    EXPECT_EQ(statisticIt->second.startBindTime_, startTime);
}

/**
 * @tc.name: FormReport_012
 * @tc.desc: test SetEndAquireTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_012, TestSize.Level1)
{
    int64_t endTime = 10 * 1000;
    formReport.SetEndBindTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_EQ(statisticIt, formReport.GetStatistic().end());
}

/**
 * @tc.name: FormReport_013
 * @tc.desc: test SetEndBindTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_013, TestSize.Level1)
{
    int64_t endTime = 10 * 1000;
    int64_t startTime = 1000;
    formReport.SetStartBindTime(testFormId, startTime);
    formReport.SetEndBindTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
    EXPECT_EQ(statisticIt->second.endBindTime_, endTime);
}

/**
 * @tc.name: FormReport_014
 * @tc.desc: test HandleAddFormStatistic function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_014, TestSize.Level1)
{
    formReport.SetFormRecordInfo(testFormId, want);
    formReport.HandleAddFormStatistic(testFormId);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
}

/**
 * @tc.name: FormReport_015
 * @tc.desc: test HandleAddFormStatistic function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_015, TestSize.Level1)
{
    formReport.SetFormRecordInfo(testFormId, want);
    formReport.InsertFormId(testFormId);
    formReport.HandleAddFormStatistic(testFormId);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
}

/**
 * @tc.name: FormReport_016
 * @tc.desc: test GetAddFormFinish function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_016, TestSize.Level1)
{
    formReport.SetFormRecordInfo(testFormId, want);
    formReport.InsertFormId(testFormId);
    bool addFormFinish;
    formReport.GetAddFormFinish(testFormId, addFormFinish);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
}

/**
 * @tc.name: FormReport_017
 * @tc.desc: test SetAddFormFinish function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_017, TestSize.Level1)
{
    formReport.SetFormRecordInfo(testFormId, want);
    formReport.InsertFormId(testFormId);
    formReport.SetAddFormFinish(testFormId);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    EXPECT_NE(statisticIt, formReport.GetStatistic().end());
}
} // namespace
