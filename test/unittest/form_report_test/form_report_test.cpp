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
#include "form_report.h"
#include "want.h"

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
 * @tc.name: FormReport_001
 * @tc.desc: test SetStartGetTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_002, TestSize.Level1)
{
    float startTime = 1000.0f;
    formReport.SetStartGetTime(testFormId, startTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    ASSERT_NE(statisticIt, formReport.GetStatistic().end());
    EXPECT_FLOAT_EQ(statisticIt->second.startGetTime_, startTime);
}

/**
 * @tc.name: FormReport_003
 * @tc.desc: test SetEndGetTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_003, TestSize.Level1)
{
    float endTime = 2000.0f;
    formReport.SetEndGetTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    ASSERT_NE(statisticIt, formReport.GetStatistic().end());
}

/**
 * @tc.name: FormReport_004
 * @tc.desc: test SetStartGetTime function.
 * @tc.type: FUNC
 */
HWTEST_F(FormReportTest, FormReport_004, TestSize.Level1)
{
    float endTime = 2000.0f;
    float startTime = 1000.0f;
    formReport.SetStartGetTime(testFormId, startTime);
    formReport.SetEndGetTime(testFormId, endTime);
    auto statisticIt = formReport.GetStatistic().find(testFormId);
    ASSERT_NE(statisticIt, formReport.GetStatistic().end());
    EXPECT_FLOAT_EQ(statisticIt->second.endGetTime_, endTime);
}
} // namespace
