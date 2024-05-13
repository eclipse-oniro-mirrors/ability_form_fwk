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
#include "form_record_report.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
namespace {
    const std::string BUNDLE_NAME = "com.example.test";
    const std::string FORM_NAME = "TestForm";
    int64_t TEST_FORM_ID = 12345;

class FormRecordReportTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    FormRecordReport& formRecordReport = FormRecordReport::GetInstance();
    Want want;
};

void FormRecordReportTest::SetUp()
{
    OHOS::AppExecFwk::ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    want.SetElement(element);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, FORM_NAME);
}

void FormRecordReportTest::TearDown()
{
    formRecordReport.ClearReportInfo();
}

/**
 * @tc.name: FormRecordReport_001
 * @tc.desc: test GetFormRecords function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_001, TestSize.Level1)
{
    formRecordReport.SetFormRecordRecordInfo(TEST_FORM_ID, want);
    auto it = formRecordReport.GetFormRecords().find(TEST_FORM_ID);
    ASSERT_NE(it, formRecordReport.GetFormRecords().end());
    EXPECT_EQ(it->second.bundleName, BUNDLE_NAME);
    EXPECT_EQ(it->second.formName, FORM_NAME);
}

/**
 * @tc.name: FormRecordReport_002
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_002, TestSize.Level1)
{
    formRecordReport.SetFormRecordRecordInfo(TEST_FORM_ID, want);
    formRecordReport.IncreaseUpdateTimes(TEST_FORM_ID, TYPE_DAILY_REFRESH);
    auto it = formRecordReport.GetFormRecords().find(TEST_FORM_ID);
    ASSERT_NE(it, formRecordReport.GetFormRecords().end());
    EXPECT_EQ(it->second.dailyRefreshTimes, 1);
}

/**
 * @tc.name: FormRecordReport_003
 * @tc.desc: test clearReportInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_003, TestSize.Level1)
{
    formRecordReport.SetFormRecordRecordInfo(TEST_FORM_ID, want);
    formRecordReport.ClearReportInfo();
    EXPECT_TRUE(formRecordReport.GetFormRecords().empty());
}
} // namespace