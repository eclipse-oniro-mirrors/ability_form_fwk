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

#define private public
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

/**
 * @tc.name: FormRecordReport_004
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_004, TestSize.Level1)
{
    FormRecordReportInfo formRecordReportInfo;
    formRecordReportInfo.invisibleRefreshTimes = 0;
    int64_t formId = 1;
    formRecordReport.formRecordReportMap_[formId] = formRecordReportInfo;
    HiSysEventPointType type = TYPE_INVISIBLE_UPDATE;
    formRecordReport.IncreaseUpdateTimes(formId, type);
    auto iter = formRecordReport.formRecordReportMap_.find(formId);
    EXPECT_EQ(iter->second.invisibleRefreshTimes, 1);
}

/**
 * @tc.name: FormRecordReport_005
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_005, TestSize.Level1)
{
    FormRecordReportInfo formRecordReportInfo;
    formRecordReportInfo.hfRefreshBlockTimes = 0;
    int64_t formId = 1;
    formRecordReport.formRecordReportMap_[formId] = formRecordReportInfo;
    HiSysEventPointType type = TYPE_HIGH_FREQUENCY;
    formRecordReport.IncreaseUpdateTimes(formId, type);
    auto iter = formRecordReport.formRecordReportMap_.find(formId);
    EXPECT_EQ(iter->second.hfRefreshBlockTimes, 1);
}

/**
 * @tc.name: FormRecordReport_006
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_006, TestSize.Level1)
{
    FormRecordReportInfo formRecordReportInfo;
    formRecordReportInfo.invisibleRefreshBlockTimes = 0;
    int64_t formId = 1;
    formRecordReport.formRecordReportMap_[formId] = formRecordReportInfo;
    HiSysEventPointType type = TYPE_INVISIBLE_INTERCEPT;
    formRecordReport.IncreaseUpdateTimes(formId, type);
    auto iter = formRecordReport.formRecordReportMap_.find(formId);
    EXPECT_EQ(iter->second.invisibleRefreshBlockTimes, 1);
}

/**
 * @tc.name: FormRecordReport_007
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_007, TestSize.Level1)
{
    FormRecordReportInfo formRecordReportInfo;
    formRecordReportInfo.highLoadRefreshBlockTimes = 1;
    int64_t formId = 1;
    formRecordReport.formRecordReportMap_[formId] = formRecordReportInfo;
    HiSysEventPointType type = TYPE_HIGH_LOAD;
    formRecordReport.IncreaseUpdateTimes(formId, type);
    auto iter = formRecordReport.formRecordReportMap_.find(formId);
    EXPECT_EQ(iter->second.highLoadRefreshBlockTimes, 0);
}

/**
 * @tc.name: FormRecordReport_008
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_008, TestSize.Level1)
{
    FormRecordReportInfo formRecordReportInfo;
    formRecordReportInfo.activeRecoverRefreshTimes = 1;
    int64_t formId = 1;
    formRecordReport.formRecordReportMap_[formId] = formRecordReportInfo;
    HiSysEventPointType type = TYPE_ACTIVE_RECVOER_UPDATE;
    formRecordReport.IncreaseUpdateTimes(formId, type);
    auto iter = formRecordReport.formRecordReportMap_.find(formId);
    EXPECT_EQ(iter->second.activeRecoverRefreshTimes, 0);
}

/**
 * @tc.name: FormRecordReport_009
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_009, TestSize.Level1)
{
    FormRecordReportInfo formRecordReportInfo;
    formRecordReportInfo.passiveRecoverRefreshTimes = 0;
    int64_t formId = 1;
    formRecordReport.formRecordReportMap_[formId] = formRecordReportInfo;
    HiSysEventPointType type = TYPE_PASSIVE_RECOVER_UPDATE;
    formRecordReport.IncreaseUpdateTimes(formId, type);
    auto iter = formRecordReport.formRecordReportMap_.find(formId);
    EXPECT_EQ(iter->second.passiveRecoverRefreshTimes, 1);
}

/**
 * @tc.name: FormRecordReport_010
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_010, TestSize.Level1)
{
    FormRecordReportInfo formRecordReportInfo;
    formRecordReportInfo.hfRecoverRefreshTimes = 0;
    int64_t formId = 1;
    formRecordReport.formRecordReportMap_[formId] = formRecordReportInfo;
    HiSysEventPointType type = TYPE_HF_RECOVER_UPDATE;
    formRecordReport.IncreaseUpdateTimes(formId, type);
    auto iter = formRecordReport.formRecordReportMap_.find(formId);
    EXPECT_EQ(iter->second.hfRecoverRefreshTimes, 1);
}

/**
 * @tc.name: FormRecordReport_011
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_011, TestSize.Level1)
{
    FormRecordReportInfo formRecordReportInfo;
    formRecordReportInfo.offloadRecoverRefreshTimes = 1;
    int64_t formId = 1;
    formRecordReport.formRecordReportMap_[formId] = formRecordReportInfo;
    HiSysEventPointType type = TYPE_OFFLOAD_RECOVER_UPDATE;
    formRecordReport.IncreaseUpdateTimes(formId, type);
    auto iter = formRecordReport.formRecordReportMap_.find(formId);
    EXPECT_EQ(iter->second.offloadRecoverRefreshTimes, 0);
}

/**
 * @tc.name: FormRecordReport_012
 * @tc.desc: test IncreaseUpdateTimes function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRecordReportTest, FormRecordReport_012, TestSize.Level1)
{
    FormRecordReportInfo formRecordReportInfo;
    formRecordReportInfo.bundleName = "bundleName";
    int64_t formId = 1;
    formRecordReport.formRecordReportMap_[formId] = formRecordReportInfo;
    std::string bundleName = "test_bundleName";
    Want want;
    want.GetElement().SetBundleName(bundleName);
    formRecordReport.SetFormRecordRecordInfo(formId, want);
    auto iter = formRecordReport.formRecordReportMap_.find(formId);
    EXPECT_NE(iter->second.bundleName, bundleName);
}
} // namespace