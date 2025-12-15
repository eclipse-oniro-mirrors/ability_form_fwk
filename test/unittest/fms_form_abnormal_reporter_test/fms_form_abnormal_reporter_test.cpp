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

#include <memory>
#include <gtest/gtest.h>
#include "gmock/gmock.h"
#include "fms_log_wrapper.h"
#include "mock_form_data_mgr.h"
#include "mock_form_event_report.h"
#include "mock_param_control.h"
#include "feature/form_check/form_abnormal_info.h"
#define private public
#include "feature/form_check/form_abnormal_reporter.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t PARAMS_SIZE_MAX = 50;

class FormAbnormalReporterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormAbnormalReporterTest::SetUpTestCase()
{}

void FormAbnormalReporterTest::TearDownTestCase()
{}

void FormAbnormalReporterTest::SetUp()
{}

void FormAbnormalReporterTest::TearDown()
{}

/**
 * @tc.name: FormAbnormalReporterTest_AddRecord_0001
 * @tc.desc: test AddRecord function
 * @tc.type: FUNC
 */
HWTEST_F(FormAbnormalReporterTest, FormAbnormalReporterTest_AddRecord_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_AddRecord_0001 start";
    int64_t formId = 123456;
    FormRecord formRecord;
    formRecord.formId = formId;
    
    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .Times(2)
        .WillOnce(Return(false))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    
    // Test ratio beyond the threshold
    FormAbnormalReporter::GetInstance().AddRecord(formId, 10);

    // Test form not found
    FormAbnormalReporter::GetInstance().AddRecord(formId, 0);

    // Test form found
    FormAbnormalReporter::GetInstance().AddRecord(formId, 0);

    // clear cached abnormal records
    FormAbnormalReporter::GetInstance().formAbnormalInfoMap_.clear();
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_AddRecord_0001 end";
}

/**
 * @tc.name: FormAbnormalReporterTest_MarkUpdateRender_0001
 * @tc.desc: test MarkUpdateRender function
 * @tc.type: FUNC
 */
HWTEST_F(FormAbnormalReporterTest, FormAbnormalReporterTest_MarkUpdateRender_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_MarkUpdateRender_0001 start";
    int64_t formId = 123456;
    FormRecord formRecord;
    formRecord.formId = formId;

    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();

    // Test form not found
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillOnce(Return(false));
    FormAbnormalReporter::GetInstance().MarkUpdateRender(formId);
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);

    // Test system app
    formRecord.isSystemApp = true;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    FormAbnormalReporter::GetInstance().MarkUpdateRender(formId);
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);

    // Test not system app and not transparency enabled
    formRecord.isSystemApp = false;
    formRecord.transparencyEnabled = false;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    FormAbnormalReporter::GetInstance().MarkUpdateRender(formId);
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);

    // Test not system app and transparency enabled
    formRecord.isSystemApp = false;
    formRecord.transparencyEnabled = true;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    FormAbnormalReporter::GetInstance().MarkUpdateRender(formId);
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 1);

    MockFormDataMgr::obj = nullptr;
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_MarkUpdateRender_0001 end";
}

/**
 * @tc.name: FormAbnormalReporterTest_CheckForms_0001
 * @tc.desc: test CheckForms function
 * @tc.type: FUNC
 */
HWTEST_F(FormAbnormalReporterTest, FormAbnormalReporterTest_CheckForms_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_CheckForms_0001 start";
    int64_t formId = 123456;
    FormRecord formRecord;
    formRecord.formId = formId;
    std::vector<int64_t> checkFormIds;

    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    EXPECT_CALL(*MockFormDataMgr::obj, CheckForms(_)).WillRepeatedly(SaveArg<0>(&checkFormIds));

    // Test form not found and formIds empty
    FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.insert(formId);
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillOnce(Return(false));
    FormAbnormalReporter::GetInstance().CheckForms();
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);
    EXPECT_EQ(checkFormIds.size(), 0);

    // Test valid abnormal form infos
    FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.insert(formId);
    formRecord.isSystemApp = false;
    formRecord.transparencyEnabled = true;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    FormAbnormalReporter::GetInstance().CheckForms();
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);
    EXPECT_EQ(checkFormIds.size(), 1);
    checkFormIds.clear();
    
    MockFormDataMgr::obj = nullptr;
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_CheckForms_0001 end";
}

/**
 * @tc.name: FormAbnormalReporterTest_CheckForms_0002
 * @tc.desc: test CheckForms function
 * @tc.type: FUNC
 */
HWTEST_F(FormAbnormalReporterTest, FormAbnormalReporterTest_CheckForms_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_CheckForms_0002 start";
    int64_t formId = 123456;
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isSystemApp = false;
    formRecord.transparencyEnabled = true;
    std::vector<int64_t> checkFormIds;

    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    EXPECT_CALL(*MockFormDataMgr::obj, CheckForms(_)).WillRepeatedly(SaveArg<0>(&checkFormIds));

    // Test lock form
    FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.insert(formId);
    formRecord.lockForm = true;
    formRecord.protectForm = true;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    FormAbnormalReporter::GetInstance().CheckForms();
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);
    EXPECT_EQ(checkFormIds.size(), 0);

    // Test protect form
    FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.insert(formId);
    formRecord.lockForm = true;
    formRecord.protectForm = false;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    FormAbnormalReporter::GetInstance().CheckForms();
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);
    EXPECT_EQ(checkFormIds.size(), 1);
    checkFormIds.clear();

    // Test enable form
    FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.insert(formId);
    formRecord.lockForm = false;
    formRecord.enableForm = false;
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillOnce(DoAll(SetArgReferee<1>(formRecord), Return(true)));
    FormAbnormalReporter::GetInstance().CheckForms();
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);
    EXPECT_EQ(checkFormIds.size(), 0);
    
    MockFormDataMgr::obj = nullptr;
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_CheckForms_0002 end";
}

/**
 * @tc.name: FormAbnormalReporterTest_CheckForms_0003
 * @tc.desc: test CheckForms function
 * @tc.type: FUNC
 */
HWTEST_F(FormAbnormalReporterTest, FormAbnormalReporterTest_CheckForms_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_CheckForms_0003 start";
    int64_t formId = 123456;
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isSystemApp = false;
    formRecord.transparencyEnabled = true;
    formRecord.lockForm = false;
    formRecord.enableForm = true;
    std::vector<int64_t> checkFormIds;

    MockFormDataMgr::obj = std::make_shared<MockFormDataMgr>();
    MockParamControl::obj = std::make_shared<MockParamControl>();
    EXPECT_CALL(*MockFormDataMgr::obj, CheckForms(_)).WillRepeatedly(SaveArg<0>(&checkFormIds));
    EXPECT_CALL(*MockFormDataMgr::obj, GetFormRecord(formId, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(formRecord), Return(true)));

    // Test due control disable form
    FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.insert(formId);
    EXPECT_CALL(*MockParamControl::obj, IsFormDisable(_)).WillOnce(Return(true));
    FormAbnormalReporter::GetInstance().CheckForms();
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);
    EXPECT_EQ(checkFormIds.size(), 0);

    // Test due control remove form
    FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.insert(formId);
    EXPECT_CALL(*MockParamControl::obj, IsFormDisable(_)).WillOnce(Return(false));
    EXPECT_CALL(*MockParamControl::obj, IsFormRemove(_)).WillOnce(Return(true));
    FormAbnormalReporter::GetInstance().CheckForms();
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);
    EXPECT_EQ(checkFormIds.size(), 0);

    // Test form display without mask
    FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.insert(formId);
    EXPECT_CALL(*MockParamControl::obj, IsFormDisable(_)).WillOnce(Return(false));
    EXPECT_CALL(*MockParamControl::obj, IsFormRemove(_)).WillOnce(Return(false));
    FormAbnormalReporter::GetInstance().CheckForms();
    EXPECT_EQ(FormAbnormalReporter::GetInstance().lastUpdateTimeSet_.size(), 0);
    EXPECT_EQ(checkFormIds.size(), 1);
    EXPECT_EQ(checkFormIds.front(), formId);
    
    MockFormDataMgr::obj = nullptr;
    MockParamControl::obj = nullptr;
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_CheckForms_0003 end";
}

/**
 * @tc.name: FormAbnormalReporterTest_ReportAbnormalForms_0001
 * @tc.desc: test ReportAbnormalForms function
 * @tc.type: FUNC
 */
HWTEST_F(FormAbnormalReporterTest, FormAbnormalReporterTest_ReportAbnormalForms_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_ReportAbnormalForms_0001 start";
    int64_t formId = 123456;
    FormRecord formRecord;
    formRecord.formId = formId;
    FormAbnormalInfo info = FormAbnormalInfo::Create(formRecord);

    FormAbnormalReportParams params1;
    FormAbnormalReportParams params2;
    MockFormEventReport::obj = std::make_shared<MockFormEventReport>();
    EXPECT_CALL(*MockFormEventReport::obj, SendFormAbnormalEvent(_))
        .WillOnce(SaveArg<0>(&params1))
        .WillOnce(SaveArg<0>(&params2));

    // Test abnormal info map size greater than PARAMS_SIZE_MAX
    for (int32_t i = 0; i <= PARAMS_SIZE_MAX; i++) {
        FormAbnormalReporter::GetInstance().formAbnormalInfoMap_.emplace(i + 1, info);
    }
    FormAbnormalReporter::GetInstance().ReportAbnormalForms();
    EXPECT_EQ(params1.bundleNames.size(), PARAMS_SIZE_MAX);
    EXPECT_EQ(params2.bundleNames.size(), 1);

    MockFormEventReport::obj = nullptr;
    GTEST_LOG_(INFO) << "FormAbnormalReporterTest_ReportAbnormalForms_0001 end";
}
}