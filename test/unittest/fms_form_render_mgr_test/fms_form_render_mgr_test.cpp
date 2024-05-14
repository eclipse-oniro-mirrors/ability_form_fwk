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

#include <chrono>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "form_constants.h"
#include "form_mgr_errors.h"
#define private public
#include "form_render_interface.h"
#include "form_render_mgr.h"
#undef private
#include "ipc_types.h"
#include "fms_log_wrapper.h"
#include "mock_form_provider_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockGetFormRecord(bool mockRet, int32_t type);
extern void MockRenderForm(bool mockRet);
extern void MockSandboxRenderForm(bool mockRet);
extern void MockUpdateRenderingForm(bool mockRet);
extern void MockStopRenderingForm(bool mockRet);
extern void MockReleaseRenderer(bool mockRet);
extern void MockAddConnection(bool mockRet);

namespace {
class FormRenderMgrTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void FormRenderMgrTest::SetUp()
{}

void FormRenderMgrTest::TearDown()
{}

/**
 * @tc.name: FormRenderMgrTest_001
 * @tc.desc: test RenderForm function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_001 start";
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::JS;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    EXPECT_EQ(ERR_OK, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_001 end";
}

/**
 * @tc.name: FormRenderMgrTest_002
 * @tc.desc: test RenderForm function and return ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_002 start";
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 0; // invalid formId.
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_002 end";
}

/**
 * @tc.name: FormRenderMgrTest_003
 * @tc.desc: test RenderForm function and privacyLevel is 1.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_003 start";
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    formRecord.privacyLevel = 1;
    MockSandboxRenderForm(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_003 end";
}

/**
 * @tc.name: FormRenderMgrTest_004
 * @tc.desc: test RenderForm function and privacyLevel is 0.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_004 start";
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    formRecord.privacyLevel = 0;
    MockRenderForm(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_004 end";
}

/**
 * @tc.name: FormRenderMgrTest_005
 * @tc.desc: test UpdateRenderingForm function and isGetFormRecord is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_005 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    MockGetFormRecord(false, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_005 end";
}

/**
 * @tc.name: FormRenderMgrTest_006
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.privacyLevel is 1.
 *           3.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_006 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    MockGetFormRecord(true, 1);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_006 end";
}

/**
 * @tc.name: FormRenderMgrTest_007
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.privacyLevel is 1.
 *           3.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_007 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    MockGetFormRecord(true, 1);
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    MockUpdateRenderingForm(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_007 end";
}

/**
 * @tc.name: FormRenderMgrTest_008
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.privacyLevel is 0.
 *           3.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_008 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    MockGetFormRecord(true, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_008 end";
}

/**
 * @tc.name: FormRenderMgrTest_009
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.privacyLevel is 0.
 *           3.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_009 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    MockGetFormRecord(true, 0);
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    MockUpdateRenderingForm(true);
    EXPECT_EQ(ERR_OK,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_009 end";
}

/**
 * @tc.name: FormRenderMgrTest_010
 * @tc.desc: test ReloadForm function and formRecords is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_010 start";
    FormRenderMgr formRenderMgr;
    std::vector<FormRecord> formRecords;
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_OK,
        formRenderMgr.ReloadForm(std::move(formRecords), bundleName, userId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_010 end";
}

/**
 * @tc.name: FormRenderMgrTest_011
 * @tc.desc: 1.test ReloadForm function and formRecords is not empty.
 *           2.renderInner_ is nullptr.
 *           3.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_011 start";
    FormRenderMgr formRenderMgr;
    std::vector<FormRecord> formRecords;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    FormRecord sandboxFormRecord;
    sandboxFormRecord.privacyLevel = 1;
    formRecords.emplace_back(formRecord);
    formRecords.emplace_back(sandboxFormRecord);
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_OK, formRenderMgr.ReloadForm(std::move(formRecords), bundleName, userId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_011 end";
}

/**
 * @tc.name: FormRenderMgrTest_012
 * @tc.desc: 1.test ReloadForm function and formRecords is not empty.
 *           2.renderInner_ is not nullptr.
 *           3.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_012 start";
    FormRenderMgr formRenderMgr;
    std::vector<FormRecord> formRecords;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    FormRecord sandboxFormRecord;
    sandboxFormRecord.privacyLevel = 1;
    formRecords.emplace_back(formRecord);
    formRecords.emplace_back(sandboxFormRecord);
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_OK, formRenderMgr.ReloadForm(std::move(formRecords), bundleName, userId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_012 end";
}

/**
 * @tc.name: FormRenderMgrTest_013
 * @tc.desc: 1.test StopRenderingForm function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_013 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_013 end";
}

/**
 * @tc.name: FormRenderMgrTest_014
 * @tc.desc: 1.test StopRenderingForm function and privacyLevel is 1.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_014 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    std::string compId = "<compId>";
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    MockStopRenderingForm(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_014 end";
}

/**
 * @tc.name: FormRenderMgrTest_015
 * @tc.desc: 1.test StopRenderingForm function and privacyLevel is 0.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_015 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_015 end";
}

/**
 * @tc.name: FormRenderMgrTest_016
 * @tc.desc: 1.test StopRenderingForm function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_016 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    std::string compId = "<compId>";
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    MockStopRenderingForm(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_016 end";
}

/**
 * @tc.name: FormRenderMgrTest_017
 * @tc.desc: test RenderFormCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_017 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(ERR_OK, formRenderMgr.RenderFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_017 end";
}

/**
 * @tc.name: FormRenderMgrTest_018
 * @tc.desc: 1.test StopRenderingFormCallback function and renderInner_ is nullptr.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_018 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(ERR_OK, formRenderMgr.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_018 end";
}

/**
 * @tc.name: FormRenderMgrTest_019
 * @tc.desc: 1.test StopRenderingFormCallback function and renderInner_ is not nullptr.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_019 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    EXPECT_EQ(ERR_OK, formRenderMgr.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_019 end";
}

/**
 * @tc.name: FormRenderMgrTest_020
 * @tc.desc: 1.test StopRenderingFormCallback function and renderInner_ is nullptr.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_020 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    EXPECT_EQ(ERR_OK, formRenderMgr.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_020 end";
}

/**
 * @tc.name: FormRenderMgrTest_021
 * @tc.desc: 1.test StopRenderingFormCallback function and renderInner_ is not nullptr.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_021 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    EXPECT_EQ(ERR_OK, formRenderMgr.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_021 end";
}

/**
 * @tc.name: FormRenderMgrTest_022
 * @tc.desc: 1.test ReleaseRenderer function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_022 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_022 end";
}

/**
 * @tc.name: FormRenderMgrTest_023
 * @tc.desc: 1.test ReleaseRenderer function and privacyLevel is 1.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_023 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    std::string compId = "<compId>";
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    MockReleaseRenderer(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_023 end";
}

/**
 * @tc.name: FormRenderMgrTest_024
 * @tc.desc: 1.test ReleaseRenderer function and privacyLevel is 0.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_024 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_024 end";
}

/**
 * @tc.name: FormRenderMgrTest_025
 * @tc.desc: 1.test ReleaseRenderer function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_025 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    std::string compId = "<compId>";
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    MockReleaseRenderer(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_025 end";
}

/**
 * @tc.name: FormRenderMgrTest_026
 * @tc.desc: 1.test AddConnection function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_026 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    sptr<FormRenderConnection> connection = nullptr;
    int32_t privacyLevel = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.AddConnection(formId, connection, privacyLevel));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_026 end";
}

/**
 * @tc.name: FormRenderMgrTest_027
 * @tc.desc: 1.test AddConnection function and privacyLevel is 1.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_027 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    sptr<FormRenderConnection> connection = nullptr;
    int32_t privacyLevel = 1;
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    MockAddConnection(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.AddConnection(formId, connection, privacyLevel));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_027 end";
}

/**
 * @tc.name: FormRenderMgrTest_028
 * @tc.desc: 1.test AddConnection function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_028 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    sptr<FormRenderConnection> connection = nullptr;
    int32_t privacyLevel = 0;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.AddConnection(formId, connection, privacyLevel));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_028 end";
}

/**
 * @tc.name: FormRenderMgrTest_029
 * @tc.desc: 1.test AddConnection function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_029 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    sptr<FormRenderConnection> connection = nullptr;
    int32_t privacyLevel = 0;
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    MockAddConnection(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.AddConnection(formId, connection, privacyLevel));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_029 end";
}

/**
 * @tc.name: FormRenderMgrTest_030
 * @tc.desc: 1.test CleanFormHost function and renderInner_ is nullptr.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_030 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    formRenderMgr.CleanFormHost(host);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_030 end";
}

/**
 * @tc.name: FormRenderMgrTest_031
 * @tc.desc: 1.test CleanFormHost function and renderInner_ is not nullptr.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_031 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    formRenderMgr.CleanFormHost(host);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_031 end";
}

/**
 * @tc.name: FormRenderMgrTest_032
 * @tc.desc: 1.test CleanFormHost function and sandboxInner_ is not nullptr.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_032 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    formRenderMgr.CleanFormHost(host);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_032 end";
}

/**
 * @tc.name: FormRenderMgrTest_033
 * @tc.desc: 1.test CleanFormHost function and sandboxInner_ is not nullptr.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_033 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    formRenderMgr.CleanFormHost(host);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_033 end";
}

/**
 * @tc.name: FormRenderMgrTest_034
 * @tc.desc: 1.test AddRenderDeathRecipient function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_034 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    int32_t privacyLevel = 1;
    formRenderMgr->AddRenderDeathRecipient(remoteObject, privacyLevel);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_034 end";
}

/**
 * @tc.name: FormRenderMgrTest_035
 * @tc.desc: 1.test AddRenderDeathRecipient function and privacyLevel is 1.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_035 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    int32_t privacyLevel = 1;
    formRenderMgr->sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    formRenderMgr->AddRenderDeathRecipient(remoteObject, privacyLevel);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_035 end";
}

/**
 * @tc.name: FormRenderMgrTest_036
 * @tc.desc: 1.test AddRenderDeathRecipient function and privacyLevel is 0.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_036 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    int32_t privacyLevel = 0;
    formRenderMgr->AddRenderDeathRecipient(remoteObject, privacyLevel);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_036 end";
}

/**
 * @tc.name: FormRenderMgrTest_037
 * @tc.desc: 1.test AddRenderDeathRecipient function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_037 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    int32_t privacyLevel = 0;
    formRenderMgr->renderInner_ = std::make_shared<FormRenderMgrInner>();
    formRenderMgr->AddRenderDeathRecipient(remoteObject, privacyLevel);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_037 end";
}

/**
 * @tc.name: FormRenderMgrTest_038
 * @tc.desc: test IsNeedRender function and isGetFormRecord is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_038 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    MockGetFormRecord(false, 0);
    EXPECT_EQ(false, formRenderMgr.IsNeedRender(formId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_038 end";
}

/**
 * @tc.name: FormRenderMgrTest_039
 * @tc.desc: 1.test IsNeedRender function and isGetFormRecord is true.
 *           2.formRecord.uiSyntax != FormType::ETS.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_039 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    MockGetFormRecord(true, 0);
    EXPECT_EQ(false, formRenderMgr.IsNeedRender(formId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_039 end";
}

/**
 * @tc.name: FormRenderMgrTest_040
 * @tc.desc: test HandleConnectFailed function and hostClient is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_040 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    int32_t errorCode = 2;
    formRenderMgr.HandleConnectFailed(formId, errorCode);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_040 end";
}

/**
 * @tc.name: FormRenderMgrTest_041
 * @tc.desc: test IsRerenderForRenderServiceDied function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_041 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    EXPECT_EQ(false, formRenderMgr.IsRerenderForRenderServiceDied(formId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_041 end";
}


/**
 * @tc.name: FormRenderMgrTest_042
 * @tc.desc: 1.test RemoveConnection function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_042 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    int32_t privacyLevel = 1;
    formRenderMgr.RemoveConnection(formId, privacyLevel);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_042 end";
}

/**
 * @tc.name: FormRenderMgrTest_043
 * @tc.desc: 1.test RemoveConnection function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_043 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    int32_t privacyLevel = 1;
    formRenderMgr.sandboxInner_ = std::make_shared<FormSandboxRenderMgrInner>();
    formRenderMgr.RemoveConnection(formId, privacyLevel);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_043 end";
}

/**
 * @tc.name: FormRenderMgrTest_044
 * @tc.desc: 1.test RemoveConnection function and privacyLevel is 0.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_044 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    int32_t privacyLevel = 0;
    formRenderMgr.RemoveConnection(formId, privacyLevel);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_044 end";
}

/**
 * @tc.name: FormRenderMgrTest_045
 * @tc.desc: 1.test RemoveConnection function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_045 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    int32_t privacyLevel = 1;
    formRenderMgr.renderInner_ = std::make_shared<FormRenderMgrInner>();
    formRenderMgr.RemoveConnection(formId, privacyLevel);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_045 end";
}
}
