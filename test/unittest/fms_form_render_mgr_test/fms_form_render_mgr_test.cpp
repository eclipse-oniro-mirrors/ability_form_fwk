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
#include "form_render/form_render_mgr.h"
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
extern void MockGetCallingUid(int32_t mockRet);
extern void MockGetCurrentAccountIdRet(int32_t userId);

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
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    int32_t userId = 0;
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
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
    auto formInner = std::make_shared<FormRenderMgrInner>();
    int32_t userId = 0;
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
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
    int32_t userId = 1;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    std::string bundleName = "<bundleName>";
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
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(formRecord.userId);
    formRenderMgr.sandboxInners_.emplace(formRecord.userId, formSandboxInner);
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
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(formRecord.userId);
    formRenderMgr.renderInners_.emplace(formRecord.userId, formInner);
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
    auto formInner = std::make_shared<FormRenderMgrInner>();
    int32_t userId = 100;
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    int32_t callingUid {20000001};
    MockGetCallingUid(callingUid);
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
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    int32_t userId = 100;
    formSandboxInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formSandboxInner);
    int32_t callingUid {20000001};
    MockGetCallingUid(callingUid);
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
    int32_t userId = 100;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    int32_t callingUid {20000001};
    MockGetCallingUid(callingUid);
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
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(formRecord.userId);
    formRenderMgr.sandboxInners_.emplace(formRecord.userId, formSandboxInner);
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
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(formRecord.userId);
    formRenderMgr.renderInners_.emplace(formRecord.userId, formInner);
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
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.AddConnection(formId, connection, formRecord));
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
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(formRecord.userId);
    formRenderMgr.sandboxInners_.emplace(formRecord.userId, formSandboxInner);
    MockAddConnection(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.AddConnection(formId, connection, formRecord));
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
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.AddConnection(formId, connection, formRecord));
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
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(formRecord.userId);
    formRenderMgr.renderInners_.emplace(formRecord.userId, formInner);
    MockAddConnection(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.AddConnection(formId, connection, formRecord));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_029 end";
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
 * @tc.name: GetFormRenderInner_001
 * @tc.desc: test GetFormRenderMgrInner and GetFormSandboxMgrInner function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, GetFormRenderMgrInner_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetFormRenderMgrInner_001 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    std::shared_ptr<FormRenderMgrInner> renderInner;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    EXPECT_TRUE(formRenderMgr.GetFormRenderMgrInner(userId, renderInner) && renderInner == formInner);

    std::shared_ptr<FormSandboxRenderMgrInner> sandboxInner;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    EXPECT_TRUE(formRenderMgr.GetFormSandboxMgrInner(userId, sandboxInner) && sandboxInner == formSandboxInner);
    EXPECT_FALSE(formRenderMgr.GetFormRenderMgrInner(0, renderInner));
    EXPECT_FALSE(formRenderMgr.GetFormSandboxMgrInner(0, sandboxInner));
    GTEST_LOG_(INFO) << "GetFormRenderMgrInner_001 end";
}

/**
 * @tc.name: DeleteRenderInner_001
 * @tc.desc: test DeleteRenderInner function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, DeleteRenderInner_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "DeleteRenderInner_001 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    std::shared_ptr<FormRenderMgrInner> renderInner;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    formRenderMgr.DeleteRenderInner(userId);
    EXPECT_FALSE(formRenderMgr.GetFormRenderMgrInner(userId, renderInner));
    GTEST_LOG_(INFO) << "DeleteRenderInner_001 end";
}

/**
 * @tc.name: InitRenderInner_001
 * @tc.desc: Test InitRenderInner creates renderInners_ entry for non-sandbox mode.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, InitRenderInner_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "InitRenderInner_001 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    EXPECT_TRUE(formRenderMgr.renderInners_.empty());
    formRenderMgr.InitRenderInner(false, userId);
    EXPECT_EQ(formRenderMgr.renderInners_.size(), 1u);
    EXPECT_TRUE(formRenderMgr.renderInners_.count(userId) > 0);
    EXPECT_TRUE(formRenderMgr.sandboxInners_.empty());
    GTEST_LOG_(INFO) << "InitRenderInner_001 end";
}

/**
 * @tc.name: InitRenderInner_002
 * @tc.desc: Test InitRenderInner creates sandboxInners_ entry for sandbox mode.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, InitRenderInner_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "InitRenderInner_002 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 200;
    EXPECT_TRUE(formRenderMgr.sandboxInners_.empty());
    formRenderMgr.InitRenderInner(true, userId);
    EXPECT_EQ(formRenderMgr.sandboxInners_.size(), 1u);
    EXPECT_TRUE(formRenderMgr.sandboxInners_.count(userId) > 0);
    EXPECT_TRUE(formRenderMgr.renderInners_.empty());
    GTEST_LOG_(INFO) << "InitRenderInner_002 end";
}

/**
 * @tc.name: InitRenderInner_003
 * @tc.desc: Test InitRenderInner does not duplicate entry if already exists.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, InitRenderInner_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "InitRenderInner_003 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    formRenderMgr.InitRenderInner(false, userId);
    EXPECT_EQ(formRenderMgr.renderInners_.size(), 1u);
    formRenderMgr.InitRenderInner(false, userId);
    EXPECT_EQ(formRenderMgr.renderInners_.size(), 1u);
    GTEST_LOG_(INFO) << "InitRenderInner_003 end";
}

/**
 * @tc.name: GetFRSDiedInLowMemoryByUid_001
 * @tc.desc: Test GetFRSDiedInLowMemoryByUid returns false when no renderInner exists.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, GetFRSDiedInLowMemoryByUid_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetFRSDiedInLowMemoryByUid_001 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    EXPECT_FALSE(formRenderMgr.GetFRSDiedInLowMemoryByUid(userId));
    GTEST_LOG_(INFO) << "GetFRSDiedInLowMemoryByUid_001 end";
}

/**
 * @tc.name: GetFRSDiedInLowMemoryByUid_002
 * @tc.desc: Test GetFRSDiedInLowMemoryByUid returns the inner state when renderInner exists.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, GetFRSDiedInLowMemoryByUid_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetFRSDiedInLowMemoryByUid_002 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    formRenderMgr.InitRenderInner(false, userId);
    EXPECT_FALSE(formRenderMgr.GetFRSDiedInLowMemoryByUid(userId));
    auto iter = formRenderMgr.renderInners_.find(userId);
    ASSERT_TRUE(iter != formRenderMgr.renderInners_.end());
    iter->second->isFrsDiedInLowMemory_ = true;
    EXPECT_TRUE(formRenderMgr.GetFRSDiedInLowMemoryByUid(userId));
    GTEST_LOG_(INFO) << "GetFRSDiedInLowMemoryByUid_002 end";
}

/**
 * @tc.name: SetRenderGroupEnableFlag_001
 * @tc.desc: Test SetRenderGroupEnableFlag when no renderInner exists for current userId, maps unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, SetRenderGroupEnableFlag_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetRenderGroupEnableFlag_001 start";
    FormRenderMgr formRenderMgr;
    MockGetCurrentAccountIdRet(200);
    formRenderMgr.InitRenderInner(false, 100);
    EXPECT_EQ(formRenderMgr.renderInners_.size(), 1u);
    formRenderMgr.SetRenderGroupEnableFlag(1, true);
    EXPECT_EQ(formRenderMgr.renderInners_.size(), 1u);
    EXPECT_TRUE(formRenderMgr.sandboxInners_.empty());
    GTEST_LOG_(INFO) << "SetRenderGroupEnableFlag_001 end";
}

/**
 * @tc.name: SetRenderGroupEnableFlag_002
 * @tc.desc: Test SetRenderGroupEnableFlag with matching userId, inner remains valid after call.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, SetRenderGroupEnableFlag_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetRenderGroupEnableFlag_002 start";
    FormRenderMgr formRenderMgr;
    MockGetCurrentAccountIdRet(100);
    formRenderMgr.InitRenderInner(false, 100);
    formRenderMgr.InitRenderInner(true, 100);
    std::shared_ptr<FormRenderMgrInner> renderInner;
    EXPECT_TRUE(formRenderMgr.GetFormRenderMgrInner(100, renderInner));
    formRenderMgr.SetRenderGroupEnableFlag(1, true);
    EXPECT_TRUE(formRenderMgr.GetFormRenderMgrInner(100, renderInner));
    formRenderMgr.SetRenderGroupEnableFlag(1, false);
    EXPECT_TRUE(formRenderMgr.GetFormRenderMgrInner(100, renderInner));
    GTEST_LOG_(INFO) << "SetRenderGroupEnableFlag_002 end";
}

/**
 * @tc.name: CheckMultiAppFormVersionCode_001
 * @tc.desc: Test CheckMultiAppFormVersionCode with empty bundleName returns false.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, CheckMultiAppFormVersionCode_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "CheckMultiAppFormVersionCode_001 start";
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.bundleName = "";
    formRecord.isSystemApp = false;
    EXPECT_FALSE(formRenderMgr.CheckMultiAppFormVersionCode(formRecord));
    GTEST_LOG_(INFO) << "CheckMultiAppFormVersionCode_001 end";
}
}
