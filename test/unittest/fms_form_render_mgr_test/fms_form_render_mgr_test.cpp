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
    int32_t hostCallingUid {0};
    MockGetCurrentAccountIdRet(100);
    formRenderMgr.CleanFormHost(host, hostCallingUid);
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
    auto formInner = std::make_shared<FormRenderMgrInner>();
    int32_t userId = 100;
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    int32_t hostCallingUid {20000001};
    formRenderMgr.CleanFormHost(host, hostCallingUid);
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
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    int32_t userId = 100;
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    int32_t hostCallingUid {20000001};
    formRenderMgr.CleanFormHost(host, hostCallingUid);
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
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    int32_t hostCallingUid {20000001};
    formRenderMgr.CleanFormHost(host, hostCallingUid);
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
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    formRenderMgr->AddRenderDeathRecipient(remoteObject, formRecord);
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
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(formRecord.userId);
    formRenderMgr->sandboxInners_.emplace(formRecord.userId, formSandboxInner);
    formRenderMgr->AddRenderDeathRecipient(remoteObject, formRecord);
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
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    formRenderMgr->AddRenderDeathRecipient(remoteObject, formRecord);
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
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(formRecord.userId);
    formRenderMgr->renderInners_.emplace(formRecord.userId, formInner);
    formRenderMgr->AddRenderDeathRecipient(remoteObject, formRecord);
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
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    formRenderMgr.RemoveConnection(formId, formRecord);
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
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(formRecord.userId);
    formRenderMgr.sandboxInners_.emplace(formRecord.userId, formSandboxInner);
    formRenderMgr.RemoveConnection(formId, formRecord);
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
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    formRenderMgr.RemoveConnection(formId, formRecord);
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
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(formRecord.userId);
    formRenderMgr.renderInners_.emplace(formRecord.userId, formInner);
    formRenderMgr.RemoveConnection(formId, formRecord);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_045 end";
}

/**
 * @tc.name: FormRenderMgrTest_046
 * @tc.desc: 1.test AddAcquireProviderFormInfoTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_046 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    std::function<void()> task;

    formRenderMgr.AddAcquireProviderFormInfoTask(userId, task);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_046 end";
}

/**
 * @tc.name: FormRenderMgrTest_047
 * @tc.desc: 1.test ExecAcquireProviderTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_047 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;

    formRenderMgr.ExecAcquireProviderTask(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_047 end";
}

/**
 * @tc.name: FormRenderMgrTest_048
 * @tc.desc: 1.test ExecAcquireProviderForbiddenTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_048 start";
    FormRenderMgr formRenderMgr;
    std::string bundleName = "<bundleName>";

    formRenderMgr.ExecAcquireProviderForbiddenTask(bundleName);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_048 end";
}

/**
 * @tc.name: FormRenderMgrTest_049
 * @tc.desc: 1.test ExecAcquireProviderForbiddenTaskByFormId function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_049, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_049 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;

    formRenderMgr.ExecAcquireProviderForbiddenTaskByFormId(formId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_049 end";
}

/**
 * @tc.name: FormRenderMgrTest_050
 * @tc.desc: 1.test AddPostRenderFormTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_050, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_050 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    std::function<void()> task;

    formRenderMgr.AddPostRenderFormTask(userId, task);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_050 end";
}

/**
 * @tc.name: FormRenderMgrTest_051
 * @tc.desc: 1.test ExecPostRenderFormTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_051, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_051 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;

    formRenderMgr.ExecPostRenderFormTask(formId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_051 end";
}

/**
 * @tc.name: FormRenderMgrTest_052
 * @tc.desc: 1.test OnScreenUnlock function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_052, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_052 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;

    formRenderMgr.OnScreenUnlock(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_052 end";
}

/**
 * @tc.name: FormRenderMgrTest_053
 * @tc.desc: 1.test OnUnlock function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_053, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_053 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;

    formRenderMgr.OnUnlock(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_053 end";
}

/**
 * @tc.name: FormRenderMgrTest_054
 * @tc.desc: 1.test SetVisibleChange function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_054, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_054 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    bool isVisible = true;

    formRenderMgr.SetVisibleChange(formId, isVisible);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_054 end";
}

/**
 * @tc.name: FormRenderMgrTest_055
 * @tc.desc: 1.test reAddConnections function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_055, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_055 start";
    FormRenderMgr formRenderMgr;
    std::vector<int64_t> formIds = {1, 2};
    int32_t userId = 100;
    sptr<IRemoteObject> remoteObject = nullptr;

    formRenderMgr.reAddConnections(formIds, userId, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_055 end";
}

/**
 * @tc.name: FormRenderMgrTest_056
 * @tc.desc: 1.test OnRenderingBlock function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_056, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_056 start";
    FormRenderMgr formRenderMgr;
    std::string bundleName = "<bundleName>";

    formRenderMgr.OnRenderingBlock(bundleName);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_056 end";
}

/**
 * @tc.name: FormRenderMgrTest_057
 * @tc.desc: 1.test RecycleForms function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_057, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_057 start";
    FormRenderMgr formRenderMgr;
    std::vector<int64_t> formIds = {1, 2};
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;

    formRenderMgr.RecycleForms(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_057 end";
}

/**
 * @tc.name: FormRenderMgrTest_058
 * @tc.desc: 1.test RecycleForms function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_058, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_058 start";
    FormRenderMgr formRenderMgr;
    std::vector<int64_t> formIds = {1, 2};
    WantParams wantParams;
    
    formRenderMgr.RecoverForms(formIds, wantParams);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_058 end";
}

/**
 * @tc.name: FormRenderMgrTest_059
 * @tc.desc: 1.test UpdateFormSize function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_059, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_059 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    float width = 1.1;
    float height = 1.1;
    float borderWidth = 1.1;
    float formViewScale = 1.1;
    formRenderMgr.UpdateFormSize(formId, width, height, borderWidth, formViewScale);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_059 end";
}

/**
 * @tc.name: FormRenderMgrTest_060
 * @tc.desc: 1.test GetFormRenderState function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_060, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_060 start";
    FormRenderMgr formRenderMgr;

    formRenderMgr.GetFormRenderState();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_060 end";
}

/**
 * @tc.name: FormRenderMgrTest_061
 * @tc.desc: 1.test PostOnUnlockTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_061, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_061 start";
    FormRenderMgr formRenderMgr;

    formRenderMgr.PostOnUnlockTask();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_061 end";
}

/**
 * @tc.name: FormRenderMgrTest_062
 * @tc.desc: 1.test GetIsSecondMounted function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_062, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_062 start";
    FormRenderMgr formRenderMgr;

    formRenderMgr.GetIsSecondMounted();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_062 end";
}

/**
 * @tc.name: FormRenderMgrTest_063
 * @tc.desc: 1.test AddAcquireProviderForbiddenTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_063, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_063 start";
    FormRenderMgr formRenderMgr;
    std::string bundleName = "<bundleName>";
    int64_t formId = 1;
    std::function<void()> task;

    formRenderMgr.AddAcquireProviderForbiddenTask(bundleName, formId, task);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_063 end";
}

/**
 * @tc.name: FormRenderMgrTest_064
 * @tc.desc: 1.test checkConnectionsFormIds function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_064, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_064 start";
    FormRenderMgr formRenderMgr;
    std::vector<int64_t> formIds = {1, 2};
    int32_t userId = 100;
    std::vector<int64_t> needconFormIds = {1, 2};

    formRenderMgr.checkConnectionsFormIds(formIds, userId, needconFormIds);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_064 end";
}

/**
 * @tc.name: FormRenderMgrTest_065
 * @tc.desc: 1.test DeleteAcquireForbiddenTasksByBundleName function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_065, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_065 start";
    FormRenderMgr formRenderMgr;
    std::string bundleName = "<bundleName>";

    formRenderMgr.DeleteAcquireForbiddenTasksByBundleName(bundleName);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_065 end";
}

/**
 * @tc.name: FormRenderMgrTest_066
 * @tc.desc: 1.test DeleteAcquireForbiddenTaskByFormId function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_066, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_066 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;

    formRenderMgr.DeleteAcquireForbiddenTaskByFormId(formId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_066 end";
}

/**
 * @tc.name: FormRenderMgrTest_067
 * @tc.desc: 1.test DeletePostRenderFormTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_067, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_067 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;

    formRenderMgr.DeletePostRenderFormTask(formId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_067 end";
}

/**
 * @tc.name: NotifyScreenOn_001
 * @tc.desc: test NotifyScreenOn function and privacyLevel is 0.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, NotifyScreenOn_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "NotifyScreenOn_001 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    formRenderMgr.NotifyScreenOn(userId);
    GTEST_LOG_(INFO) << "NotifyScreenOn_001 end";
}

/**
 * @tc.name: DisconnectAllRenderConnections_001
 * @tc.desc: test DisconnectAllRenderConnections function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, DisconnectAllRenderConnections_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_001 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    formRenderMgr.DisconnectAllRenderConnections(userId);
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_001 end";
}

/**
 * @tc.name: DisconnectAllRenderConnections_002
 * @tc.desc: test DisconnectAllRenderConnections function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, DisconnectAllRenderConnections_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_002 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    formRenderMgr.DisconnectAllRenderConnections(userId);
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_002 end";
}

/**
 * @tc.name: DisconnectAllRenderConnections_003
 * @tc.desc: test DisconnectAllRenderConnections function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, DisconnectAllRenderConnections_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_003 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    formRenderMgr.DisconnectAllRenderConnections(userId);
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_003 end";
}

/**
 * @tc.name: RerenderAllFormsImmediate_001
 * @tc.desc: test RerenderAllFormsImmediate function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, RerenderAllFormsImmediate_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_001 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    formRenderMgr.RerenderAllFormsImmediate(userId);
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_001 end";
}

/**
 * @tc.name: RerenderAllFormsImmediate_002
 * @tc.desc: test RerenderAllFormsImmediate function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, RerenderAllFormsImmediate_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_002 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    formRenderMgr.RerenderAllFormsImmediate(userId);
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_002 end";
}

/**
 * @tc.name: RerenderAllFormsImmediate_003
 * @tc.desc: test RerenderAllFormsImmediate function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, RerenderAllFormsImmediate_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_003 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    formRenderMgr.RerenderAllFormsImmediate(userId);
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_003 end";
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
 * @tc.name: SetRenderGroupParams_001
 * @tc.desc: test SetRenderGroupParams function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, SetRenderGroupParams_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetRenderGroupParams_001 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    Want want;
    formRenderMgr.SetRenderGroupParams(1, want);
    GTEST_LOG_(INFO) << "SetRenderGroupParams_001 end";
}

/**
 * @tc.name: FormRenderMgrTest_068
 * @tc.desc: test RenderForm function and return ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_068, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_068 start";
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 0; // invalid formId.
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_068 end";
}

/**
 * @tc.name: FormRenderMgrTest_069
 * @tc.desc: test RenderForm function and privacyLevel is 1.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_069, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_069 start";
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    formRecord.privacyLevel = 1;
    MockSandboxRenderForm(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_069 end";
}

/**
 * @tc.name: FormRenderMgrTest_070
 * @tc.desc: test RenderForm function and privacyLevel is 0.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_070, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_070 start";
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    formRecord.privacyLevel = 0;
    MockRenderForm(true);
    EXPECT_EQ(ERR_OK, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_070 end";
}

/**
 * @tc.name: FormRenderMgrTest_071
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.privacyLevel is 1.
 *           3.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_071, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_071 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    MockGetFormRecord(true, 1);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_071 end";
}

/**
 * @tc.name: FormRenderMgrTest_072
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.privacyLevel is 1.
 *           3.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_072, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_072 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_072 end";
}

/**
 * @tc.name: FormRenderMgrTest_073
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.privacyLevel is 0.
 *           3.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_073, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_073 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    MockGetFormRecord(true, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_073 end";
}

/**
 * @tc.name: FormRenderMgrTest_074
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.privacyLevel is 0.
 *           3.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_074, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_074 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_074 end";
}

/**
 * @tc.name: FormRenderMgrTest_075
 * @tc.desc: test ReloadForm function and formRecords is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_075, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_075 start";
    FormRenderMgr formRenderMgr;
    std::vector<FormRecord> formRecords;
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_OK,
        formRenderMgr.ReloadForm(std::move(formRecords), bundleName, userId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_075 end";
}

/**
 * @tc.name: FormRenderMgrTest_076
 * @tc.desc: 1.test ReloadForm function and formRecords is not empty.
 *           2.renderInner_ is nullptr.
 *           3.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_076, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_076 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_076 end";
}

/**
 * @tc.name: FormRenderMgrTest_077
 * @tc.desc: 1.test ReloadForm function and formRecords is not empty.
 *           2.renderInner_ is not nullptr.
 *           3.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_077, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_077start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_077 end";
}

/**
 * @tc.name: FormRenderMgrTest_078
 * @tc.desc: 1.test StopRenderingForm function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_078, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_078 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_078 end";
}

/**
 * @tc.name: FormRenderMgrTest_079
 * @tc.desc: 1.test StopRenderingForm function and privacyLevel is 1.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_079, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_079 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_079 end";
}

/**
 * @tc.name: FormRenderMgrTest_080
 * @tc.desc: 1.test StopRenderingForm function and privacyLevel is 0.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_080, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_080 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_080 end";
}

/**
 * @tc.name: FormRenderMgrTest_081
 * @tc.desc: 1.test StopRenderingForm function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_081, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_081 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_081 end";
}

/**
 * @tc.name: FormRenderMgrTest_082
 * @tc.desc: test RenderFormCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_082, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_082 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(ERR_OK, formRenderMgr.RenderFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_082 end";
}

/**
 * @tc.name: FormRenderMgrTest_083
 * @tc.desc: 1.test StopRenderingFormCallback function and renderInner_ is nullptr.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_083, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_083 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(ERR_OK, formRenderMgr.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_083 end";
}

/**
 * @tc.name: FormRenderMgrTest_084
 * @tc.desc: 1.test StopRenderingFormCallback function and renderInner_ is not nullptr.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_084, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_084 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_084 end";
}

/**
 * @tc.name: FormRenderMgrTest_085
 * @tc.desc: 1.test StopRenderingFormCallback function and renderInner_ is nullptr.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_085, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_085 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_085 end";
}

/**
 * @tc.name: FormRenderMgrTest_086
 * @tc.desc: 1.test StopRenderingFormCallback function and renderInner_ is not nullptr.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_086, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_086 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_086 end";
}

/**
 * @tc.name: FormRenderMgrTest_087
 * @tc.desc: 1.test ReleaseRenderer function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_087, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_087 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_087 end";
}

/**
 * @tc.name: FormRenderMgrTest_088
 * @tc.desc: 1.test ReleaseRenderer function and privacyLevel is 1.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_088, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_088 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_088 end";
}

/**
 * @tc.name: FormRenderMgrTest_089
 * @tc.desc: 1.test ReleaseRenderer function and privacyLevel is 0.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_089, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_089 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_089 end";
}

/**
 * @tc.name: FormRenderMgrTest_090
 * @tc.desc: 1.test ReleaseRenderer function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_090, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_090 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_090 end";
}

/**
 * @tc.name: FormRenderMgrTest_091
 * @tc.desc: 1.test AddConnection function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_091, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_091 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    sptr<FormRenderConnection> connection = nullptr;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.AddConnection(formId, connection, formRecord));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_091 end";
}

/**
 * @tc.name: FormRenderMgrTest_092
 * @tc.desc: 1.test AddConnection function and privacyLevel is 1.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_092, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_092 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_092 end";
}

/**
 * @tc.name: FormRenderMgrTest_093
 * @tc.desc: 1.test AddConnection function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_093, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_093 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    sptr<FormRenderConnection> connection = nullptr;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.AddConnection(formId, connection, formRecord));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_093 end";
}

/**
 * @tc.name: FormRenderMgrTest_094
 * @tc.desc: 1.test AddConnection function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_094, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_094 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_094 end";
}

/**
 * @tc.name: FormRenderMgrTest_095
 * @tc.desc: 1.test CleanFormHost function and renderInner_ is nullptr.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_095, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_095 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    int32_t hostCallingUid {0};
    MockGetCurrentAccountIdRet(100);
    formRenderMgr.CleanFormHost(host, hostCallingUid);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_095 end";
}

/**
 * @tc.name: FormRenderMgrTest_096
 * @tc.desc: 1.test CleanFormHost function and renderInner_ is not nullptr.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_096, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_096 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    int32_t userId = 100;
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    int32_t hostCallingUid {20000001};
    formRenderMgr.CleanFormHost(host, hostCallingUid);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_096 end";
}

/**
 * @tc.name: FormRenderMgrTest_097
 * @tc.desc: 1.test CleanFormHost function and sandboxInner_ is not nullptr.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_097, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_097 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    int32_t userId = 100;
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    int32_t hostCallingUid {20000001};
    formRenderMgr.CleanFormHost(host, hostCallingUid);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_097 end";
}

/**
 * @tc.name: FormRenderMgrTest_098
 * @tc.desc: 1.test CleanFormHost function and sandboxInner_ is not nullptr.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_098, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_098 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    int32_t hostCallingUid {20000001};
    formRenderMgr.CleanFormHost(host, hostCallingUid);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_098 end";
}

/**
 * @tc.name: FormRenderMgrTest_099
 * @tc.desc: 1.test AddRenderDeathRecipient function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_099, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_099 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    formRenderMgr->AddRenderDeathRecipient(remoteObject, formRecord);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_099 end";
}

/**
 * @tc.name: FormRenderMgrTest_100
 * @tc.desc: 1.test AddRenderDeathRecipient function and privacyLevel is 1.
 *           2.sandboxInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_100 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(formRecord.userId);
    formRenderMgr->sandboxInners_.emplace(formRecord.userId, formSandboxInner);
    formRenderMgr->AddRenderDeathRecipient(remoteObject, formRecord);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_100 end";
}

/**
 * @tc.name: FormRenderMgrTest_101
 * @tc.desc: 1.test AddRenderDeathRecipient function and privacyLevel is 0.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_101, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_101 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    formRenderMgr->AddRenderDeathRecipient(remoteObject, formRecord);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_101 end";
}

/**
 * @tc.name: FormRenderMgrTest_102
 * @tc.desc: 1.test AddRenderDeathRecipient function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_102, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_102 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(formRecord.userId);
    formRenderMgr->renderInners_.emplace(formRecord.userId, formInner);
    formRenderMgr->AddRenderDeathRecipient(remoteObject, formRecord);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_102 end";
}

/**
 * @tc.name: FormRenderMgrTest_103
 * @tc.desc: test IsNeedRender function and isGetFormRecord is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_103, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_103 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    MockGetFormRecord(false, 0);
    EXPECT_EQ(false, formRenderMgr.IsNeedRender(formId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_103 end";
}

/**
 * @tc.name: FormRenderMgrTest_104
 * @tc.desc: 1.test IsNeedRender function and isGetFormRecord is true.
 *           2.formRecord.uiSyntax != FormType::ETS.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_104, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_104 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    MockGetFormRecord(true, 0);
    EXPECT_EQ(false, formRenderMgr.IsNeedRender(formId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_104 end";
}

/**
 * @tc.name: FormRenderMgrTest_105
 * @tc.desc: test HandleConnectFailed function and hostClient is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_105, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_105 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    int32_t errorCode = 2;
    formRenderMgr.HandleConnectFailed(formId, errorCode);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_105 end";
}

/**
 * @tc.name: FormRenderMgrTest_106
 * @tc.desc: test IsRerenderForRenderServiceDied function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_106, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_106 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    EXPECT_EQ(false, formRenderMgr.IsRerenderForRenderServiceDied(formId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_106 end";
}


/**
 * @tc.name: FormRenderMgrTest_107
 * @tc.desc: 1.test RemoveConnection function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_107, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_107 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    formRenderMgr.RemoveConnection(formId, formRecord);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_107 end";
}

/**
 * @tc.name: FormRenderMgrTest_108
 * @tc.desc: 1.test RemoveConnection function and privacyLevel is 1.
 *           2.sandboxInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_108, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_108 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 1;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(formRecord.userId);
    formRenderMgr.sandboxInners_.emplace(formRecord.userId, formSandboxInner);
    formRenderMgr.RemoveConnection(formId, formRecord);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_108 end";
}

/**
 * @tc.name: FormRenderMgrTest_109
 * @tc.desc: 1.test RemoveConnection function and privacyLevel is 0.
 *           2.renderInner_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_109, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_109 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    formRenderMgr.RemoveConnection(formId, formRecord);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_109 end";
}

/**
 * @tc.name: FormRenderMgrTest_110
 * @tc.desc: 1.test RemoveConnection function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_110, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_110 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.privacyLevel = 0;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(formRecord.userId);
    formRenderMgr.renderInners_.emplace(formRecord.userId, formInner);
    formRenderMgr.RemoveConnection(formId, formRecord);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_110 end";
}

/**
 * @tc.name: FormRenderMgrTest_111
 * @tc.desc: 1.test AddAcquireProviderFormInfoTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_111, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_111 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    std::function<void()> task;

    formRenderMgr.AddAcquireProviderFormInfoTask(userId, task);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_111 end";
}

/**
 * @tc.name: FormRenderMgrTest_112
 * @tc.desc: 1.test ExecAcquireProviderTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_112, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_112 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;

    formRenderMgr.ExecAcquireProviderTask(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_112 end";
}

/**
 * @tc.name: FormRenderMgrTest_113
 * @tc.desc: 1.test ExecAcquireProviderForbiddenTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_113, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_113 start";
    FormRenderMgr formRenderMgr;
    std::string bundleName = "<bundleName>";

    formRenderMgr.ExecAcquireProviderForbiddenTask(bundleName);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_113 end";
}

/**
 * @tc.name: FormRenderMgrTest_114
 * @tc.desc: 1.test ExecAcquireProviderForbiddenTaskByFormId function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_114, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_114 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;

    formRenderMgr.ExecAcquireProviderForbiddenTaskByFormId(formId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_114 end";
}

/**
 * @tc.name: FormRenderMgrTest_115
 * @tc.desc: 1.test AddPostRenderFormTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_115, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_115 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    std::function<void()> task;

    formRenderMgr.AddPostRenderFormTask(userId, task);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_115 end";
}

/**
 * @tc.name: FormRenderMgrTest_116
 * @tc.desc: 1.test ExecPostRenderFormTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_116, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_116 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;

    formRenderMgr.ExecPostRenderFormTask(formId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_116 end";
}

/**
 * @tc.name: FormRenderMgrTest_117
 * @tc.desc: 1.test OnScreenUnlock function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_117, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_117 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;

    formRenderMgr.OnScreenUnlock(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_117 end";
}

/**
 * @tc.name: FormRenderMgrTest_118
 * @tc.desc: 1.test OnUnlock function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_118, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_118 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;

    formRenderMgr.OnUnlock(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_118 end";
}

/**
 * @tc.name: FormRenderMgrTest_119
 * @tc.desc: 1.test SetVisibleChange function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_119, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_119 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    bool isVisible = true;

    formRenderMgr.SetVisibleChange(formId, isVisible);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_119 end";
}

/**
 * @tc.name: FormRenderMgrTest_120
 * @tc.desc: 1.test reAddConnections function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_120, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_120 start";
    FormRenderMgr formRenderMgr;
    std::vector<int64_t> formIds = {1, 2};
    int32_t userId = 100;
    sptr<IRemoteObject> remoteObject = nullptr;

    formRenderMgr.reAddConnections(formIds, userId, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_120 end";
}

/**
 * @tc.name: FormRenderMgrTest_121
 * @tc.desc: 1.test OnRenderingBlock function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_121, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_121 start";
    FormRenderMgr formRenderMgr;
    std::string bundleName = "<bundleName>";

    formRenderMgr.OnRenderingBlock(bundleName);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_121 end";
}

/**
 * @tc.name: FormRenderMgrTest_122
 * @tc.desc: 1.test RecycleForms function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_122, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_122 start";
    FormRenderMgr formRenderMgr;
    std::vector<int64_t> formIds = {1, 2};
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;

    formRenderMgr.RecycleForms(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_122 end";
}

/**
 * @tc.name: FormRenderMgrTest_123
 * @tc.desc: 1.test RecycleForms function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_123, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_123 start";
    FormRenderMgr formRenderMgr;
    std::vector<int64_t> formIds = {1, 2};
    WantParams wantParams;
    
    formRenderMgr.RecoverForms(formIds, wantParams);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_123 end";
}

/**
 * @tc.name: FormRenderMgrTest_124
 * @tc.desc: 1.test UpdateFormSize function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_124, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_124 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    float width = 1.1;
    float height = 1.1;
    float borderWidth = 1.1;
    float formViewScale = 1.1;
    formRenderMgr.UpdateFormSize(formId, width, height, borderWidth, formViewScale);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_124 end";
}

/**
 * @tc.name: FormRenderMgrTest_125
 * @tc.desc: 1.test GetFormRenderState function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_125, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_125 start";
    FormRenderMgr formRenderMgr;

    formRenderMgr.GetFormRenderState();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_125 end";
}

/**
 * @tc.name: FormRenderMgrTest_126
 * @tc.desc: 1.test PostOnUnlockTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_126, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_126 start";
    FormRenderMgr formRenderMgr;

    formRenderMgr.PostOnUnlockTask();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_126 end";
}

/**
 * @tc.name: FormRenderMgrTest_127
 * @tc.desc: 1.test GetIsSecondMounted function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_127, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_127 start";
    FormRenderMgr formRenderMgr;

    formRenderMgr.GetIsSecondMounted();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_127 end";
}

/**
 * @tc.name: FormRenderMgrTest_128
 * @tc.desc: 1.test AddAcquireProviderForbiddenTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_128, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_128 start";
    FormRenderMgr formRenderMgr;
    std::string bundleName = "<bundleName>";
    int64_t formId = 1;
    std::function<void()> task;

    formRenderMgr.AddAcquireProviderForbiddenTask(bundleName, formId, task);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_128 end";
}

/**
 * @tc.name: FormRenderMgrTest_129
 * @tc.desc: 1.test checkConnectionsFormIds function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_129, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_129 start";
    FormRenderMgr formRenderMgr;
    std::vector<int64_t> formIds = {1, 2};
    int32_t userId = 100;
    std::vector<int64_t> needconFormIds = {1, 2};

    formRenderMgr.checkConnectionsFormIds(formIds, userId, needconFormIds);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_129 end";
}

/**
 * @tc.name: FormRenderMgrTest_130
 * @tc.desc: 1.test DeleteAcquireForbiddenTasksByBundleName function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_130, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_130 start";
    FormRenderMgr formRenderMgr;
    std::string bundleName = "<bundleName>";

    formRenderMgr.DeleteAcquireForbiddenTasksByBundleName(bundleName);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_130 end";
}

/**
 * @tc.name: FormRenderMgrTest_131
 * @tc.desc: 1.test DeleteAcquireForbiddenTaskByFormId function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_131, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_131 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;

    formRenderMgr.DeleteAcquireForbiddenTaskByFormId(formId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_131 end";
}

/**
 * @tc.name: FormRenderMgrTest_132
 * @tc.desc: 1.test DeletePostRenderFormTask function and privacyLevel is 0.
 *           2.renderInner_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_132, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_132 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;

    formRenderMgr.DeletePostRenderFormTask(formId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_132 end";
}

/**
 * @tc.name: FormRenderMgrTest_133
 * @tc.desc: test NotifyScreenOn function and privacyLevel is 0.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_133, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_133 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    MockGetCurrentAccountIdRet(userId);
    formRenderMgr.NotifyScreenOn();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_133 end";
}

/**
 * @tc.name: FormRenderMgrTest_134
 * @tc.desc: test DisconnectAllRenderConnections function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_134, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_134 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    formRenderMgr.DisconnectAllRenderConnections(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_134 end";
}

/**
 * @tc.name: FormRenderMgrTest_135
 * @tc.desc: test DisconnectAllRenderConnections function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_135, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_135 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    formRenderMgr.DisconnectAllRenderConnections(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_135 end";
}

/**
 * @tc.name: FormRenderMgrTest_136
 * @tc.desc: test DisconnectAllRenderConnections function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_136, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_136 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    formRenderMgr.DisconnectAllRenderConnections(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_136 end";
}

/**
 * @tc.name: FormRenderMgrTest_137
 * @tc.desc: test RerenderAllFormsImmediate function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_137, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_137 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    formRenderMgr.RerenderAllFormsImmediate(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_137 end";
}

/**
 * @tc.name: FormRenderMgrTest_138
 * @tc.desc: test RerenderAllFormsImmediate function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_138, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_138 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    formRenderMgr.RerenderAllFormsImmediate(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_138 end";
}

/**
 * @tc.name: FormRenderMgrTest_139
 * @tc.desc: test RerenderAllFormsImmediate function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_139, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_139 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    formRenderMgr.RerenderAllFormsImmediate(userId);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_139 end";
}

/**
 * @tc.name: FormRenderMgrTest_140
 * @tc.desc: test GetFormRenderMgrInner and GetFormSandboxMgrInner function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_140, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_140 start";
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
    GTEST_LOG_(INFO) << "FormRenderMgrTest_140 end";
}

/**
 * @tc.name: FormRenderMgrTest_141
 * @tc.desc: test SetRenderGroupParams function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_141, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_141 start";
    FormRenderMgr formRenderMgr;
    int32_t userId = 100;
    auto formInner = std::make_shared<FormRenderMgrInner>();
    formInner->SetUserId(userId);
    formRenderMgr.renderInners_.emplace(userId, formInner);
    auto formSandboxInner = std::make_shared<FormSandboxRenderMgrInner>();
    formSandboxInner->SetUserId(userId);
    formRenderMgr.sandboxInners_.emplace(userId, formSandboxInner);
    Want want;
    formRenderMgr.SetRenderGroupParams(1, want);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_141 end";
}

/**
 * @tc.name: FormRenderMgrTest_142
 * @tc.desc: test UpdateRenderingForm function and isGetFormRecord is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_142, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_142 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    MockGetFormRecord(false, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_142 end";
}

/**
 * @tc.name: FormRenderMgrTest_143
 * @tc.desc: test RenderForm function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_143, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_143 start";
    FormRenderMgr formRenderMgr;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::JS;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    EXPECT_EQ(ERR_OK, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_143 end";
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
}
