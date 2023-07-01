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

extern void MockGetFormRecord(bool mockRet);
extern void MockConnectServiceAbility(bool mockRet);

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

class MockIFormRender : public IFormRender {
public:
    int32_t RenderForm(const FormJsInfo &formJsInfo, const Want &want,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }

    int32_t StopRenderingForm(const FormJsInfo &formJsInfo,
        const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }

    int32_t CleanFormHost(const sptr<IRemoteObject> &hostToken) override
    {
        return ERR_OK;
    }

    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
};

/**
 * @tc.name: FormRenderMgrTest_001
 * @tc.desc: test RenderForm function and return ERR_OK
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
 * @tc.desc: test RenderForm function and return ERR_APPEXECFWK_FORM_INVALID_PARAM
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
 * @tc.desc: test RenderForm function and atomicRerenderCount_ is 0
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
    MockConnectServiceAbility(true);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_003 end";
}

/**
 * @tc.name: FormRenderMgrTest_004
 * @tc.desc: 1.test RenderForm function and set atomicRerenderCount_ is 1
 *           2.hostToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_004 start";
    FormRenderMgr formRenderMgr;
    formRenderMgr.atomicRerenderCount_ = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = nullptr;
    MockConnectServiceAbility(true);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_004 end";
}

/**
 * @tc.name: FormRenderMgrTest_005
 * @tc.desc: 1.test RenderForm function and set atomicRerenderCount_ is 1
 *           2.hostToken is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_005 start";
    FormRenderMgr formRenderMgr;
    formRenderMgr.atomicRerenderCount_ = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    MockConnectServiceAbility(true);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_005 end";
}

/**
 * @tc.name: FormRenderMgrTest_006
 * @tc.desc: 1.test RenderForm function and conIterator != renderFormConnections_.end()
 *           2.connection is nullptr and return ERR_APPEXECFWK_FORM_INVALID_PARAM
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_006 start";
    FormRenderMgr formRenderMgr;
    int64_t formIds = 1;
    sptr<FormRenderConnection> formRenderConnections = nullptr;
    formRenderMgr.renderFormConnections_.emplace(formIds, formRenderConnections);
    formRenderMgr.atomicRerenderCount_ = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_006 end";
}

/**
 * @tc.name: FormRenderMgrTest_007
 * @tc.desc: 1.test RenderForm function and conIterator != renderFormConnections_.end().
 *           2.renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_007 start";
    FormRenderMgr formRenderMgr;
    int64_t formIds = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> formRenderConnections = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.renderFormConnections_.emplace(formIds, formRenderConnections);
    formRenderMgr.atomicRerenderCount_ = 1;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 1;
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    MockConnectServiceAbility(true);
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_007 end";
}

/**
 * @tc.name: FormRenderMgrTest_008
 * @tc.desc: 1.test RenderForm function and conIterator != renderFormConnections_.end().
 *           2.renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_008 start";
    FormRenderMgr formRenderMgr;
    int64_t formIds = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> formRenderConnections = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.renderFormConnections_.emplace(formIds, formRenderConnections);
    formRenderMgr.atomicRerenderCount_ = 1;
    formRenderMgr.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    formRecord.uiSyntax = FormType::ETS;
    formRecord.formId = 1;
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    EXPECT_EQ(
        ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.RenderForm(formRecord, wantParams, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_008 end";
}

/**
 * @tc.name: FormRenderMgrTest_009
 * @tc.desc: test UpdateRenderingForm function and isGetFormRecord is false.
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
    MockGetFormRecord(false);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_NOT_EXIST_ID,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_009 end";
}

/**
 * @tc.name: FormRenderMgrTest_010
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.mergeData is true
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_010 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_010 end";
}

/**
 * @tc.name: FormRenderMgrTest_011
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.connection is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_011 start";
    FormRenderMgr formRenderMgr;
    int64_t formIds = 100;
    formRenderMgr.renderFormConnections_.emplace(formIds, nullptr);
    int64_t formId = 1;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = false;
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_011 end";
}

/**
 * @tc.name: FormRenderMgrTest_012
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.renderRemoteObj_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_012 start";
    FormRenderMgr formRenderMgr;
    int64_t formIds = 100;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> formRenderConnections = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.renderFormConnections_.emplace(formIds, formRenderConnections);
    formRenderMgr.renderRemoteObj_ = nullptr;
    int64_t formId = 1;
    FormProviderData formProviderData;
    bool mergeData = false;
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_012 end";
}

/**
 * @tc.name: FormRenderMgrTest_013
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.renderRemoteObj_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_013 start";
    FormRenderMgr formRenderMgr;
    int64_t formIds = 100;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> formRenderConnections = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.renderFormConnections_.emplace(formIds, formRenderConnections);
    formRenderMgr.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    int64_t formId = 1;
    FormProviderData formProviderData;
    bool mergeData = false;
    MockGetFormRecord(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.UpdateRenderingForm(formId, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_013 end";
}

/**
 * @tc.name: FormRenderMgrTest_014
 * @tc.desc: test ReloadForm function and renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_014 start";
    FormRenderMgr formRenderMgr;
    formRenderMgr.renderRemoteObj_ = nullptr;
    std::vector<FormRecord> formRecords;
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.ReloadForm(std::move(formRecords), bundleName, userId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_014 end";
}

/**
 * @tc.name: FormRenderMgrTest_015
 * @tc.desc: test ReloadForm function and renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_015 start";
    FormRenderMgr formRenderMgr;
    formRenderMgr.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    std::vector<FormRecord> formRecords;
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.ReloadForm(std::move(formRecords), bundleName, userId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_015 end";
}

/**
 * @tc.name: FormRenderMgrTest_016
 * @tc.desc: test StopRenderingForm function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_016 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::JS;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_OK,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_016 end";
}

/**
 * @tc.name: FormRenderMgrTest_017
 * @tc.desc: test StopRenderingForm function and formRecord.abilityName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_017 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "";
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_017 end";
}

/**
 * @tc.name: FormRenderMgrTest_018
 * @tc.desc: test StopRenderingForm function and formRecord.bundleName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_018 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "";
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_018 end";
}

/**
 * @tc.name: FormRenderMgrTest_019
 * @tc.desc: test StopRenderingForm function and compId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_019 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    std::string compId = "";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_019 end";
}

/**
 * @tc.name: FormRenderMgrTest_020
 * @tc.desc: 1.test StopRenderingForm function and compId is not empty.
 *           2.connection is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_020 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.formId = 1;
    std::string compId = "compId";
    sptr<FormRenderConnection> formRenderConnections = nullptr;
    formRenderMgr.renderFormConnections_.emplace(formId, formRenderConnections);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_020 end";
}

/**
 * @tc.name: FormRenderMgrTest_021
 * @tc.desc: 1.test StopRenderingForm function and compId is not empty.
 *           2.connection is not nullptr
 *           3.renderRemoteObj_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_021 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.formId = 1;
    std::string compId = "compId";
    WantParams wantParams;
    sptr<FormRenderConnection> formRenderConnections = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.renderFormConnections_.emplace(formId, formRenderConnections);
    formRenderMgr.renderRemoteObj_ = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_021 end";
}

/**
 * @tc.name: FormRenderMgrTest_022
 * @tc.desc: 1.test StopRenderingForm function and compId is not empty.
 *           2.connection is not nullptr
 *           3.remoteObject is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_022 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.formId = 1;
    std::string compId = "compId";
    WantParams wantParams;
    sptr<FormRenderConnection> formRenderConnections = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.renderFormConnections_.emplace(formId, formRenderConnections);
    formRenderMgr.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_022 end";
}

/**
 * @tc.name: FormRenderMgrTest_023
 * @tc.desc: test RenderFormCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_023 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(ERR_OK, formRenderMgr.RenderFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_023 end";
}

/**
 * @tc.name: FormRenderMgrTest_024
 * @tc.desc: test StopRenderingFormCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_024 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_024 end";
}

/**
 * @tc.name: FormRenderMgrTest_025
 * @tc.desc: test StopRenderingFormCallback function and stopConnection is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_025 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    sptr<FormRenderConnection> formRenderConnections = nullptr;
    formRenderMgr.renderFormConnections_.emplace(formId, formRenderConnections);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_025 end";
}

/**
 * @tc.name: FormRenderMgrTest_026
 * @tc.desc: test StopRenderingFormCallback function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_026 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> formRenderConnections = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.renderFormConnections_.emplace(formId, formRenderConnections);
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    form.insert(formId);
    formRenderMgr.etsHosts_.emplace(remote, form);
    EXPECT_EQ(ERR_OK, formRenderMgr.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_026 end";
}

/**
 * @tc.name: FormRenderMgrTest_027
 * @tc.desc: test StopRenderingFormCallback function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_027 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    Want want;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> formRenderConnections = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.renderFormConnections_.emplace(formId, formRenderConnections);
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    form.insert(formId);
    formRenderMgr.etsHosts_.emplace(remote, form);
    std::unordered_set<int64_t> forms;
    int64_t formIds = 2;
    forms.insert(formIds);
    formRenderMgr.etsHosts_.emplace(remote, forms);
    EXPECT_EQ(ERR_OK, formRenderMgr.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_027 end";
}

/**
 * @tc.name: FormRenderMgrTest_028
 * @tc.desc: test AddConnection function and return ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_028 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    sptr<FormRenderConnection> connection = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgr.AddConnection(formId, connection));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_028 end";
}

/**
 * @tc.name: FormRenderMgrTest_029
 * @tc.desc: test AddConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_029 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> connection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    EXPECT_EQ(ERR_OK, formRenderMgr.AddConnection(formId, connection));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_029 end";
}

/**
 * @tc.name: FormRenderMgrTest_030
 * @tc.desc: test AddConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_030 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> connection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr.renderFormConnections_.emplace(formId, connection);
    EXPECT_EQ(ERR_OK, formRenderMgr.AddConnection(formId, connection));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_030 end";
}

/**
 * @tc.name: FormRenderMgrTest_031
 * @tc.desc: 1.test RerenderAllForms function.
 *           2.etsHosts_ is empty.
 *           3.renderFormConnections_ is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_031 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    formRenderMgr->RerenderAllForms();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_031 end";
}

/**
 * @tc.name: FormRenderMgrTest_032
 * @tc.desc: 1.test RerenderAllForms function.
 *           2.etsHosts_ is empty.
 *           3.renderFormConnections_ is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_032 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    int64_t formIds = 1;
    sptr<FormRenderConnection> formRenderConnections = nullptr;
    formRenderMgr->renderFormConnections_.emplace(formIds, formRenderConnections);
    formRenderMgr->RerenderAllForms();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_032 end";
}

/**
 * @tc.name: FormRenderMgrTest_033
 * @tc.desc: 1.test RerenderAllForms function.
 *           2.etsHosts_ is not empty.
 *           3.renderFormConnections_ is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_033 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    int64_t formIds = 1;
    sptr<FormRenderConnection> formRenderConnections = nullptr;
    formRenderMgr->renderFormConnections_.emplace(formIds, formRenderConnections);
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    form.insert(formIds);
    formRenderMgr->etsHosts_.emplace(remote, form);
    formRenderMgr->RerenderAllForms();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_033 end";
}

/**
 * @tc.name: FormRenderMgrTest_034
 * @tc.desc: 1.test RerenderAllForms function.
 *           2.etsHosts_ is not empty.
 *           3.renderFormConnections_ is not empty and item.second is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_034 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    int64_t formIds = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> formRenderConnections = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgr->renderFormConnections_.emplace(formIds, formRenderConnections);
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    form.insert(formIds);
    formRenderMgr->etsHosts_.emplace(remote, form);
    formRenderMgr->RerenderAllForms();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_034 end";
}

/**
 * @tc.name: FormRenderMgrTest_035
 * @tc.desc: test CleanFormHost function and renderRemoteObj_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_035 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    formRenderMgr.CleanFormHost(host);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_035 end";
}

/**
 * @tc.name: FormRenderMgrTest_036
 * @tc.desc: test CleanFormHost function and renderRemoteObj_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_036 start";
    FormRenderMgr formRenderMgr;
    formRenderMgr.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    sptr<IRemoteObject> host = nullptr;
    formRenderMgr.CleanFormHost(host);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_036 end";
}

/**
 * @tc.name: FormRenderMgrTest_037
 * @tc.desc: test AddRenderDeathRecipient function and renderRemoteObj_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_037 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    formRenderMgr->renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    sptr<IRemoteObject> remoteObject = nullptr;
    formRenderMgr->AddRenderDeathRecipient(remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_037 end";
}

/**
 * @tc.name: FormRenderMgrTest_038
 * @tc.desc: test AddRenderDeathRecipient function and remoteObject is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_038 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    formRenderMgr->renderRemoteObj_ = nullptr;
    sptr<IRemoteObject> remoteObject = nullptr;
    formRenderMgr->AddRenderDeathRecipient(remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_038 end";
}

/**
 * @tc.name: FormRenderMgrTest_039
 * @tc.desc: 1.test AddRenderDeathRecipient function and remoteObject is not nullptr
 *           2.renderDeathRecipient_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_039 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    formRenderMgr->renderRemoteObj_ = nullptr;
    formRenderMgr->renderDeathRecipient_ = nullptr;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formRenderMgr->AddRenderDeathRecipient(remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_039 end";
}

/**
 * @tc.name: FormRenderMgrTest_040
 * @tc.desc: 1.test AddRenderDeathRecipient function and remoteObject is not nullptr
 *           2.renderDeathRecipient_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_040 start";
    std::shared_ptr<FormRenderMgr> formRenderMgr = std::make_shared<FormRenderMgr>();
    ASSERT_NE(nullptr, formRenderMgr);
    formRenderMgr->renderRemoteObj_ = nullptr;
    formRenderMgr->renderDeathRecipient_ = nullptr;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    // set renderDeathRecipient_ is not nullptr
    formRenderMgr->AddRenderDeathRecipient(remoteObject);
    // test AddRenderDeathRecipient function
    formRenderMgr->AddRenderDeathRecipient(remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_040 end";
}

/**
 * @tc.name: FormRenderMgrTest_041
 * @tc.desc: test DisconnectRenderService function and size is LAST_CONNECTION
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_041 start";
    FormRenderMgr formRenderMgr;
    sptr<FormRenderConnection> connection = nullptr;
    size_t size = 1;
    formRenderMgr.DisconnectRenderService(connection, size);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_041 end";
}

/**
 * @tc.name: FormRenderMgrTest_042
 * @tc.desc: test DisconnectRenderService function and size is not LAST_CONNECTION
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_042 start";
    FormRenderMgr formRenderMgr;
    sptr<FormRenderConnection> connection = nullptr;
    size_t size = 2;
    formRenderMgr.DisconnectRenderService(connection, size);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_042 end";
}

/**
 * @tc.name: FormRenderMgrTest_043
 * @tc.desc: test IsNeedRender function and isGetFormRecord is false
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_043 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    MockGetFormRecord(false);
    EXPECT_EQ(false, formRenderMgr.IsNeedRender(formId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_043 end";
}

/**
 * @tc.name: FormRenderMgrTest_044
 * @tc.desc: 1.test IsNeedRender function and isGetFormRecord is true
 *           2.formRecord.uiSyntax != FormType::ETS
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_044 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    MockGetFormRecord(true);
    EXPECT_EQ(false, formRenderMgr.IsNeedRender(formId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_044 end";
}

/**
 * @tc.name: FormRenderMgrTest_045
 * @tc.desc: 1.test RemoveHostToken function and iter == etsHosts_.end()
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_045 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> host = nullptr;
    formRenderMgr.RemoveHostToken(host);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_045 end";
}

/**
 * @tc.name: FormRenderMgrTest_046
 * @tc.desc: 1.test RemoveHostToken function and iter != etsHosts_.end()
 *           2.GetFormRecord is false
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_046 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    int64_t formId = 1;
    form.insert(formId);
    formRenderMgr.etsHosts_.emplace(remote, form);
    sptr<IRemoteObject> host = nullptr;
    MockGetFormRecord(false);
    formRenderMgr.RemoveHostToken(host);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_046 end";
}

/**
 * @tc.name: FormRenderMgrTest_047
 * @tc.desc: 1.test RemoveHostToken function and iter != etsHosts_.end()
 *           2.GetFormRecord is true
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_047 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    int64_t formId = 1;
    form.insert(formId);
    formRenderMgr.etsHosts_.emplace(remote, form);
    sptr<IRemoteObject> host = nullptr;
    MockGetFormRecord(true);
    formRenderMgr.RemoveHostToken(host);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_047 end";
}

/**
 * @tc.name: FormRenderMgrTest_048
 * @tc.desc: test NotifyHostRenderServiceIsDead function and hostClient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_048 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    int64_t formId = 1;
    form.insert(formId);
    formRenderMgr.etsHosts_.emplace(remote, form);
    formRenderMgr.NotifyHostRenderServiceIsDead();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_048 end";
}

/**
 * @tc.name: FormRenderMgrTest_049
 * @tc.desc: test NotifyHostRenderServiceIsDead function and hostClient is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_049, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_049 start";
    FormRenderMgr formRenderMgr;
    sptr<IRemoteObject> remote = new (std::nothrow) MockFormProviderClient();
    std::unordered_set<int64_t> form;
    int64_t formId = 1;
    form.insert(formId);
    formRenderMgr.etsHosts_.emplace(remote, form);
    formRenderMgr.NotifyHostRenderServiceIsDead();
    GTEST_LOG_(INFO) << "FormRenderMgrTest_049 end";
}

/**
 * @tc.name: FormRenderMgrTest_050
 * @tc.desc: test HandleConnectFailed function and hostClient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_050, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_050 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    int32_t errorCode = 2;
    formRenderMgr.HandleConnectFailed(formId, errorCode);
    GTEST_LOG_(INFO) << "FormRenderMgrTest_050 end";
}

/**
 * @tc.name: FormRenderMgrTest_051
 * @tc.desc: test IsRerenderForRenderServiceDied function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_051, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_051 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    EXPECT_EQ(false, formRenderMgr.IsRerenderForRenderServiceDied(formId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_051 end";
}
}

/**
 * @tc.name: FormRenderMgrTest_052
 * @tc.desc: test RemoveConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_052, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_052 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    formRenderMgr.renderFormConnections_.emplace(formId, nullptr);
    EXPECT_EQ(1, formRenderMgr.renderFormConnections_.size());
    formRenderMgr.RemoveConnection(formId);
    EXPECT_EQ(0, formRenderMgr.renderFormConnections_.size());
    GTEST_LOG_(INFO) << "FormRenderMgrTest_052 end";
}

/**
 * @tc.name: FormRenderMgrTest_053
 * @tc.desc: test RemoveConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_053, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_053 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    EXPECT_EQ(0, formRenderMgr.renderFormConnections_.size());
    formRenderMgr.RemoveConnection(formId);
    EXPECT_EQ(0, formRenderMgr.renderFormConnections_.size());
    GTEST_LOG_(INFO) << "FormRenderMgrTest_053 end";
}

/**
 * @tc.name: FormRenderMgrTest_054
 * @tc.desc: test RemoveConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrTest, FormRenderMgrTest_054, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrTest_054 start";
    FormRenderMgr formRenderMgr;
    int64_t formId = 1;
    int64_t formIdOther = 2;
    formRenderMgr.renderFormConnections_.emplace(formId, nullptr);
    EXPECT_EQ(1, formRenderMgr.renderFormConnections_.size());
    formRenderMgr.RemoveConnection(formIdOther);
    EXPECT_EQ(1, formRenderMgr.renderFormConnections_.size());
    GTEST_LOG_(INFO) << "FormRenderMgrTest_054 end";
}
