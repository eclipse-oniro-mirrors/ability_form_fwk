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
#include "form_render/form_render_mgr_inner.h"
#undef private
#include "ipc_types.h"
#include "fms_log_wrapper.h"
#include "mock_form_provider_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockGetFormRecord(bool mockRet, int32_t type);
extern void MockConnectServiceAbility(bool mockRet);
extern void MockDisconnectServiceAbility(bool mockRet);

namespace {
class FormRenderMgrInnerTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};

void FormRenderMgrInnerTest::SetUp()
{}

void FormRenderMgrInnerTest::TearDown()
{}

class MockIFormRender : public IFormRender {
public:
    int32_t RenderForm(const FormJsInfo &formJsInfo, const Want &want,
        sptr<IRemoteObject> callerToken) override
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
 * @tc.name: FormRenderMgrInnerTest_001
 * @tc.desc: test RenderForm function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_001 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    Want want;
    sptr<IRemoteObject> hostToken = nullptr;
    MockConnectServiceAbility(false);
    EXPECT_EQ(ERR_OK, formRenderMgrInner.RenderForm(formRecord, want, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_001 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_002
 * @tc.desc: test RenderForm function and atomicRerenderCount_ is 1.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_002 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    Want want;
    bool isVerified = false;
    formRenderMgrInner.atomicRerenderCount_ = 1;
    sptr<IRemoteObject> hostToken = nullptr;
    MockConnectServiceAbility(false);
    EXPECT_EQ(
        ERR_OK, formRenderMgrInner.RenderForm(formRecord, want, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_002 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_003
 * @tc.desc: test RenderForm function and hostToken is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_003 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    Want want;
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();;
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        formRenderMgrInner.RenderForm(formRecord, want, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_003 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_004
 * @tc.desc: 1.test RenderForm function and conn is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_004 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    Want want;
    sptr<IRemoteObject> hostToken = nullptr;
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.RenderForm(formRecord, want, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_004 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_005
 * @tc.desc: 1.test RenderForm function and conIterator != renderFormConnections_.end().
 *           2.renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_005 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    Want want;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    sptr<IRemoteObject> hostToken = nullptr;
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,
        formRenderMgrInner.RenderForm(formRecord, want, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_005 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_006
 * @tc.desc: 1.test RenderForm function and conIterator != renderFormConnections_.end().
 *           2.renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_006 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    Want want;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    sptr<IRemoteObject> hostToken = nullptr;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.RenderForm(formRecord, want, hostToken));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_006 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_007
 * @tc.desc: test UpdateRenderingForm function and isGetFormRecord is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_007 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = false;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.UpdateRenderingForm(formRecord, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_007 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_008
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.mergeData is true
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_008 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = true;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.UpdateRenderingForm(formRecord, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_008 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_009
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.connection is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_009 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, nullptr);
    FormProviderData formProviderData;
    WantParams wantParams;
    bool mergeData = false;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.UpdateRenderingForm(formRecord, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_009 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_010
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.renderRemoteObj_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_010 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    FormProviderData formProviderData;
    bool mergeData = false;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.UpdateRenderingForm(formRecord, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_010 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_011
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.renderRemoteObj_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_011 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    FormProviderData formProviderData;
    bool mergeData = false;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.UpdateRenderingForm(formRecord, formProviderData, wantParams, mergeData));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_011 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_012
 * @tc.desc: test ReloadForm function and renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_012 start";
    FormRenderMgrInner formRenderMgrInner;
    std::vector<FormRecord> formRecords;
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.ReloadForm(std::move(formRecords), bundleName, userId));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_012 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_013
 * @tc.desc: test ReloadForm function and renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_013 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    std::vector<FormRecord> formRecords;
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.ReloadForm(std::move(formRecords), bundleName, userId));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_013 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_014
 * @tc.desc: test FillBundleInfo function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_014 start";
    FormRenderMgrInner formRenderMgrInner;
    std::string bundleName = "<bundleName>";
    Want want;
    int32_t userId = 100;
    formRenderMgrInner.FillBundleInfo(want, bundleName, userId);
    EXPECT_EQ(true, want.HasParameter(Constants::FORM_COMPATIBLE_VERSION_KEY));
    EXPECT_EQ(true, want.HasParameter(Constants::FORM_TARGET_VERSION_KEY));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_014 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_015
 * @tc.desc: test StopRenderingForm function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_015 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::JS;
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_OK,
        formRenderMgrInner.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_015 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_016
 * @tc.desc: test StopRenderingForm function and formRecord.abilityName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_016 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "";
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_016 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_017
 * @tc.desc: test StopRenderingForm function and formRecord.bundleName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_017 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "";
    std::string compId = "<compId>";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_017 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_018
 * @tc.desc: test StopRenderingForm function and compId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_018 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    std::string compId = "";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.StopRenderingForm(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_018 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_019
 * @tc.desc: 1.test StopRenderingForm function and compId is not empty.
 *           2.connection is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_019 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.formId = 1;
    std::string compId = "compId";
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.StopRenderingForm(formRecord.formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_019 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_020
 * @tc.desc: 1.test StopRenderingForm function and compId is not empty.
 *           2.connection is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_020 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.formId = 1;
    std::string compId = "compId";
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.StopRenderingForm(formRecord.formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_020 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_021
 * @tc.desc: 1.test StopRenderingForm function and compId is not empty.
 *           2.connection is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_021 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.formId = 1;
    std::string compId = "compId";
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.StopRenderingForm(formRecord.formId, formRecord, compId));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_021 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_022
 * @tc.desc: test StopRenderingFormCallback function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_022 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_022 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_023
 * @tc.desc: test StopRenderingFormCallback function and stopConnection is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_023 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    Want want;
    formRenderMgrInner.renderFormConnections_.emplace(formId, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_023 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_024
 * @tc.desc: test StopRenderingFormCallback function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_024 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    Want want;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, conn);
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    form.insert(formId);
    formRenderMgrInner.etsHosts_.emplace(remote, form);
    EXPECT_EQ(ERR_OK, formRenderMgrInner.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_024 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_025
 * @tc.desc: test StopRenderingFormCallback function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_025 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    Want want;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, conn);
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    form.insert(formId);
    formRenderMgrInner.etsHosts_.emplace(remote, form);
    std::unordered_set<int64_t> forms;
    int64_t formIds = 2;
    forms.insert(formIds);
    formRenderMgrInner.etsHosts_.emplace(remote, forms);
    EXPECT_EQ(ERR_OK, formRenderMgrInner.StopRenderingFormCallback(formId, want));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_025 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_026
 * @tc.desc: test AddConnection function and return ERR_APPEXECFWK_FORM_INVALID_PARAM.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_026 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    sptr<FormRenderConnection> connection = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.AddConnection(formId, connection));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_026 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_027
 * @tc.desc: test AddConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_027 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> connection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    EXPECT_EQ(ERR_OK, formRenderMgrInner.AddConnection(formId, connection));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_027 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_028
 * @tc.desc: test AddConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_028 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> connection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, connection);
    EXPECT_EQ(ERR_OK, formRenderMgrInner.AddConnection(formId, connection));
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_028 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_029
 * @tc.desc: 1.test RerenderAllForms function.
 *           2.etsHosts_ is empty.
 *           3.renderFormConnections_ is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_029 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    formRenderMgrInner->RerenderAllForms();
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_029 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_030
 * @tc.desc: 1.test RerenderAllForms function.
 *           2.etsHosts_ is empty.
 *           3.renderFormConnections_ is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_030 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    int64_t formIds = 1;
    formRenderMgrInner->renderFormConnections_.emplace(formIds, nullptr);
    formRenderMgrInner->RerenderAllForms();
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_030 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_031
 * @tc.desc: 1.test RerenderAllForms function.
 *           2.etsHosts_ is not empty.
 *           3.renderFormConnections_ is not empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_031 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    int64_t formIds = 1;
    sptr<FormRenderConnection> conn = nullptr;
    formRenderMgrInner->renderFormConnections_.emplace(formIds, conn);
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    form.insert(formIds);
    formRenderMgrInner->etsHosts_.emplace(remote, form);
    formRenderMgrInner->RerenderAllForms();
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_031 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_032
 * @tc.desc: 1.test RerenderAllForms function.
 *           2.etsHosts_ is not empty.
 *           3.renderFormConnections_ is not empty and item.second is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_032, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_032 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    int64_t formIds = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner->renderFormConnections_.emplace(formIds, conn);
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    form.insert(formIds);
    formRenderMgrInner->etsHosts_.emplace(remote, form);
    formRenderMgrInner->RerenderAllForms();
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_032 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_033
 * @tc.desc: test CleanFormHost function and renderRemoteObj_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_033 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<IRemoteObject> host = nullptr;
    formRenderMgrInner.CleanFormHost(host);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_033 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_034
 * @tc.desc: test CleanFormHost function and renderRemoteObj_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_034 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    sptr<IRemoteObject> host = nullptr;
    formRenderMgrInner.CleanFormHost(host);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_034 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_035
 * @tc.desc: test AddRenderDeathRecipient function and renderRemoteObj_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_035 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    formRenderMgrInner->renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    sptr<IRemoteObject> remoteObject = nullptr;
    formRenderMgrInner->AddRenderDeathRecipient(remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_035 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_036
 * @tc.desc: test AddRenderDeathRecipient function and remoteObject is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_036 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    formRenderMgrInner->renderRemoteObj_ = nullptr;
    sptr<IRemoteObject> remoteObject = nullptr;
    formRenderMgrInner->AddRenderDeathRecipient(remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_036 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_037
 * @tc.desc: 1.test AddRenderDeathRecipient function and remoteObject is not nullptr
 *           2.renderDeathRecipient_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_037 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    formRenderMgrInner->renderRemoteObj_ = nullptr;
    formRenderMgrInner->renderDeathRecipient_ = nullptr;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formRenderMgrInner->AddRenderDeathRecipient(remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_037 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_038
 * @tc.desc: 1.test AddRenderDeathRecipient function and remoteObject is not nullptr
 *           2.renderDeathRecipient_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_038 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    formRenderMgrInner->renderRemoteObj_ = nullptr;
    formRenderMgrInner->renderDeathRecipient_ = nullptr;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    // set renderDeathRecipient_ is not nullptr
    formRenderMgrInner->AddRenderDeathRecipient(remoteObject);
    // test AddRenderDeathRecipient function
    formRenderMgrInner->AddRenderDeathRecipient(remoteObject);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_038 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_039
 * @tc.desc: test DisconnectRenderService function and size is LAST_CONNECTION
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_039 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<FormRenderConnection> connection = nullptr;
    size_t size = 1;
    formRenderMgrInner.DisconnectRenderService(connection, size);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_039 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_040
 * @tc.desc: test DisconnectRenderService function and size is not LAST_CONNECTION
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_040 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<FormRenderConnection> connection = nullptr;
    MockDisconnectServiceAbility(true);
    size_t size = 2;
    formRenderMgrInner.DisconnectRenderService(connection, size);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_040 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_041
 * @tc.desc: 1.test RemoveHostToken function and iter == etsHosts_.end()
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_041 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<IRemoteObject> host = nullptr;
    formRenderMgrInner.RemoveHostToken(host);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_041 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_042
 * @tc.desc: 1.test RemoveHostToken function and iter != etsHosts_.end()
 *           2.GetFormRecord is false
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_042 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    int64_t formId = 1;
    form.insert(formId);
    formRenderMgrInner.etsHosts_.emplace(remote, form);
    sptr<IRemoteObject> host = nullptr;
    MockGetFormRecord(false, 0);
    formRenderMgrInner.RemoveHostToken(host);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_042 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_043
 * @tc.desc: 1.test RemoveHostToken function and iter != etsHosts_.end()
 *           2.GetFormRecord is true
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_043 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    int64_t formId = 1;
    form.insert(formId);
    formRenderMgrInner.etsHosts_.emplace(remote, form);
    sptr<IRemoteObject> host = nullptr;
    MockGetFormRecord(true, 0);
    formRenderMgrInner.RemoveHostToken(host);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_043 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_044
 * @tc.desc: test NotifyHostRenderServiceIsDead function and hostClient is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_044 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    int64_t formId = 1;
    form.insert(formId);
    formRenderMgrInner.etsHosts_.emplace(remote, form);
    formRenderMgrInner.NotifyHostRenderServiceIsDead();
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_044 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_045
 * @tc.desc: test NotifyHostRenderServiceIsDead function and hostClient is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_045 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<IRemoteObject> remote = new (std::nothrow) MockFormProviderClient();
    std::unordered_set<int64_t> form;
    int64_t formId = 1;
    form.insert(formId);
    formRenderMgrInner.etsHosts_.emplace(remote, form);
    formRenderMgrInner.NotifyHostRenderServiceIsDead();
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_045 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_046
 * @tc.desc: test RemoveConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_046 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    formRenderMgrInner.renderFormConnections_.emplace(formId, nullptr);
    EXPECT_EQ(1, formRenderMgrInner.renderFormConnections_.size());
    formRenderMgrInner.RemoveConnection(formId);
    EXPECT_EQ(0, formRenderMgrInner.renderFormConnections_.size());
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_046 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_047
 * @tc.desc: test RemoveConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_047 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    EXPECT_EQ(0, formRenderMgrInner.renderFormConnections_.size());
    formRenderMgrInner.RemoveConnection(formId);
    EXPECT_EQ(0, formRenderMgrInner.renderFormConnections_.size());
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_047 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_048
 * @tc.desc: test RemoveConnection function and return ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_048 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    int64_t formIdOther = 2;
    formRenderMgrInner.renderFormConnections_.emplace(formId, nullptr);
    EXPECT_EQ(1, formRenderMgrInner.renderFormConnections_.size());
    formRenderMgrInner.RemoveConnection(formIdOther);
    EXPECT_EQ(1, formRenderMgrInner.renderFormConnections_.size());
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_048 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_049
 * @tc.desc: test GetConnectionAndRenderForm function runs normally and returns the expected result.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_049, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_049 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    Want want;
    EXPECT_EQ(formRenderMgrInner.GetConnectionAndRenderForm(formRecord, want),
              ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_049 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_050
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.connection is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_050, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_050 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, nullptr);
    Want want;
    EXPECT_EQ(formRenderMgrInner.GetConnectionAndRenderForm(formRecord, want),
              ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_050 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_051
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.renderRemoteObj_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_051, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_051 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    Want want;
    EXPECT_EQ(formRenderMgrInner.GetConnectionAndRenderForm(formRecord, want),
              ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_051 end";
}

/**
 * @tc.name: FormRenderMgrInnerTest_052
 * @tc.desc: 1.test UpdateRenderingForm function and isGetFormRecord is true.
 *           2.renderRemoteObj_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, FormRenderMgrInnerTest_052, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_052 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    Want want;
    EXPECT_EQ(formRenderMgrInner.GetConnectionAndRenderForm(formRecord, want),
              ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormRenderMgrInnerTest_052 end";
}

/**
 * @tc.name: NotifyScreenOn_001
 * @tc.desc: test NotifyScreenOn function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, NotifyScreenOn_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "NotifyScreenOn_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    formRenderMgrInner.NotifyScreenOn();
    GTEST_LOG_(INFO) << "NotifyScreenOn_001 end";
}

/**
 * @tc.name: SetUserId_001
 * @tc.desc: test SetUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, SetUserId_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetUserId_001 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    int32_t userId = 100;
    formRenderMgrInner->SetUserId(userId);
    GTEST_LOG_(INFO) << "SetUserId_001 end";
}


/**
 * @tc.name: GetUserId_001
 * @tc.desc: test SetUserId function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetUserId_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetUserId_001 start";
    std::shared_ptr<FormRenderMgrInner> formRenderMgrInner = std::make_shared<FormRenderMgrInner>();
    ASSERT_NE(nullptr, formRenderMgrInner);
    int32_t userId = 100;
    formRenderMgrInner->SetUserId(userId);
    EXPECT_EQ(userId, formRenderMgrInner->GetUserId());
    GTEST_LOG_(INFO) << "GetUserId_001 end";
}

/**
 * @tc.name: RerenderAllFormsImmediate_001
 * @tc.desc: test RerenderAllFormsImmediate function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RerenderAllFormsImmediate_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.RerenderAllFormsImmediate();
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_001 end";
}

/**
 * @tc.name: RerenderAllFormsImmediate_002
 * @tc.desc: test RerenderAllFormsImmediate function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RerenderAllFormsImmediate_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_002 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<IRemoteObject> remote = nullptr;
    std::unordered_set<int64_t> form;
    int64_t formId = 1;
    form.insert(formId);
    formRenderMgrInner.etsHosts_.emplace(remote, form);
    formRenderMgrInner.RerenderAllFormsImmediate();
    GTEST_LOG_(INFO) << "RerenderAllFormsImmediate_002 end";
}

/**
 * @tc.name: DisconnectAllRenderConnections_001
 * @tc.desc: test DisconnectAllRenderConnections function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, DisconnectAllRenderConnections_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_001 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    formRenderMgrInner.renderFormConnections_.emplace(formId, nullptr);
    EXPECT_EQ(1, formRenderMgrInner.renderFormConnections_.size());
    formRenderMgrInner.DisconnectAllRenderConnections();
    EXPECT_EQ(0, formRenderMgrInner.renderFormConnections_.size());
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_001 end";
}

/**
 * @tc.name: DisconnectAllRenderConnections_002
 * @tc.desc: test DisconnectAllRenderConnections function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, DisconnectAllRenderConnections_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_002 start";
    FormRenderMgrInner formRenderMgrInner;
    EXPECT_EQ(0, formRenderMgrInner.renderFormConnections_.size());
    formRenderMgrInner.DisconnectAllRenderConnections();
    EXPECT_EQ(0, formRenderMgrInner.renderFormConnections_.size());
    GTEST_LOG_(INFO) << "DisconnectAllRenderConnections_002 end";
}

/**
 * @tc.name: PostSetRenderGroupParamsTask_001
 * @tc.desc: test PostSetRenderGroupParamsTask function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostSetRenderGroupParamsTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostSetRenderGroupParamsTask_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    Want want;
    formRenderMgrInner.PostSetRenderGroupParamsTask(1, want);
    GTEST_LOG_(INFO) << "PostSetRenderGroupParamsTask_001 end";
}

/**
 * @tc.name: PostSetRenderGroupParamsTask_002
 * @tc.desc: test PostSetRenderGroupParamsTask function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostSetRenderGroupParamsTask_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostSetRenderGroupParamsTask_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    Want want;
    formRenderMgrInner.PostSetRenderGroupParamsTask(1, want);
    GTEST_LOG_(INFO) << "PostSetRenderGroupParamsTask_002 end";
}

/**
 * @tc.name: PostSetRenderGroupEnableFlagTask_001
 * @tc.desc: test PostSetRenderGroupEnableFlagTask function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostSetRenderGroupEnableFlagTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostSetRenderGroupEnableFlagTask_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    int64_t formId = 1;
    bool isEnable = true;
    formRenderMgrInner.PostSetRenderGroupEnableFlagTask(formId, isEnable);
    GTEST_LOG_(INFO) << "PostSetRenderGroupEnableFlagTask_001 end";
}

/**
 * @tc.name: PostSetRenderGroupEnableFlagTask_002
 * @tc.desc: test PostSetRenderGroupEnableFlagTask function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostSetRenderGroupEnableFlagTask_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostSetRenderGroupEnableFlagTask_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    int64_t formId = 1;
    bool isEnable = true;
    formRenderMgrInner.PostSetRenderGroupEnableFlagTask(formId, isEnable);
    GTEST_LOG_(INFO) << "PostSetRenderGroupEnableFlagTask_002 end";
}

/**
 * @tc.name: PostSetVisibleChangeTask_001
 * @tc.desc: test PostSetVisibleChangeTask function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostSetVisibleChangeTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostSetVisibleChangeTask_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    int64_t formId = 1;
    bool isVisible = true;
    formRenderMgrInner.PostSetVisibleChangeTask(formId, isVisible);
    GTEST_LOG_(INFO) << "PostSetVisibleChangeTask_001 end";
}

/**
 * @tc.name: PostSetVisibleChangeTask_002
 * @tc.desc: test PostSetVisibleChangeTask function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostSetVisibleChangeTask_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostSetVisibleChangeTask_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    int64_t formId = 1;
    bool isVisible = true;
    formRenderMgrInner.PostSetVisibleChangeTask(formId, isVisible);
    GTEST_LOG_(INFO) << "PostSetVisibleChangeTask_002 end";
}

/**
 * @tc.name: PostSetVisibleChangeTask_003
 * @tc.desc: test PostSetVisibleChangeTask function when isVisible is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostSetVisibleChangeTask_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostSetVisibleChangeTask_003 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    int64_t formId = 1;
    bool isVisible = false;
    formRenderMgrInner.PostSetVisibleChangeTask(formId, isVisible);
    GTEST_LOG_(INFO) << "PostSetVisibleChangeTask_003 end";
}

/**
 * @tc.name: ReleaseRenderer_001
 * @tc.desc: test ReleaseRenderer function when uiSyntax is JS.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, ReleaseRenderer_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_001 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::JS;
    std::string compId = "compId";
    EXPECT_EQ(ERR_OK, formRenderMgrInner.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "ReleaseRenderer_001 end";
}

/**
 * @tc.name: ReleaseRenderer_002
 * @tc.desc: test ReleaseRenderer function when abilityName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, ReleaseRenderer_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_002 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "";
    std::string compId = "compId";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "ReleaseRenderer_002 end";
}

/**
 * @tc.name: ReleaseRenderer_003
 * @tc.desc: test ReleaseRenderer function when bundleName is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, ReleaseRenderer_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_003 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "";
    std::string compId = "compId";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "ReleaseRenderer_003 end";
}

/**
 * @tc.name: ReleaseRenderer_004
 * @tc.desc: test ReleaseRenderer function when connection does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, ReleaseRenderer_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_004 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    std::string compId = "compId";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "ReleaseRenderer_004 end";
}

/**
 * @tc.name: ReleaseRenderer_005
 * @tc.desc: test ReleaseRenderer function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, ReleaseRenderer_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_005 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    std::string compId = "compId";
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, conn);
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "ReleaseRenderer_005 end";
}

/**
 * @tc.name: ReleaseRenderer_006
 * @tc.desc: test ReleaseRenderer function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, ReleaseRenderer_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_006 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.providerUserId = 100;
    formRecord.isDynamic = true;
    std::string compId = "compId";
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, conn);
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.ReleaseRenderer(formId, formRecord, compId));
    GTEST_LOG_(INFO) << "ReleaseRenderer_006 end";
}

/**
 * @tc.name: RecycleForms_001
 * @tc.desc: test RecycleForms function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RecycleForms_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RecycleForms_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    std::vector<int64_t> formIds = {1, 2, 3};
    Want want;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.RecycleForms(formIds, want, remoteObjectOfHost));
    GTEST_LOG_(INFO) << "RecycleForms_001 end";
}

/**
 * @tc.name: RecycleForms_002
 * @tc.desc: test RecycleForms function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RecycleForms_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RecycleForms_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    std::vector<int64_t> formIds = {1};
    Want want;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(FormRecord(), wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(1, conn);
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.RecycleForms(formIds, want, remoteObjectOfHost));
    GTEST_LOG_(INFO) << "RecycleForms_002 end";
}

/**
 * @tc.name: RecoverForms_001
 * @tc.desc: test RecoverForms function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RecoverForms_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RecoverForms_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    std::vector<int64_t> formIds = {1, 2, 3};
    WantParams wantParams;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.RecoverForms(formIds, wantParams));
    GTEST_LOG_(INFO) << "RecoverForms_001 end";
}

/**
 * @tc.name: RecoverForms_002
 * @tc.desc: test RecoverForms function when renderRemoteObj_ is not nullptr and form record not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RecoverForms_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RecoverForms_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    std::vector<int64_t> formIds = {1};
    WantParams wantParams;
    MockGetFormRecord(false, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.RecoverForms(formIds, wantParams));
    GTEST_LOG_(INFO) << "RecoverForms_002 end";
}

/**
 * @tc.name: RecoverForms_003
 * @tc.desc: test RecoverForms function when connection does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RecoverForms_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RecoverForms_003 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    std::vector<int64_t> formIds = {1};
    WantParams wantParams;
    MockGetFormRecord(true, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.RecoverForms(formIds, wantParams));
    GTEST_LOG_(INFO) << "RecoverForms_003 end";
}

/**
 * @tc.name: RecoverForms_004
 * @tc.desc: test RecoverForms function when connection exists.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RecoverForms_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RecoverForms_004 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    std::vector<int64_t> formIds = {100};
    WantParams wantParams;
    FormRecord formRecord;
    formRecord.formId = 100;
    formRecord.providerUserId = 100;
    formRecord.bundleName = "bundleName";
    WantParams connWantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, connWantParams);
    formRenderMgrInner.renderFormConnections_.emplace(100, conn);
    MockGetFormRecord(true, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.RecoverForms(formIds, wantParams));
    GTEST_LOG_(INFO) << "RecoverForms_004 end";
}

/**
 * @tc.name: UpdateFormSize_001
 * @tc.desc: test UpdateFormSize function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, UpdateFormSize_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "UpdateFormSize_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    int64_t formId = 1;
    float width = 100.0f;
    float height = 100.0f;
    float borderWidth = 1.0f;
    float formViewScale = 1.0f;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, 
        formRenderMgrInner.UpdateFormSize(formId, width, height, borderWidth, formViewScale));
    GTEST_LOG_(INFO) << "UpdateFormSize_001 end";
}

/**
 * @tc.name: UpdateFormSize_002
 * @tc.desc: test UpdateFormSize function when form record not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, UpdateFormSize_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "UpdateFormSize_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    int64_t formId = 1;
    float width = 100.0f;
    float height = 100.0f;
    float borderWidth = 1.0f;
    float formViewScale = 1.0f;
    MockGetFormRecord(false, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.UpdateFormSize(formId, width, height, borderWidth, formViewScale));
    GTEST_LOG_(INFO) << "UpdateFormSize_002 end";
}

/**
 * @tc.name: UpdateFormSize_003
 * @tc.desc: test UpdateFormSize function when form record exists.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, UpdateFormSize_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "UpdateFormSize_003 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    int64_t formId = 100;
    float width = 100.0f;
    float height = 100.0f;
    float borderWidth = 1.0f;
    float formViewScale = 1.0f;
    MockGetFormRecord(true, 0);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.UpdateFormSize(formId, width, height, borderWidth, formViewScale));
    GTEST_LOG_(INFO) << "UpdateFormSize_003 end";
}

/**
 * @tc.name: GetRenderObject_001
 * @tc.desc: test GetRenderObject function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetRenderObject_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetRenderObject_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    sptr<IRemoteObject> renderObj;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.GetRenderObject(renderObj));
    GTEST_LOG_(INFO) << "GetRenderObject_001 end";
}

/**
 * @tc.name: GetRenderObject_002
 * @tc.desc: test GetRenderObject function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetRenderObject_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetRenderObject_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    sptr<IRemoteObject> renderObj;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.GetRenderObject(renderObj));
    GTEST_LOG_(INFO) << "GetRenderObject_002 end";
}

/**
 * @tc.name: GetRenderFormConnectId_001
 * @tc.desc: test GetRenderFormConnectId function when connection not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetRenderFormConnectId_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetRenderFormConnectId_001 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    int32_t connectId = 0;
    EXPECT_FALSE(formRenderMgrInner.GetRenderFormConnectId(formId, connectId));
    GTEST_LOG_(INFO) << "GetRenderFormConnectId_001 end";
}

/**
 * @tc.name: GetRenderFormConnectId_002
 * @tc.desc: test GetRenderFormConnectId function when connection is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetRenderFormConnectId_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetRenderFormConnectId_002 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    int32_t connectId = 0;
    formRenderMgrInner.renderFormConnections_.emplace(formId, nullptr);
    EXPECT_FALSE(formRenderMgrInner.GetRenderFormConnectId(formId, connectId));
    GTEST_LOG_(INFO) << "GetRenderFormConnectId_002 end";
}

/**
 * @tc.name: GetRenderFormConnectId_003
 * @tc.desc: test GetRenderFormConnectId function when connection exists.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetRenderFormConnectId_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetRenderFormConnectId_003 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    int32_t connectId = 0;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, conn);
    EXPECT_TRUE(formRenderMgrInner.GetRenderFormConnectId(formId, connectId));
    GTEST_LOG_(INFO) << "GetRenderFormConnectId_003 end";
}

/**
 * @tc.name: GetRenderFormConnection_001
 * @tc.desc: test GetRenderFormConnection function when connection not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetRenderFormConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetRenderFormConnection_001 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    sptr<FormRenderConnection> connection;
    EXPECT_FALSE(formRenderMgrInner.GetRenderFormConnection(connection, formId));
    GTEST_LOG_(INFO) << "GetRenderFormConnection_001 end";
}

/**
 * @tc.name: GetRenderFormConnection_002
 * @tc.desc: test GetRenderFormConnection function when connection exists.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetRenderFormConnection_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetRenderFormConnection_002 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, conn);
    sptr<FormRenderConnection> connection;
    EXPECT_TRUE(formRenderMgrInner.GetRenderFormConnection(connection, formId));
    EXPECT_NE(connection, nullptr);
    GTEST_LOG_(INFO) << "GetRenderFormConnection_002 end";
}

/**
 * @tc.name: GetConnectedForms_001
 * @tc.desc: test GetConnectedForms function when no connection.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetConnectedForms_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetConnectedForms_001 start";
    FormRenderMgrInner formRenderMgrInner;
    std::vector<int64_t> formIds = {1, 2, 3};
    std::vector<int64_t> connectedForms;
    formRenderMgrInner.GetConnectedForms(formIds, connectedForms);
    EXPECT_EQ(0, connectedForms.size());
    GTEST_LOG_(INFO) << "GetConnectedForms_001 end";
}

/**
 * @tc.name: GetConnectedForms_002
 * @tc.desc: test GetConnectedForms function with connection nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetConnectedForms_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetConnectedForms_002 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    formRenderMgrInner.renderFormConnections_.emplace(formId, nullptr);
    std::vector<int64_t> formIds = {formId};
    std::vector<int64_t> connectedForms;
    formRenderMgrInner.GetConnectedForms(formIds, connectedForms);
    EXPECT_EQ(0, connectedForms.size());
    GTEST_LOG_(INFO) << "GetConnectedForms_002 end";
}

/**
 * @tc.name: GetConnectedForms_003
 * @tc.desc: test GetConnectedForms function with valid connection.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetConnectedForms_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetConnectedForms_003 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, conn);
    std::vector<int64_t> formIds = {formId};
    std::vector<int64_t> connectedForms;
    formRenderMgrInner.GetConnectedForms(formIds, connectedForms);
    EXPECT_EQ(1, connectedForms.size());
    GTEST_LOG_(INFO) << "GetConnectedForms_003 end";
}

/**
 * @tc.name: RenderConnectedForm_001
 * @tc.desc: test RenderConnectedForm function when connection is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RenderConnectedForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RenderConnectedForm_001 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    Want want;
    sptr<FormRenderConnection> connection = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.RenderConnectedForm(formRecord, want, connection));
    GTEST_LOG_(INFO) << "RenderConnectedForm_001 end";
}

/**
 * @tc.name: RenderConnectedForm_002
 * @tc.desc: test RenderConnectedForm function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RenderConnectedForm_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RenderConnectedForm_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    FormRecord formRecord;
    formRecord.formId = 1;
    Want want;
    WantParams wantParams;
    sptr<FormRenderConnection> connection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    MockConnectServiceAbility(true);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, 
        formRenderMgrInner.RenderConnectedForm(formRecord, want, connection));
    GTEST_LOG_(INFO) << "RenderConnectedForm_002 end";
}

/**
 * @tc.name: RenderConnectedForm_003
 * @tc.desc: test RenderConnectedForm function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RenderConnectedForm_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RenderConnectedForm_003 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    FormRecord formRecord;
    formRecord.formId = 1;
    Want want;
    WantParams wantParams;
    sptr<FormRenderConnection> connection = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgrInner.RenderConnectedForm(formRecord, want, connection));
    GTEST_LOG_(INFO) << "RenderConnectedForm_003 end";
}

/**
 * @tc.name: PostStopRenderingFormTask_001
 * @tc.desc: test PostStopRenderingFormTask function when connection not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostStopRenderingFormTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostStopRenderingFormTask_001 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    Want want;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.PostStopRenderingFormTask(formRecord, want));
    GTEST_LOG_(INFO) << "PostStopRenderingFormTask_001 end";
}

/**
 * @tc.name: PostStopRenderingFormTask_002
 * @tc.desc: test PostStopRenderingFormTask function when connection is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostStopRenderingFormTask_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostStopRenderingFormTask_002 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    Want want;
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.PostStopRenderingFormTask(formRecord, want));
    GTEST_LOG_(INFO) << "PostStopRenderingFormTask_002 end";
}

/**
 * @tc.name: PostStopRenderingFormTask_003
 * @tc.desc: test PostStopRenderingFormTask function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostStopRenderingFormTask_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostStopRenderingFormTask_003 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    Want want;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.PostStopRenderingFormTask(formRecord, want));
    GTEST_LOG_(INFO) << "PostStopRenderingFormTask_003 end";
}

/**
 * @tc.name: PostStopRenderingFormTask_004
 * @tc.desc: test PostStopRenderingFormTask function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostStopRenderingFormTask_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostStopRenderingFormTask_004 start";
    FormRenderMgrInner formRenderMgrInner;
    FormRecord formRecord;
    formRecord.formId = 1;
    Want want;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formRecord.formId, conn);
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.PostStopRenderingFormTask(formRecord, want));
    GTEST_LOG_(INFO) << "PostStopRenderingFormTask_004 end";
}

/**
 * @tc.name: CheckRenderConnectionExistById_001
 * @tc.desc: test CheckRenderConnectionExistById function when connection not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, CheckRenderConnectionExistById_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "CheckRenderConnectionExistById_001 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.CheckRenderConnectionExistById(formId));
    GTEST_LOG_(INFO) << "CheckRenderConnectionExistById_001 end";
}

/**
 * @tc.name: CheckRenderConnectionExistById_002
 * @tc.desc: test CheckRenderConnectionExistById function when connection is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, CheckRenderConnectionExistById_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "CheckRenderConnectionExistById_002 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    formRenderMgrInner.renderFormConnections_.emplace(formId, nullptr);
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.CheckRenderConnectionExistById(formId));
    GTEST_LOG_(INFO) << "CheckRenderConnectionExistById_002 end";
}

/**
 * @tc.name: CheckRenderConnectionExistById_003
 * @tc.desc: test CheckRenderConnectionExistById function when connection exists.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, CheckRenderConnectionExistById_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "CheckRenderConnectionExistById_003 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, conn);
    EXPECT_EQ(ERR_OK, formRenderMgrInner.CheckRenderConnectionExistById(formId));
    GTEST_LOG_(INFO) << "CheckRenderConnectionExistById_003 end";
}

/**
 * @tc.name: RecoverFRSOnFormActivity_002
 * @tc.desc: test RecoverFRSOnFormActivity function when isFrsDiedInLowMemory_ is true.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RecoverFRSOnFormActivity_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RecoverFRSOnFormActivity_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.isFrsDiedInLowMemory_ = true;
    sptr<IRemoteObject> remote = new (std::nothrow) MockFormProviderClient();
    std::unordered_set<int64_t> form;
    form.insert(1);
    formRenderMgrInner.etsHosts_.emplace(remote, form);
    formRenderMgrInner.RecoverFRSOnFormActivity();
    EXPECT_FALSE(formRenderMgrInner.isFrsDiedInLowMemory_);
    GTEST_LOG_(INFO) << "RecoverFRSOnFormActivity_002 end";
}

/**
 * @tc.name: GetIsFRSDiedInLowMemory_001
 * @tc.desc: test GetIsFRSDiedInLowMemory function when isFrsDiedInLowMemory_ is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetIsFRSDiedInLowMemory_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetIsFRSDiedInLowMemory_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.isFrsDiedInLowMemory_ = false;
    EXPECT_FALSE(formRenderMgrInner.GetIsFRSDiedInLowMemory());
    GTEST_LOG_(INFO) << "GetIsFRSDiedInLowMemory_001 end";
}

/**
 * @tc.name: GetIsFRSDiedInLowMemory_002
 * @tc.desc: test GetIsFRSDiedInLowMemory function when isFrsDiedInLowMemory_ is true.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetIsFRSDiedInLowMemory_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetIsFRSDiedInLowMemory_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.isFrsDiedInLowMemory_ = true;
    EXPECT_TRUE(formRenderMgrInner.GetIsFRSDiedInLowMemory());
    GTEST_LOG_(INFO) << "GetIsFRSDiedInLowMemory_002 end";
}

/**
 * @tc.name: ExecOnUnlockTask_001
 * @tc.desc: test ExecOnUnlockTask function when onUnlockTask_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, ExecOnUnlockTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ExecOnUnlockTask_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.onUnlockTask_ = nullptr;
    sptr<IRemoteObject> remoteObject = nullptr;
    formRenderMgrInner.ExecOnUnlockTask(remoteObject);
    GTEST_LOG_(INFO) << "ExecOnUnlockTask_001 end";
}

/**
 * @tc.name: ExecOnUnlockTask_002
 * @tc.desc: test ExecOnUnlockTask function when onUnlockTask_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, ExecOnUnlockTask_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ExecOnUnlockTask_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.onUnlockTask_ = [](const sptr<IRemoteObject> &remoteObject) {};
    sptr<IRemoteObject> remoteObject = nullptr;
    formRenderMgrInner.ExecOnUnlockTask(remoteObject);
    EXPECT_EQ(formRenderMgrInner.onUnlockTask_, nullptr);
    GTEST_LOG_(INFO) << "ExecOnUnlockTask_002 end";
}

/**
 * @tc.name: OnRenderingBlock_001
 * @tc.desc: test OnRenderingBlock function with valid bundleName.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, OnRenderingBlock_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "OnRenderingBlock_001 start";
    FormRenderMgrInner formRenderMgrInner;
    std::string bundleName = "testBundle";
    formRenderMgrInner.OnRenderingBlock(bundleName);
    GTEST_LOG_(INFO) << "OnRenderingBlock_001 end";
}

/**
 * @tc.name: checkConnectionsFormIds_001
 * @tc.desc: test checkConnectionsFormIds function when all connections exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, checkConnectionsFormIds_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "checkConnectionsFormIds_001 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId1 = 1;
    int64_t formId2 = 2;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> conn1 = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    sptr<FormRenderConnection> conn2 = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId1, conn1);
    formRenderMgrInner.renderFormConnections_.emplace(formId2, conn2);
    std::vector<int64_t> formIds = {formId1, formId2};
    std::vector<int64_t> needConFormIds;
    EXPECT_EQ(ERR_OK, formRenderMgrInner.checkConnectionsFormIds(formIds, needConFormIds));
    EXPECT_EQ(0, needConFormIds.size());
    GTEST_LOG_(INFO) << "checkConnectionsFormIds_001 end";
}

/**
 * @tc.name: checkConnectionsFormIds_002
 * @tc.desc: test checkConnectionsFormIds function when some connections not exist.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, checkConnectionsFormIds_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "checkConnectionsFormIds_002 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId1 = 1;
    int64_t formId2 = 2;
    int64_t formId3 = 3;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> conn1 = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId1, conn1);
    std::vector<int64_t> formIds = {formId1, formId2, formId3};
    std::vector<int64_t> needConFormIds;
    EXPECT_EQ(ERR_OK, formRenderMgrInner.checkConnectionsFormIds(formIds, needConFormIds));
    EXPECT_EQ(2, needConFormIds.size());
    GTEST_LOG_(INFO) << "checkConnectionsFormIds_002 end";
}

/**
 * @tc.name: GetReRenderCount_001
 * @tc.desc: test GetReRenderCount function when atomicRerenderCount_ is 0.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetReRenderCount_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetReRenderCount_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.atomicRerenderCount_ = 0;
    EXPECT_EQ(0, formRenderMgrInner.GetReRenderCount());
    GTEST_LOG_(INFO) << "GetReRenderCount_001 end";
}

/**
 * @tc.name: GetReRenderCount_002
 * @tc.desc: test GetReRenderCount function when atomicRerenderCount_ is not 0.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetReRenderCount_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetReRenderCount_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.atomicRerenderCount_ = 5;
    EXPECT_EQ(5, formRenderMgrInner.GetReRenderCount());
    GTEST_LOG_(INFO) << "GetReRenderCount_002 end";
}

/**
 * @tc.name: GetRenderRemoteObj_001
 * @tc.desc: test GetRenderRemoteObj function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetRenderRemoteObj_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetRenderRemoteObj_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    EXPECT_EQ(nullptr, formRenderMgrInner.GetRenderRemoteObj());
    GTEST_LOG_(INFO) << "GetRenderRemoteObj_001 end";
}

/**
 * @tc.name: GetRenderRemoteObj_002
 * @tc.desc: test GetRenderRemoteObj function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, GetRenderRemoteObj_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetRenderRemoteObj_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    EXPECT_NE(nullptr, formRenderMgrInner.GetRenderRemoteObj());
    GTEST_LOG_(INFO) << "GetRenderRemoteObj_002 end";
}

/**
 * @tc.name: SetRenderRemoteObj_001
 * @tc.desc: test SetRenderRemoteObj function.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, SetRenderRemoteObj_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "SetRenderRemoteObj_001 start";
    FormRenderMgrInner formRenderMgrInner;
    sptr<IFormRender> remoteObject = new (std::nothrow) MockIFormRender();
    formRenderMgrInner.SetRenderRemoteObj(remoteObject);
    EXPECT_NE(nullptr, formRenderMgrInner.renderRemoteObj_);
    GTEST_LOG_(INFO) << "SetRenderRemoteObj_001 end";
}

/**
 * @tc.name: NotifyScreenOn_002
 * @tc.desc: test NotifyScreenOn function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, NotifyScreenOn_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "NotifyScreenOn_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    formRenderMgrInner.NotifyScreenOn();
    GTEST_LOG_(INFO) << "NotifyScreenOn_002 end";
}

/**
 * @tc.name: PostOnUnlockTask_001
 * @tc.desc: test PostOnUnlockTask function when renderRemoteObj_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostOnUnlockTask_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostOnUnlockTask_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    formRenderMgrInner.PostOnUnlockTask();
    EXPECT_NE(nullptr, formRenderMgrInner.onUnlockTask_);
    GTEST_LOG_(INFO) << "PostOnUnlockTask_001 end";
}

/**
 * @tc.name: PostOnUnlockTask_002
 * @tc.desc: test PostOnUnlockTask function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, PostOnUnlockTask_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "PostOnUnlockTask_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    formRenderMgrInner.PostOnUnlockTask();
    EXPECT_NE(nullptr, formRenderMgrInner.onUnlockTask_);
    GTEST_LOG_(INFO) << "PostOnUnlockTask_002 end";
}

/**
 * @tc.name: StopRenderingForm_001
 * @tc.desc: test StopRenderingForm function with hostToken.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, StopRenderingForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "StopRenderingForm_001 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.uiSyntax = FormType::ETS;
    formRecord.abilityName = "abilityName";
    formRecord.bundleName = "bundleName";
    formRecord.providerUserId = 100;
    std::string compId = "compId";
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    WantParams wantParams;
    sptr<FormRenderConnection> conn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    formRenderMgrInner.renderFormConnections_.emplace(formId, conn);
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM, formRenderMgrInner.StopRenderingForm(formId, formRecord, compId, hostToken));
    GTEST_LOG_(INFO) << "StopRenderingForm_001 end";
}

/**
 * @tc.name: RenderForm_001
 * @tc.desc: test RenderForm function when isActiveUser_ is false.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, RenderForm_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "RenderForm_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.isActiveUser_ = false;
    FormRecord formRecord;
    Want want;
    sptr<IRemoteObject> hostToken = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED, formRenderMgrInner.RenderForm(formRecord, want, hostToken));
    GTEST_LOG_(INFO) << "RenderForm_001 end";
}

/**
 * @tc.name: AddConnection_001
 * @tc.desc: test AddConnection function when connection already exists with different connectId.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, AddConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "AddConnection_001 start";
    FormRenderMgrInner formRenderMgrInner;
    int64_t formId = 1;
    FormRecord formRecord;
    WantParams wantParams;
    sptr<FormRenderConnection> oldConn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    oldConn->SetConnectId(100);
    formRenderMgrInner.renderFormConnections_.emplace(formId, oldConn);
    sptr<FormRenderConnection> newConn = new (std::nothrow) FormRenderConnection(formRecord, wantParams);
    newConn->SetConnectId(200);
    EXPECT_EQ(ERR_OK, formRenderMgrInner.AddConnection(formId, newConn));
    EXPECT_NE(nullptr, formRenderMgrInner.renderFormConnections_[formId]);
    GTEST_LOG_(INFO) << "AddConnection_001 end";
}

/**
 * @tc.name: NotifyHostRenderServiceIsDead_001
 * @tc.desc: test NotifyHostRenderServiceIsDead function when renderRemoteObj_ is not nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, NotifyHostRenderServiceIsDead_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "NotifyHostRenderServiceIsDead_001 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = new (std::nothrow) MockIFormRender();
    sptr<IRemoteObject> remote = new (std::nothrow) MockFormProviderClient();
    std::unordered_set<int64_t> form;
    form.insert(1);
    formRenderMgrInner.etsHosts_.emplace(remote, form);
    formRenderMgrInner.NotifyHostRenderServiceIsDead();
    GTEST_LOG_(INFO) << "NotifyHostRenderServiceIsDead_001 end";
}

/**
 * @tc.name: NotifyHostRenderServiceIsDead_002
 * @tc.desc: test NotifyHostRenderServiceIsDead function when etsHosts_ is empty.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderMgrInnerTest, NotifyHostRenderServiceIsDead_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "NotifyHostRenderServiceIsDead_002 start";
    FormRenderMgrInner formRenderMgrInner;
    formRenderMgrInner.renderRemoteObj_ = nullptr;
    formRenderMgrInner.NotifyHostRenderServiceIsDead();
    GTEST_LOG_(INFO) << "NotifyHostRenderServiceIsDead_002 end";
}
}
