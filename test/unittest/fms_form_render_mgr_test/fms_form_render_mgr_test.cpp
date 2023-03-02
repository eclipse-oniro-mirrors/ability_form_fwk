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
#include "hilog_wrapper.h"
#include "mock_form_provider_client.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockGetFormRecord(bool mockRet);

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
    std::vector<int64_t> formIds;
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.ReloadForm(std::move(formIds), bundleName, userId));
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
    std::vector<int64_t> formIds;
    std::string bundleName = "<bundleName>";
    int32_t userId = 1;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_INVALID_PARAM,
        formRenderMgr.ReloadForm(std::move(formIds), bundleName, userId));
    GTEST_LOG_(INFO) << "FormRenderMgrTest_015 end";
}
}