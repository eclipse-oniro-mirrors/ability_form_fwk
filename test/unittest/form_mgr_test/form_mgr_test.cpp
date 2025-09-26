/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include <memory>
#include "form_caller_mgr.h"
#define private public
#define protected public
#include "form_mgr.h"
#include "form_errors.h"
#include "iservice_registry.h"
#undef private
#undef protected
#include "form_mgr_errors.h"
#include "mock_form_provider_client.h"
#include "gmock/gmock.h"
#include "mock_form_mgr_proxy.h"
#include "mock_form_token.h"
#include "if_system_ability_manager.h"
#include "mock_system_ability_manager.h"
#include "mock_i_remote_object.h"
#include "fms_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

using ::testing::Return;
using ::testing::SetArgReferee;
using ::testing::ContainerEq;
using ::testing::_;
using ::testing::DoAll;

// overload operator for ContainerEq
namespace OHOS::AppExecFwk {
    bool operator==(const FormInfo& lhs, const FormInfo& rhs)
    {
        if (lhs.bundleName != rhs.bundleName) {
            return false;
        }
        if (lhs.moduleName != rhs.moduleName) {
            return false;
        }
        if (lhs.name != rhs.name) {
            return false;
        }
        // to be continued...
        return true;
    }
}

namespace {
const std::int32_t ERROR_NUM = 2293778;
const std::int32_t ERROR_NUMS = 8388610;
const std::int32_t NEGATIVE_NUM = -1;
const std::int32_t POSITIVE_NUM = 1;
const std::int32_t ERR_FAILED = -1;
const std::int64_t FORM_ID = 10;
class FormMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static sptr<MockFormMgrProxy> mockProxy;
};
// initialize static variable.
sptr<MockFormMgrProxy> FormMgrTest::mockProxy = nullptr;

void FormMgrTest::SetUpTestCase(void)
{}

void FormMgrTest::TearDownTestCase(void)
{}

void FormMgrTest::SetUp(void)
{
    if (mockProxy == nullptr) {
        GTEST_LOG_(INFO) << "SetUpTestCase";
        sptr<IRemoteObject> impl = nullptr;
        mockProxy = new (std::nothrow) MockFormMgrProxy(impl);
        FormMgr::GetInstance().SetFormMgrService(mockProxy);
    }
}

void FormMgrTest::TearDown(void)
{
    GTEST_LOG_(INFO) << "FormMgrTest_TearDown start";
    FormMgr::GetInstance().SetFormMgrService(nullptr);
    mockProxy = nullptr;
    GTEST_LOG_(INFO) << "FormMgrTest_TearDown end";
}

/**
 * @tc.name: FormMgrTest_0001
 * @tc.desc: Verify GetFormsInfo
 * @tc.type: FUNC
 * @tc.require: #I59O23
 */
HWTEST_F(FormMgrTest, FormMgrTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0001 starts";
    // initialize input parameters.
    FormInfoFilter filter;
    filter.moduleName = "";
    std::vector<FormInfo> formInfos;
    // setup expectations.
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    expectFormInfos.push_back(formInfo);
    EXPECT_CALL(*mockProxy, GetFormsInfo(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(expectFormInfos), Return(ERR_OK)));
    // test.
    FormMgr::GetInstance().GetFormsInfo(filter, formInfos);
    // expect result.
    EXPECT_THAT(formInfos, ContainerEq(expectFormInfos));
    // FormMgr is a singleton, therefore, deleteing it will cause segfault for other invocations.
    testing::Mock::AllowLeak(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0001 test ends";
}

/**
 * @tc.name: FormMgrTest_0002
 * @tc.desc: Verify GetFormsInfo
 * @tc.type: FUNC
 * @tc.require: #I59O23
 */
HWTEST_F(FormMgrTest, FormMgrTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0002 starts";
    // initialize input parameters.
    FormInfoFilter filter;
    filter.moduleName = "empty";
    std::vector<FormInfo> formInfos;
    // setup expectations.
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    EXPECT_CALL(*mockProxy, GetFormsInfo(_, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));
    // test.
    FormMgr::GetInstance().GetFormsInfo(filter, formInfos);
    // expect result.
    EXPECT_EQ(formInfos.size(), 0);
    testing::Mock::AllowLeak(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0002 test ends";
}

/**
 * @tc.name: FormMgrTest_0003
 * @tc.desc: Verify IsRequestPublishFormSupported
 * @tc.type: FUNC
 * @tc.require: #I58Y0A
 */
HWTEST_F(FormMgrTest, FormMgrTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0003 starts";
    EXPECT_CALL(*mockProxy, IsRequestPublishFormSupported())
        .Times(1)
        .WillOnce(Return(false));
    bool result = FormMgr::GetInstance().IsRequestPublishFormSupported();
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrTest_0003 test ends";
}

/**
 * @tc.name: FormMgrTest_0004
 * @tc.desc: Verify StartAbility
 * @tc.type: FUNC
 * @tc.require: #I5EFDX
 */
HWTEST_F(FormMgrTest, FormMgrTest_0004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0004 starts";
    EXPECT_CALL(*mockProxy, StartAbility(_, _))
        .Times(1)
        .WillOnce(Return(0));
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().StartAbility(want, token);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0004 test ends";
}

/**
 * @tc.name: FormMgrTest_0005
 * @tc.desc: Verify UpdateForm
 * @tc.type: FUNC
 * @tc.require: issueI5PFT9
 */
HWTEST_F(FormMgrTest, FormMgrTest_0005, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0005 starts";
    EXPECT_CALL(*mockProxy, UpdateForm(_, _))
        .Times(1)
        .WillOnce(Return(0));
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    FormProviderData formProviderData = FormProviderData(std::string("{\"city\": \"beijing001\"}"));
    int32_t result = FormMgr::GetInstance().UpdateForm(formJsInfo.formId, formProviderData);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0005 test ends";
}

/**
 * @tc.name: FormMgrTest_0006
 * @tc.desc: Verify RequestForm
 * @tc.type: FUNC
 * @tc.require: issueI5Q8IU
 */
HWTEST_F(FormMgrTest, FormMgrTest_0006, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0006 starts";

    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    int32_t result = FormMgr::GetInstance().RequestForm(formJsInfo.formId, token, want);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0006 test ends";
}

/**
 * @tc.name: FormMgrTest_0007
 * @tc.desc: Verify MessageEvent
 * @tc.type: FUNC
 * @tc.require: issueI5QGMS
 */
HWTEST_F(FormMgrTest, FormMgrTest_0007, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0007 starts";

    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormJsInfo formJsInfo;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    int32_t result = FormMgr::GetInstance().MessageEvent(formJsInfo.formId, want, token);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0007 test ends";
}

/**
 * @tc.name: FormMgrTest_0005
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: I5ST27
 */
HWTEST_F(FormMgrTest, FormMgrTest_0008, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0008 starts";
    EXPECT_CALL(*mockProxy, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // initialize input parameters.
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    bool isProtected = false;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0008 test ends";
}

/**
 * @tc.name: FormMgrTest_0006
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: I5ST27
 */
HWTEST_F(FormMgrTest, FormMgrTest_0009, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0009 starts";
    EXPECT_CALL(*mockProxy, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // initialize input parameters.
    int64_t formId = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0009 test ends";
}

/**
 * @tc.name: FormMgrTest_0007
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: I5ST27
 */
HWTEST_F(FormMgrTest, FormMgrTest_0010, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0010 starts";
    EXPECT_CALL(*mockProxy, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // initialize input parameters.
    int64_t formId1 = 3;
    int64_t formId2 = 4;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);
    formIds.push_back(formId2);
    bool isProtected = false;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0010 test ends";
}

/**
 * @tc.name: FormMgrTest_0011
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: I5ST27
 */
HWTEST_F(FormMgrTest, FormMgrTest_0011, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0008 starts";
    EXPECT_CALL(*mockProxy, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // initialize input parameters.
    int64_t formId1 = 5;
    int64_t formId2 = 6;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);
    formIds.push_back(formId2);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0011 test ends";
}

/**
 * @tc.name: FormMgrTest_0012
 * @tc.desc: Verify GetErrorMsg
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0012, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0012 starts";
    int errorCode = 0;
    auto result = FormMgr::GetInstance().GetErrorMsg(errorCode);

    EXPECT_EQ(result, "unknown error");
    GTEST_LOG_(INFO) << "FormMgrTest_0012 test ends";
}

/**
 * @tc.name: FormMgrTest_0013
 * @tc.desc: Verify DumpStorageFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0013, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0013 starts";
    EXPECT_CALL(*mockProxy, DumpStorageFormInfos(_))
    .Times(1)
    .WillOnce(Return(0));
    std::string formInfos = "a";
    auto result = FormMgr::GetInstance().DumpStorageFormInfos(formInfos);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0013 test ends";
}

/**
 * @tc.name: FormMgrTest_0014
 * @tc.desc: Verify DumpFormInfoByFormId
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0014, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0014 starts";
    EXPECT_CALL(*mockProxy, DumpFormInfoByFormId(_, _))
    .Times(1)
    .WillOnce(Return(0));
    std::string formInfos = "a";
    std::int64_t formId = 3;
    auto result = FormMgr::GetInstance().DumpFormInfoByFormId(formId, formInfos);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0014 test ends";
}

/**
 * @tc.name: FormMgrTest_0015
 * @tc.desc: Verify DumpFormTimerByFormId
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0015, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0015 starts";
    EXPECT_CALL(*mockProxy, DumpFormTimerByFormId(_, _))
    .Times(1)
    .WillOnce(Return(0));
    std::string isTimingService = "b";
    std::int64_t formId = 3;
    auto result = FormMgr::GetInstance().DumpFormTimerByFormId(formId, isTimingService);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0015 test ends";
}

/**
 * @tc.name: FormMgrTest_0016
 * @tc.desc: Verify RouterEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0016, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0016 starts";
    EXPECT_CALL(*mockProxy, RouterEvent(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormJsInfo formJsInfo;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    int32_t result = FormMgr::GetInstance().RouterEvent(formJsInfo.formId, want, token);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0016 test ends";
}

/**
 * @tc.name: FormMgrTest_0017
 * @tc.desc: Verify SetNextRefreshTime
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0017, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0017 starts";
    int64_t formId = 1;
    int64_t nextTime = 2;
    auto result = FormMgr::GetInstance().SetNextRefreshTime(formId, nextTime);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0017 test ends";
}

/**
 * @tc.name: FormMgrTest_0018
 * @tc.desc: Verify GetErrorMessage
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0018, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0018 starts";
    FormErrors::GetInstance().InitErrorMessageMap();
    int errCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    auto result = FormMgr::GetInstance().GetErrorMessage(errCode);

    EXPECT_EQ(result, "check permission deny, need to request ohos.permission.REQUIRE_FORM "
        "or ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS.");
    GTEST_LOG_(INFO) << "FormMgrTest_0018 test ends";
}

/**
 * @tc.name: FormMgrTest_0019
 * @tc.desc: Verify DeleteInvalidForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0019, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0019 starts";
    EXPECT_CALL(*mockProxy, DeleteInvalidForms(_, _, _))
    .Times(1)
    .WillOnce(Return(0));
    std::vector<int64_t> formInfos;
    formInfos.push_back(1);
    formInfos.push_back(2);
    FormJsInfo formJsInfo;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t numFormsDeleted = 2;
    auto result = FormMgr::GetInstance().DeleteInvalidForms(formInfos, token, numFormsDeleted);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0019 test ends";
}

/**
 * @tc.name: FormMgrTest_0020
 * @tc.desc: Verify DumpStorageFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0020, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0020 starts";
    EXPECT_CALL(*mockProxy, NotifyFormsVisible(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    int64_t formId1 = 5;
    int64_t formId2 = 6;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);
    formIds.push_back(formId2);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsVisible(formIds, isProtected, token);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0020 test ends";
}

/**
 * @tc.name: FormMgrTest_0021
 * @tc.desc: Verify NotifyFormsEnableUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0021, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0021 starts";
    EXPECT_CALL(*mockProxy, NotifyFormsEnableUpdate(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    int64_t formId1 = 3;
    int64_t formId2 = 4;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);
    formIds.push_back(formId2);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsEnableUpdate(formIds, isProtected, token);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0021 test ends";
}

/**
 * @tc.name: FormMgrTest_0022
 * @tc.desc: Verify  GetAllFormsInfo
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0022, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0022 starts";
    EXPECT_CALL(*mockProxy, GetAllFormsInfo(_))
    .Times(1)
    .WillOnce(Return(0));
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    auto result = FormMgr::GetInstance().GetAllFormsInfo(formInfos);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0022 test ends";
}

/**
 * @tc.name: FormMgrTest_0023
 * @tc.desc: Verify GetFormsInfoByApp
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0023, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0023 starts";
    EXPECT_CALL(*mockProxy, GetFormsInfoByApp(_, _))
    .Times(1)
    .WillOnce(Return(0));
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    std::string bundleName = "a";
    auto result = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0023 test ends";
}

/**
 * @tc.name: FormMgrTest_0024
 * @tc.desc: Verify GetFormsInfoByModule
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0024, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0024 starts";
    EXPECT_CALL(*mockProxy, GetFormsInfoByModule(_, _, _))
    .Times(1)
    .WillOnce(Return(0));
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    std::string bundleName = "a";
    std::string moduleName = "A";
    auto result = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0024 test ends";
}

/**
 * @tc.name: FormMgrTest_0025
 * @tc.desc: Verify CheckFMSReady
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0025, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0025 starts";
    EXPECT_CALL(*mockProxy, CheckFMSReady())
        .Times(1)
        .WillOnce(Return(true));

    auto result = FormMgr::GetInstance().CheckFMSReady();
    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FormMgrTest_0025 test ends";
}

/**
 * @tc.name: FormMgrTest_0026
 * @tc.desc: Verify DumpFormInfoByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0026, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0026 starts";
    EXPECT_CALL(*mockProxy, DumpFormInfoByBundleName(_, _))
    .Times(1)
    .WillOnce(Return(0));
    std::string bundleName = "b";
    std::string formInfos = "a";
    auto result = FormMgr::GetInstance().DumpFormInfoByBundleName(bundleName, formInfos);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0026 test ends";
}

/**
 * @tc.name: FormMgrTest_0027
 * @tc.desc: Verify AcquireFormState
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0027, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0027 starts";
    EXPECT_CALL(*mockProxy, AcquireFormState(_, _, _))
    .Times(1)
    .WillOnce(Return(0));
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormStateInfo stateInfo;
    auto result = FormMgr::GetInstance().AcquireFormState(want, token, stateInfo);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0027 test ends";
}

/**
 * @tc.name: FormMgrTest_0028
 * @tc.desc: Verify DeleteForm
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0028, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0028 starts";
    int64_t formId = 1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().DeleteForm(formId, token);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0028 test ends";
}

/**
 * @tc.name: FormMgrTest_0029
 * @tc.desc: Verify ReleaseForm
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0029, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0029 starts";
    int64_t formId = 1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    bool delCache = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().ReleaseForm(formId, token, delCache);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0029 test ends";
}

/**
 * @tc.name: FormMgrTest_0030
 * @tc.desc: Verify ReleaseForm
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0030, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0030 starts";
    int64_t formId = -1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    bool delCache = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().ReleaseForm(formId, token, delCache);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0030 test ends";
}

/**
 * @tc.name: FormMgrTest_0031
 * @tc.desc: Verify UpdateForm
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0031, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0031 starts";
    int64_t formId = 1;
    FormProviderData formBindingData;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().UpdateForm(formId, formBindingData);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0031 test ends";
}

/**
 * @tc.name: FormMgrTest_0032
 * @tc.desc: Verify UpdateForm
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0032, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0032 starts";
    int64_t formId = -1;
    FormProviderData formBindingData;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().UpdateForm(formId, formBindingData);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0032 test ends";
}

/**
 * @tc.name: FormMgrTest_0033
 * @tc.desc: Verify UpdateForm
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0033, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0033 starts";
    int64_t formId = 1;
    FormProviderData formBindingData;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().UpdateForm(formId, formBindingData);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_PROVIDER_DATA_EMPTY);
    GTEST_LOG_(INFO) << "FormMgrTest_0033 test ends";
}

/**
 * @tc.name: FormMgrTest_0034
 * @tc.desc: Verify RequestForm
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0034, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0034 starts";
    int64_t formId = 1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().RequestForm(formId, token, want);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0034 test ends";
}

/**
 * @tc.name: FormMgrTest_0035
 * @tc.desc: Verify RequestForm
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0035, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0035 starts";
    int64_t formId = -1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().RequestForm(formId, token, want);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0035 test ends";
}

/**
 * @tc.name: FormMgrTest_0036
 * @tc.desc: Verify NotifyWhetherVisibleForms
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0036, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0036 starts";
    std::vector<int64_t> formIds;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t formVisibleType = 1;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, token, formVisibleType);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0036 test ends";
}

/**
 * @tc.name: FormMgrTest_0037
 * @tc.desc: Verify NotifyWhetherVisibleForms
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0037, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0037 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t formVisibleType = 1;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, token, formVisibleType);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0037 test ends";
}

/**
 * @tc.name: FormMgrTest_0038
 * @tc.desc: Verify SetNextRefreshTime
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0038, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0038 starts";
    int64_t formId = 10;
    int64_t nextTime = 50;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().SetNextRefreshTime(formId, nextTime);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0038 test ends";
}

/**
 * @tc.name: FormMgrTest_0039
 * @tc.desc: Verify LifecycleUpdate
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0039, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0039 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    bool updateType = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().LifecycleUpdate(formIds, token, updateType);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0039 test ends";
}

/**
 * @tc.name: FormMgrTest_0040
 * @tc.desc: Verify RegisterDeathCallback
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0040, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0040 starts";
    std::shared_ptr<FormMgr> formMgr = std::make_shared<FormMgr>();
    ASSERT_NE(nullptr, formMgr);
    formMgr->RegisterDeathCallback(nullptr);
    formMgr->UnRegisterDeathCallback(nullptr);
    formMgr->SetRecoverStatus(Constants::IN_RECOVERING);
    GTEST_LOG_(INFO) << "FormMgrTest_0040 test ends";
}

/**
 * @tc.name: FormMgrTest_0041
 * @tc.desc: Verify DeleteInvalidForms
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0041, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0041 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t numFormsDeleted = 2;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().DeleteInvalidForms(formIds, token, numFormsDeleted);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0041 test ends";
}

/**
 * @tc.name: FormMgrTest_0042
 * @tc.desc: Verify AcquireFormState
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0042, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0042 starts";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormStateInfo stateInfo;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().AcquireFormState(want, token, stateInfo);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0042 test ends";
}

/**
 * @tc.name: FormMgrTest_0043
 * @tc.desc: Verify NotifyFormsVisible
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0043, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0043 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    bool isVisible = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().NotifyFormsVisible(formIds, isVisible, token);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0043 test ends";
}

/**
 * @tc.name: FormMgrTest_0044
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0044, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0044 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, token);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0044 test ends";
}

/**
 * @tc.name: FormMgrTest_0045
 * @tc.desc: Verify NotifyFormsEnableUpdate
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0045, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0045 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    bool isEnableUpdate = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().NotifyFormsEnableUpdate(formIds, isEnableUpdate, token);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0045 test ends";
}

/**
 * @tc.name: FormMgrTest_0046
 * @tc.desc: Verify GetAllFormsInfo
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0046, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0046 starts";
    std::vector<FormInfo> formInfos;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().GetAllFormsInfo(formInfos);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0046 test ends";
}

/**
 * @tc.name: FormMgrTest_0047
 * @tc.desc: Verify GetFormsInfoByApp
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0047, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0047 starts";
    std::string bundleName = "this is bundleName";
    std::vector<FormInfo> formInfos;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0047 test ends";
}

/**
 * @tc.name: FormMgrTest_0048
 * @tc.desc: Verify GetFormsInfoByApp
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0048, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0048 starts";
    std::string bundleName = "";
    std::vector<FormInfo> formInfos;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME);
    GTEST_LOG_(INFO) << "FormMgrTest_0048 test ends";
}

/**
 * @tc.name: FormMgrTest_0050
 * @tc.desc: Verify GetFormsInfoByModule
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0050, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0050 starts";
    std::string bundleName = "";
    std::string moduleName = "this is moduleName";
    std::vector<FormInfo> formInfos;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME);
    GTEST_LOG_(INFO) << "FormMgrTest_0050 test ends";
}

/**
 * @tc.name: FormMgrTest_0051
 * @tc.desc: Verify GetFormsInfoByModule
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0051, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0051 starts";
    std::string bundleName = "this is bundleName";
    std::string moduleName = "";
    std::vector<FormInfo> formInfos;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_MODULENAME);
    GTEST_LOG_(INFO) << "FormMgrTest_0051 test ends";
}

/**
 * @tc.name: FormMgrTest_0052
 * @tc.desc: Verify GetFormsInfoByModule
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0052, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0052 starts";
    std::string bundleName = "this is bundleName";
    std::string moduleName = "this is moduleName";
    std::vector<FormInfo> formInfos;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0052 test ends";
}

/**
 * @tc.name: FormMgrTest_0053
 * @tc.desc: Verify GetErrorMessage
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0053, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0053 starts";
    FormErrors::GetInstance().InitErrorMessageMap();
    int errCode = ERR_APPEXECFWK_FORM_COMMON_CODE;
    auto result = FormMgr::GetInstance().GetErrorMessage(errCode);

    EXPECT_EQ(result, "some internal server error occurs.");
    GTEST_LOG_(INFO) << "FormMgrTest_0053 test ends";
}

/**
 * @tc.name: FormMgrTest_0054
 * @tc.desc: Verify AddForm
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0054, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0054 starts";
    int64_t formId = 10;
    Want want;
    FormJsInfo formInfo;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    auto data = FormMgr::GetInstance().AddForm(formId, want, token, formInfo);
    EXPECT_EQ(data, ERROR_NUMS);
    GTEST_LOG_(INFO) << "FormMgrTest_0054 test ends";
}

/**
 * @tc.name: FormMgrTest_0055
 * @tc.desc: Verify DeleteForm (ID <= 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0055, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0055 starts";
    int64_t formId = -1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().DeleteForm(formId, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0055 test ends";
}

/**
 * @tc.name: FormMgrTest_0056
 * @tc.desc: Verify DeleteForm (Parameters are normal.)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0056, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0056 starts";
    EXPECT_CALL(*mockProxy, DeleteForm(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    int64_t formId = 1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().DeleteForm(formId, token);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0056 test ends";
}

/**
 * @tc.name: FormMgrTest_0057
 * @tc.desc: Verify ReleaseForm (Parameters are normal.)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0057, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0057 starts";
    EXPECT_CALL(*mockProxy, ReleaseForm(_, _, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    int64_t formId = 1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    bool delCache = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().ReleaseForm(formId, token, delCache);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0057 test ends";
}

/**
 * @tc.name: FormMgrTest_0058
 * @tc.desc: Verify UpdateForm (Parameter formId exception)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0058, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0058 starts";
    EXPECT_CALL(*mockProxy, UpdateForm(_, _))
        .Times(1)
        .WillOnce(Return(NEGATIVE_NUM));
    FormJsInfo formJsInfo;
    formJsInfo.formId = 0x00000008fffffffL;
    FormProviderData formProviderData = FormProviderData(std::string("{\"city\": \"beijing001\"}"));
    int32_t result = FormMgr::GetInstance().UpdateForm(formJsInfo.formId, formProviderData);
    EXPECT_EQ(result, NEGATIVE_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0058 test ends";
}

/**
 * @tc.name: FormMgrTest_0059
 * @tc.desc: Verify RequestForm (Parameter formId exception)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0059, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0059 starts";
    EXPECT_CALL(*mockProxy, RequestForm(_, _, _))
        .Times(1)
        .WillOnce(Return(NEGATIVE_NUM));
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormJsInfo formJsInfo;
    formJsInfo.formId = 0x00000008fffffffL;
    int32_t result = FormMgr::GetInstance().RequestForm(formJsInfo.formId, token, want);
    EXPECT_EQ(result, NEGATIVE_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0059 test ends";
}

/**
 * @tc.name: FormMgrTest_0060
 * @tc.desc: Verify NotifyWhetherVisibleForms (Parameters are normal, the return value of mock function is 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0060, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0060 starts";
    EXPECT_CALL(*mockProxy, NotifyWhetherVisibleForms(_, _, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t formVisibleType = 1;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, token, formVisibleType);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0060 test ends";
}

/**
 * @tc.name: FormMgrTest_0061
 * @tc.desc: Verify NotifyWhetherVisibleForms (Parameters are normal, the return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0061, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0061 starts";
    EXPECT_CALL(*mockProxy, NotifyWhetherVisibleForms(_, _, _))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t formVisibleType = 1;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, token, formVisibleType);
    EXPECT_EQ(result, POSITIVE_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0061 test ends";
}

/**
 * @tc.name: FormMgrTest_0062
 * @tc.desc: Verify CastTempForm (Parameters are normal, the return value of mock function is 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0062, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0062 starts";
    EXPECT_CALL(*mockProxy, CastTempForm(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    int64_t formId = 1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = FormMgr::GetInstance().CastTempForm(formId, token);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0062 test ends";
}

/**
 * @tc.name: FormMgrTest_0063
 * @tc.desc: Verify CastTempForm (Parameters are normal, the return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0063, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0063 starts";
    EXPECT_CALL(*mockProxy, CastTempForm(_, _))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
    int64_t formId = 1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = FormMgr::GetInstance().CastTempForm(formId, token);
    EXPECT_EQ(result, POSITIVE_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0063 test ends";
}

/**
 * @tc.name: FormMgrTest_0064
 * @tc.desc: Verify CastTempForm (formId <= 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0064, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0064 starts";

    int64_t formId = -1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = FormMgr::GetInstance().CastTempForm(formId, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0064 test ends";
}

/**
 * @tc.name: FormMgrTest_0065
 * @tc.desc: Verify RegisterDeathCallback (Parameter is not nullptr)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0065, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0065 starts";
    std::shared_ptr<FormMgr> formMgr = std::make_shared<FormMgr>();
    ASSERT_NE(nullptr, formMgr);
    std::shared_ptr<FormInterfaceCallbackTest> callback = std::make_shared<FormInterfaceCallbackTest>();
    std::shared_ptr<FormInterfaceCallbackTest> callback_first = std::make_shared<FormInterfaceCallbackTest>();
    formMgr->formDeathCallbacks_.emplace_back(callback);
    formMgr->formDeathCallbacks_.emplace_back(callback_first);
    formMgr->RegisterDeathCallback(callback);
    GTEST_LOG_(INFO) << "FormMgrTest_0065 test ends";
}

/**
 * @tc.name: FormMgrTest_0066
 * @tc.desc: Verify UnRegisterDeathCallback (Parameter is not nullptr)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0066, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0066 starts";
    std::shared_ptr<FormMgr> formMgr = std::make_shared<FormMgr>();
    ASSERT_NE(nullptr, formMgr);
    std::shared_ptr<FormInterfaceCallbackTest> callback = std::make_shared<FormInterfaceCallbackTest>();
    std::shared_ptr<FormInterfaceCallbackTest> callback_first = std::make_shared<FormInterfaceCallbackTest>();
    formMgr->formDeathCallbacks_.emplace_back(callback);
    formMgr->formDeathCallbacks_.emplace_back(callback_first);
    formMgr->UnRegisterDeathCallback(callback);
    GTEST_LOG_(INFO) << "FormMgrTest_0066 test ends";
}

/**
 * @tc.name: FormMgrTest_0067
 * @tc.desc: Verify GetDeathRecipient
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0067, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0067 starts";
    auto data = FormMgr::GetInstance().GetDeathRecipient();
    EXPECT_TRUE(data == FormMgr::GetInstance().deathRecipient_);
    GTEST_LOG_(INFO) << "FormMgrTest_0067 test ends";
}

/**
 * @tc.name: FormMgrTest_0068
 * @tc.desc: Verify CheckIsDeathCallbackRegistered (Parameter is nullptr)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0068, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0068 starts";
    bool data = FormMgr::GetInstance().CheckIsDeathCallbackRegistered(nullptr);
    EXPECT_TRUE(data == false);
    GTEST_LOG_(INFO) << "FormMgrTest_0068 test ends";
}

/**
 * @tc.name: FormMgrTest_0069
 * @tc.desc: Verify CheckIsDeathCallbackRegistered (Parameter is not nullptr)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0069, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0069 starts";
    std::shared_ptr<FormInterfaceCallbackTest> callback = std::make_shared<FormInterfaceCallbackTest>();
    std::shared_ptr<FormInterfaceCallbackTest> callback_first = std::make_shared<FormInterfaceCallbackTest>();
    std::shared_ptr<FormInterfaceCallbackTest> callback_second = std::make_shared<FormInterfaceCallbackTest>();
    bool result = FormMgr::GetInstance().CheckIsDeathCallbackRegistered(callback_first);
    EXPECT_TRUE(result == false);
    FormMgr::GetInstance().formDeathCallbacks_.emplace_back(callback_first);
    FormMgr::GetInstance().formDeathCallbacks_.emplace_back(callback_second);
    bool data = FormMgr::GetInstance().CheckIsDeathCallbackRegistered(callback_first);
    EXPECT_TRUE(data);
    GTEST_LOG_(INFO) << "FormMgrTest_0069 test ends";
}

/**
 * @tc.name: FormMgrTest_0070
 * @tc.desc: Verify CheckIsDeathCallbackRegistered (Parameter exception)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0070, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0070 starts";
    std::shared_ptr<FormInterfaceCallbackTest> callback = std::make_shared<FormInterfaceCallbackTest>();
    std::shared_ptr<FormInterfaceCallbackTest> callback_first = std::make_shared<FormInterfaceCallbackTest>();
    std::shared_ptr<FormInterfaceCallbackTest> callback_second = std::make_shared<FormInterfaceCallbackTest>();
    FormMgr::GetInstance().formDeathCallbacks_.emplace_back(callback_first);
    FormMgr::GetInstance().formDeathCallbacks_.emplace_back(callback_second);
    bool data = FormMgr::GetInstance().CheckIsDeathCallbackRegistered(callback);
    EXPECT_TRUE(data == false);
    GTEST_LOG_(INFO) << "FormMgrTest_0070 test ends";
}

/**
 * @tc.name: FormMgrTest_0071
 * @tc.desc: Verify OnRemoteDied
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0071, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0071 starts";
    sptr<IRemoteObject> mockFormProviderClient = new (std::nothrow) MockFormProviderClient();
    sptr<FormMgr::FormMgrDeathRecipient> formMgrDeath = new (std::nothrow) FormMgr::FormMgrDeathRecipient();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    formMgrDeath->OnRemoteDied(mockFormProviderClient);
    EXPECT_TRUE(FormMgr::GetInstance().GetRecoverStatus() == Constants::IN_RECOVERING);
    GTEST_LOG_(INFO) << "FormMgrTest_0071 test ends";
}

/**
 * @tc.name: FormMgrTest_0072
 * @tc.desc: Verify OnRemoteDied (Parameter is nullptr)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0072, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0072 starts";
    sptr<FormMgr::FormMgrDeathRecipient> formMgrDeath = new (std::nothrow) FormMgr::FormMgrDeathRecipient();
    formMgrDeath->OnRemoteDied(nullptr);
    GTEST_LOG_(INFO) << "FormMgrTest_0072 test ends";
}

/**
 * @tc.name: FormMgrTest_0073
 * @tc.desc: Verify Reconnect
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0073, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0073 starts";
    bool data =  FormMgr::GetInstance().Reconnect();
    EXPECT_EQ(data, true);
    GTEST_LOG_(INFO) << "FormMgrTest_0073 test ends";
}

/**
 * @tc.name: FormMgrTest_0074
 * @tc.desc: Verify ResetProxy (Parameter is nullptr)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0074, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0074 starts";
    std::shared_ptr<FormMgr> formMgr = std::make_shared<FormMgr>();
    ASSERT_NE(nullptr, formMgr);
    formMgr->ResetProxy(nullptr);
    formMgr->SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0074 test ends";
}

/**
 * @tc.name: FormMgrTest_0075
 * @tc.desc: Verify ResetProxy
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0075, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0075 starts";
    sptr<IRemoteObject> remote = new (std::nothrow) MockFormProviderClient();
    FormMgr::GetInstance().ResetProxy(remote);
    EXPECT_TRUE(FormMgr::GetInstance().GetRecoverStatus() == Constants::IN_RECOVERING);
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0075 test ends";
}

/**
 * @tc.name: FormMgrTest_0076
 * @tc.desc: Verify DeleteInvalidForms (The return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0076, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0076 starts";

    std::vector<int64_t> formInfos;
    formInfos.push_back(1);
    formInfos.push_back(2);
    FormJsInfo formJsInfo;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t numFormsDeleted = 2;
    auto result = FormMgr::GetInstance().DeleteInvalidForms(formInfos, token, numFormsDeleted);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0076 test ends";
}

/**
 * @tc.name: FormMgrTest_0077
 * @tc.desc: Verify AcquireFormState (The return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0077, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0077 starts";

    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormStateInfo stateInfo;
    auto result = FormMgr::GetInstance().AcquireFormState(want, token, stateInfo);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0077 test ends";
}

/**
 * @tc.name: FormMgrTest_0078
 * @tc.desc: Verify NotifyFormsVisible (The return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0078, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0078 starts";

    int64_t formId1 = 5;
    int64_t formId2 = 6;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);
    formIds.push_back(formId2);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsVisible(formIds, isProtected, token);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0078 test ends";
}

/**
 * @tc.name: FormMgrTest_0079
 * @tc.desc: Verify NotifyFormsPrivacyProtected (The return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0079, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0079 starts";

    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    bool isProtected = false;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, token);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0079 test ends";
}

/**
 * @tc.name: FormMgrTest_0080
 * @tc.desc: Verify NotifyFormsEnableUpdate (The return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0080, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0080 starts";

    int64_t formId1 = 3;
    int64_t formId2 = 4;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);
    formIds.push_back(formId2);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsEnableUpdate(formIds, isProtected, token);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0080 test ends";
}

/**
 * @tc.name: FormMgrTest_0081
 * @tc.desc: Verify GetAllFormsInfo (The return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0081, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0081 starts";

    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    auto result = FormMgr::GetInstance().GetAllFormsInfo(formInfos);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0081 test ends";
}

/**
 * @tc.name: FormMgrTest_0082
 * @tc.desc: Verify GetFormsInfoByApp (The return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0082, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0082 starts";

    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    std::string bundleName = "a";
    auto result = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0082 test ends";
}

/**
 * @tc.name: FormMgrTest_0083
 * @tc.desc: Verify GetFormsInfoByModule (The return value of mock function is not 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0083, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0083 starts";

    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    std::string bundleName = "a";
    std::string moduleName = "A";
    auto result = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0083 test ends";
}

/**
 * @tc.name: FormMgrTest_0084
 * @tc.desc: Verify CheckFMSReady (mock function returns nullptr)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0084, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0084 starts";
    sptr<MockSystemAbilityManager> mockSamgr = new (std::nothrow) MockSystemAbilityManager();
    sptr<ISystemAbilityManager> backupSamgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    SystemAbilityManagerClient::GetInstance().systemAbilityManager_ = mockSamgr;
    std::shared_ptr<bool> dummyVal = std::make_shared<bool>(true);
    mockSamgr->weakGetSystemAbility_ = dummyVal;
    auto result = FormMgr::GetInstance().CheckFMSReady();
    EXPECT_TRUE(result == false);
    GTEST_LOG_(INFO) << "FormMgrTest_0084 test ends";
}

/**
 * @tc.name: FormMgrTest_0085
 * @tc.desc: Verify ShareForm (The return value of mock function is 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0085, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0085 starts";
    EXPECT_CALL(*mockProxy, ShareForm(_, _, _, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    int64_t formId = 0;
    std::string deviceId = "aa";
    int64_t requestCode = 1;
    sptr<IRemoteObject> Token = new (std::nothrow) MockFormProviderClient();
    auto result = FormMgr::GetInstance().ShareForm(formId, deviceId, Token, requestCode);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0085 test ends";
}

/**
 * @tc.name: FormMgrTest_0086
 * @tc.desc: Verify GetFormsCount
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0086, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0086 starts";
    bool isTempFormFlag = true;
    int32_t formCount = 0;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().GetFormsCount(isTempFormFlag, formCount);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0086 test ends";
}

/**
 * @tc.name: FormMgrTest_0087
 * @tc.desc: Verify GetFormsCount
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0087, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0087 starts";
    bool isTempFormFlag = true;
    int32_t formCount = 0;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetFormsCount(isTempFormFlag, formCount);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0087 test ends";
}

/**
 * @tc.name: FormMgrTest_0088
 * @tc.desc: Verify GetHostFormsCount
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0088, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0088 starts";
    std::string bundleName = "this is bundleName";
    int32_t formCount = 0;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().GetHostFormsCount(bundleName, formCount);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0088 test ends";
}

/**
 * @tc.name: FormMgrTest_0089
 * @tc.desc: Verify GetHostFormsCount
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0089, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0089 starts";
    std::string bundleName = "";
    int32_t formCount = 0;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetHostFormsCount(bundleName, formCount);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME);
    GTEST_LOG_(INFO) << "FormMgrTest_0089 test ends";
}

/**
 * @tc.name: FormMgrTest_0090
 * @tc.desc: Verify GetHostFormsCount
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0090, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0090 starts";
    std::string bundleName = "this is bundleName";
    int32_t formCount = 0;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetHostFormsCount(bundleName, formCount);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0090 test ends";
}

/**
 * @tc.name: FormMgrTest_0091
 * @tc.desc: Verify AcquireFormData (The return value of mock function is 0)
 * @tc.type: FUNC
 * @tc.require: issueI63Y7Y
 */
HWTEST_F(FormMgrTest, FormMgrTest_0091, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0091 starts";
    EXPECT_CALL(*mockProxy, AcquireFormData(_, _, _, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    int64_t formId = 0;
    int64_t requestCode = 1;
    AAFwk::WantParams formData;
    sptr<IRemoteObject> Token = new (std::nothrow) MockFormProviderClient();
    auto result = FormMgr::GetInstance().AcquireFormData(formId, requestCode, Token, formData);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0091 test ends";
}

/**
 * @tc.name: FormMgrTest_0092
 * @tc.desc: Verify GetRunningFormInfos
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0092, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0092 starts";
    EXPECT_CALL(*mockProxy, GetRunningFormInfos(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);

    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    int result = FormMgr::GetInstance().GetRunningFormInfos(isUnusedInclude, runningFormInfos);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0092 test ends";
}

/**
 * @tc.name: FormMgrTest_0093
 * @tc.desc: Verify GetRunningFormInfos
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0093, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0093 starts";

    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);

    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    int result = FormMgr::GetInstance().GetRunningFormInfos(isUnusedInclude, runningFormInfos);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0093 test ends";
}

/**
 * @tc.name: FormMgrTest_0094
 * @tc.desc: Verify GetRunningFormInfos
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0094, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0094 starts";
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, GetRunningFormInfos(_, _))
        .Times(1)
        .WillOnce(Return(ERROR_NUM));
    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    int result = FormMgr::GetInstance().GetRunningFormInfos(isUnusedInclude, runningFormInfos);

    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0094 test ends";
}

/**
 * @tc.name: FormMgrTest_0095
 * @tc.desc: Verify GetRunningFormInfos
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0095, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0095 starts";
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, GetRunningFormInfos(_, _))
        .Times(1)
        .WillOnce(Return(NEGATIVE_NUM));
    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    int result = FormMgr::GetInstance().GetRunningFormInfos(isUnusedInclude, runningFormInfos);

    EXPECT_EQ(result, NEGATIVE_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0095 test ends";
}

/**
 * @tc.name: FormMgrTest_0096
 * @tc.desc: Verify GetRunningFormInfos
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0096, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0096 starts";
    EXPECT_CALL(*mockProxy, GetRunningFormInfosByBundleName(_, _, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);

    std::string bundleName = "a";
    bool isUnusedInclude = false;
    std::vector<RunningFormInfo> runningFormInfos;
    int result = FormMgr::GetInstance().GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0096 test ends";
}

/**
 * @tc.name: FormMgrTest_0097
 * @tc.desc: Verify GetRunningFormInfosByBundleName
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0097, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0097 starts";
    EXPECT_CALL(*mockProxy, GetRunningFormInfosByBundleName(_, _, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    bool isUnusedInclude = false;
    std::vector<RunningFormInfo> runningFormInfos;
    int result = FormMgr::GetInstance().GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0097 test ends";
}

/**
 * @tc.name: FormMgrTest_0098
 * @tc.desc: Verify GetRunningFormInfosByBundleName
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0098, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0098 starts";

    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    std::string bundleName = "a";
    bool isUnusedInclude = false;
    std::vector<RunningFormInfo> runningFormInfos;
    int result = FormMgr::GetInstance().GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0098 test ends";
}

/**
 * @tc.name: FormMgrTest_0099
 * @tc.desc: Verify GetRunningFormInfosByBundleName
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0099, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0099 starts";
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, GetRunningFormInfosByBundleName(_, _, _))
        .Times(1)
        .WillOnce(Return(ERROR_NUM));
    std::string bundleName = "a";
    bool isUnusedInclude = false;
    std::vector<RunningFormInfo> runningFormInfos;
    int result = FormMgr::GetInstance().GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);

    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0099 test ends";
}

/**
 * @tc.name: FormMgrTest_0100
 * @tc.desc: Verify RegisterFormAddObserverByBundle
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0100, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0100 starts";
    EXPECT_CALL(*mockProxy, RegisterFormAddObserverByBundle(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().RegisterFormAddObserverByBundle(bundleName, callerToken);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0100 test ends";
}

/**
 * @tc.name: FormMgrTest_0101
 * @tc.desc: Verify RegisterFormAddObserverByBundle
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0101, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0101 starts";

    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().RegisterFormAddObserverByBundle(bundleName, callerToken);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0101 test ends";
}

/**
 * @tc.name: FormMgrTest_0102
 * @tc.desc: Verify RegisterFormAddObserverByBundle
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0102, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0102 starts";
    EXPECT_CALL(*mockProxy, RegisterFormAddObserverByBundle(_, _))
        .Times(1)
        .WillOnce(Return(ERROR_NUM));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().RegisterFormAddObserverByBundle(bundleName, callerToken);

    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0102 test ends";
}

/**
 * @tc.name: FormMgrTest_0103
 * @tc.desc: Verify RegisterFormRemoveObserverByBundle
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0103, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0103 starts";
    EXPECT_CALL(*mockProxy, RegisterFormRemoveObserverByBundle(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, callerToken);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0103 test ends";
}

/**
 * @tc.name: FormMgrTest_0104
 * @tc.desc: Verify RegisterFormRemoveObserverByBundle
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0104, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0104 starts";

    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, callerToken);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0104 test ends";
}

/**
 * @tc.name: FormMgrTest_0105
 * @tc.desc: Verify RegisterFormRemoveObserverByBundle
 * @tc.type: FUNC
 * @tc.require: issueI63OQL
 */
HWTEST_F(FormMgrTest, FormMgrTest_0105, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0105 starts";
    EXPECT_CALL(*mockProxy, RegisterFormRemoveObserverByBundle(_, _))
        .Times(1)
        .WillOnce(Return(ERROR_NUM));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, callerToken);

    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0105 test ends";
}

/**
 * @tc.name: FormMgrTest_0106
 * @tc.desc: Verify UpdateForm (include data proxies)
 * @tc.type: FUNC
 * @tc.require: issueI7CGTP
 */
HWTEST_F(FormMgrTest, FormMgrTest_0106, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0106 starts";
    EXPECT_CALL(*mockProxy, UpdateProxyForm(_, _, _))
        .Times(1)
        .WillOnce(Return(NEGATIVE_NUM));
    FormJsInfo formJsInfo;
    formJsInfo.formId = 0x00000008fffffffL;
    FormProviderData formProviderData = FormProviderData(std::string("{\"city\": \"beijing001\"}"));
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("city", "");
    formDataProxies.push_back(formDataProxy);
    int32_t result = FormMgr::GetInstance().UpdateForm(formJsInfo.formId, formProviderData, formDataProxies);
    EXPECT_EQ(result, NEGATIVE_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0106 test ends";
}

/**
 * @tc.name: FormMgrTest_0107
 * @tc.desc: Verify RequestPublishForm (include data proxies)
 * @tc.type: FUNC
 * @tc.require: issueI7CGTP
 */
HWTEST_F(FormMgrTest, FormMgrTest_0107, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0107 starts";
    EXPECT_CALL(*mockProxy, RequestPublishProxyForm(_, _, _, _, _))
        .Times(1)
        .WillOnce(Return(NEGATIVE_NUM));
    Want want;
    int64_t formId = 0x00000008fffffffL;
    std::unique_ptr<FormProviderData> formProviderData;
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("city", "");
    formDataProxies.push_back(formDataProxy);
    int32_t result = FormMgr::GetInstance().RequestPublishForm(want, true, formProviderData, formId, formDataProxies);
    EXPECT_EQ(result, NEGATIVE_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0107 test ends";
}

/**
 * @tc.name: FormMgrTest_0108
 * @tc.desc: Verify StopRenderingForm
 * @tc.type: FUNC
 * @tc.require: issueI7HGZ2
 */
HWTEST_F(FormMgrTest, FormMgrTest_0108, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0108 starts";
    int64_t formId = 0;
    std::string compId = "this is compId";
    int result = FormMgr::GetInstance().StopRenderingForm(formId, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0108 test ends";
}

/**
 * @tc.name: FormMgrTest_0109
 * @tc.desc: Verify ReleaseRenderer
 * @tc.type: FUNC
 * @tc.require: issueI7HGZ2
 */
HWTEST_F(FormMgrTest, FormMgrTest_0109, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0109 starts";
    int64_t formId = 0;
    std::string compId = "this is compId";
    int result = FormMgr::GetInstance().ReleaseRenderer(formId, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0109 test ends";
}

/**
 * @tc.name: FormMgrTest_0111
 * @tc.desc: Verify GetErrorMsgByExternalErrorCode
 * @tc.type: FUNC
 * @tc.require: issueI7HGZ2
 */
HWTEST_F(FormMgrTest, FormMgrTest_0111, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0111 starts";
    int32_t innerErrorCode = 0;
    int32_t externalErrorCode = 0;
    std::string errorMsg = "this is errorMsg";
    FormMgr::GetInstance().GetExternalError(innerErrorCode, externalErrorCode, errorMsg);

    std::string result = FormMgr::GetInstance().GetErrorMsgByExternalErrorCode(externalErrorCode);
    EXPECT_EQ(result, "success");
    GTEST_LOG_(INFO) << "FormMgrTest_0111 test ends";
}

/**
 * @tc.name: FormMgrTest_0112
 * @tc.desc: Verify GetFormInstancesByFilter
 * @tc.type: FUNC
 * @tc.require: issueI7HGZ2
 */
HWTEST_F(FormMgrTest, FormMgrTest_0112, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0112 starts";
    FormInstancesFilter filter;
    std::vector<FormInstance> formInstances;
    ErrCode result = FormMgr::GetInstance().GetFormInstancesByFilter(filter, formInstances);
    int code = 8388610;
    EXPECT_EQ(result, code);

    int64_t formId = 1;
    FormInstance formInstance;
    ErrCode result1 = FormMgr::GetInstance().GetFormInstanceById(formId, formInstance);
    EXPECT_EQ(result1, code);
    GTEST_LOG_(INFO) << "FormMgrTest_0112 test ends";
}

/**
 * @tc.name: FormMgrTest_0113
 * @tc.desc: Verify BackgroundEvent
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormMgrTest, FormMgrTest_0113, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0113 starts";
    EXPECT_CALL(*mockProxy, BackgroundEvent(_, _, _))
        .Times(1)
        .WillOnce(Return(ERROR_NUM));
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    Want want;
    int64_t formId = 1;
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().BackgroundEvent(formId, want, callerToken);

    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0113 test ends";
}

/**
 * @tc.name: FormMgrTest_0114
 * @tc.desc: Verify RegisterPublishFormInterceptor
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormMgrTest, FormMgrTest_0114, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0114 starts";
    EXPECT_CALL(*mockProxy, RegisterPublishFormInterceptor(_))
        .Times(1)
        .WillOnce(Return(ERR_OK));
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    sptr<IRemoteObject> interceptorCallback;

    int32_t result = FormMgr::GetInstance().RegisterPublishFormInterceptor(interceptorCallback);

    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0114 test ends";
}

/**
 * @tc.name: FormMgrTest_0115
 * @tc.desc: Verify UnregisterPublishFormInterceptor
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormMgrTest, FormMgrTest_0115, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0115 starts";
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, UnregisterPublishFormInterceptor(_))
        .Times(1)
        .WillOnce(Return(ERROR_NUMS));
    sptr<IRemoteObject> interceptorCallback;

    int32_t result = FormMgr::GetInstance().UnregisterPublishFormInterceptor(interceptorCallback);
    EXPECT_EQ(result, 8388610);
    GTEST_LOG_(INFO) << "FormMgrTest_0115 test ends";
}

/**
 * @tc.name: FormMgrTest_0117
 * @tc.desc: Verify RegisterAddObserver
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormMgrTest, FormMgrTest_0117, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0117 starts";

    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    std::string bundleName = "this is a bundleName";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();

    ErrCode result = FormMgr::GetInstance().RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0117 test ends";
}

/**
 * @tc.name: FormMgrTest_0118
 * @tc.desc: Verify RegisterRemoveObserver
 * @tc.type: FUNC
 * @tc.require: IssueI7X4L4
 */
HWTEST_F(FormMgrTest, FormMgrTest_0118, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0118 starts";

    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();

    ErrCode result = FormMgr::GetInstance().RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0118 test ends";
}

/**
 * @tc.name: FormMgrTest_0119
 * @tc.desc: Verify RegisterFormRouterProxy
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrTest, FormMgrTest_0119, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0119 starts";

    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    std::vector<int64_t> formIds;
    formIds.push_back(0);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();

    ErrCode result = FormMgr::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0119 test ends";
}

/**
 * @tc.name: FormMgrTest_0120
 * @tc.desc: Verify UnregisterFormRouterProxy
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrTest, FormMgrTest_0120, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0120 starts";

    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    std::vector<int64_t> formIds;
    formIds.push_back(0);

    ErrCode result = FormMgr::GetInstance().UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0120 test ends";
}

/**
 * @tc.name: FormMgrTest_0121
 * @tc.desc: Verify HasFormVisible
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0121, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0121 starts";
    EXPECT_CALL(*mockProxy, HasFormVisible(_))
        .Times(1)
        .WillOnce(Return(true));
    uint32_t tokenId = 0;
    bool result = FormMgr::GetInstance().HasFormVisible(tokenId);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrTest_0121 test ends";
}

/**
 * @tc.name: FormMgrTest_0122
 * @tc.desc: Verify GetFormsInfoByFilter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(FormMgrTest, FormMgrTest_0122, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0122 starts";
    FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    expectFormInfos.push_back(formInfo);
    EXPECT_CALL(*mockProxy, GetFormsInfoByFilter(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(expectFormInfos), Return(ERR_OK)));
    FormMgr::GetInstance().GetFormsInfoByFilter(filter, formInfos);
    EXPECT_THAT(formInfos, ContainerEq(expectFormInfos));
    testing::Mock::AllowLeak(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0122 test ends";
}

/**
 * @tc.name: FormMgrTest_0123
 * @tc.desc: Verify UpdateFormLocation (The return value of mock function is not 0)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0123, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0123 starts";

    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int64_t formId = 0;
    int32_t formLocation = 1;
    EXPECT_EQ(FormMgr::GetInstance().UpdateFormLocation(formId, formLocation), ERROR_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0123 test ends";
}

/**
 * @tc.name: FormMgrTest_0124
 * @tc.desc: Verify CreateForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0124, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0124 starts";
    EXPECT_CALL(*mockProxy, CreateForm(_, _))
        .Times(1)
        .WillOnce(Return(0));
    Want want;
    RunningFormInfo runningFormInfo;
    int result = FormMgr::GetInstance().CreateForm(want, runningFormInfo);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0124 test ends";
}

/**
 * @tc.name: FormMgrTest_0125
 * @tc.desc: Verify RegisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0125, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0125 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    sptr<IRemoteObject> observer = nullptr;
    int result = FormMgr::GetInstance().RegisterClickEventObserver(bundleName, formEventType, observer);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrTest_0125 end";
}

/**
 * @tc.name: FormMgrTest_0126
 * @tc.desc: Verify RegisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0126, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0126 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().RegisterClickEventObserver(bundleName, formEventType, iremoteObject);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0126 end";
}

/**
 * @tc.name: FormMgrTest_0127
 * @tc.desc: Verify RegisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0127, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0127 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";

    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);

    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, RegisterClickEventObserver(_, _, _))
    .Times(1)
    .WillOnce(Return(OHOS::ERR_OK));
    int result = FormMgr::GetInstance().RegisterClickEventObserver(bundleName, formEventType, iremoteObject);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0127 end";
}

/**
 * @tc.name: FormMgrTest_0128
 * @tc.desc: Verify RegisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0128, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0128 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    FormMgr::GetInstance().resetFlag_ = true;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    FormMgr::GetInstance().RegisterClickEventObserver(bundleName, formEventType, iremoteObject);
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0128 end";
}

/**
 * @tc.name: FormMgrTest_0129
 * @tc.desc: Verify UnregisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0129, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0129 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    sptr<IRemoteObject> observer = nullptr;
    int result = FormMgr::GetInstance().UnregisterClickEventObserver(bundleName, formEventType, observer);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrTest_0129 end";
}

/**
 * @tc.name: FormMgrTest_0130
 * @tc.desc: Verify UnregisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0130, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0130 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().UnregisterClickEventObserver(bundleName, formEventType, iremoteObject);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0130 end";
}

/**
 * @tc.name: FormMgrTest_0131
 * @tc.desc: Verify UnregisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0131, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0131 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";

    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);

    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, UnregisterClickEventObserver(_, _, _))
    .Times(1)
    .WillOnce(Return(OHOS::ERR_OK));
    int result = FormMgr::GetInstance().UnregisterClickEventObserver(bundleName, formEventType, iremoteObject);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0131 end";
}

/**
 * @tc.name: FormMgrTest_0132
 * @tc.desc: Verify UnregisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0132, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0132 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    FormMgr::GetInstance().resetFlag_ = true;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    FormMgr::GetInstance().UnregisterClickEventObserver(bundleName, formEventType, iremoteObject);
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0132 end";
}

/**
 * @tc.name: FormMgrTest_0133
 * @tc.desc: Verify SetFormsRecyclable
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0133, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0133 test begin";
    std::vector<int64_t> formIds;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int32_t result = FormMgr::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0133 test ends";
}

/**
 * @tc.name: FormMgrTest_0134
 * @tc.desc: Verify SetFormsRecyclable
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0134, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0134 test begin";
    std::vector<int64_t> formIds;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0134 test ends";
}

/**
 * @tc.name: FormMgrTest_0135
 * @tc.desc: Verify SetFormsRecyclable
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0135, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0135 test begin";
    std::vector<int64_t> formIds;
    int64_t formId1 = 1;
    int64_t formId2 = 2;
    formIds.push_back(formId1);
    formIds.push_back(formId2);
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, SetFormsRecyclable(_))
    .Times(1)
    .WillOnce(Return(OHOS::ERR_OK));
    int32_t result = FormMgr::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0135 test ends";
}

/**
 * @tc.name: FormMgrTest_0136
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0136, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0136 begin";
    std::vector<int64_t> formIds;
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int32_t result = FormMgr::GetInstance().RecycleForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0136 test ends";
}

/**
 * @tc.name: FormMgrTest_0137
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0137, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0137 begin";
    std::vector<int64_t> formIds;
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().RecycleForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0137 test ends";
}

/**
 * @tc.name: FormMgrTest_0138
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0138, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0138 begin";
    std::vector<int64_t> formIds;
    int64_t formId1 = 1;
    formIds.push_back(formId1);
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);

    int32_t result = FormMgr::GetInstance().RecycleForms(formIds, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0138 test ends";
}

/**
 * @tc.name: FormMgrTest_0139
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0139, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0139 begin";
    std::vector<int64_t> formIds;
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int32_t result = FormMgr::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0139 test ends";
}

/**
 * @tc.name: FormMgrTest_0140
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0140, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0140 begin";
    std::vector<int64_t> formIds;
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0140 test ends";
}

/**
 * @tc.name: FormMgrTest_0141
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0141, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0141 begin";
    std::vector<int64_t> formIds;
    int64_t formId1 = 1;
    formIds.push_back(formId1);
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, RecoverForms(_, _))
    .Times(1)
    .WillOnce(Return(OHOS::ERR_OK));
    int32_t result = FormMgr::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0141 test ends";
}

/**
 * @tc.name: FormMgrTest_0142
 * @tc.desc: Verify SetPublishFormResult (The return value of mock function is not 0)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0142, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0142 starts";

    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int64_t formId = 0;
    Constants::PublishFormResult result {Constants::PublishFormErrorCode::SUCCESS, ""};
    EXPECT_EQ(FormMgr::GetInstance().SetPublishFormResult(formId, result), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0142 test ends";
}

/**
 * @tc.name: FormMgrTest_0143
 * @tc.desc: Verify AcquireAddFormResult (The return value of mock function is not 0)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0143, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0143 starts";

    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int64_t formId = 0;
    EXPECT_EQ(FormMgr::GetInstance().AcquireAddFormResult(formId), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0143 test ends";
}

/**
 * @tc.name: FormMgrTest_0144
 * @tc.desc: Verify BatchRefreshForms (The return value of mock function is not 0)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0144, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0144 starts";
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int32_t formRefreshType = Constants::REFRESH_ALL_FORM;
    EXPECT_EQ(FormMgr::GetInstance().BatchRefreshForms(formRefreshType), ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0144 test ends";
}

/**
 * @tc.name: FormMgrTest_0145
 * @tc.desc: Verify BatchRefreshForms (The return value of mock function is not 0)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0145, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0145 starts";
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t formRefreshType = Constants::REFRESH_ALL_FORM - 1;
    EXPECT_EQ(FormMgr::GetInstance().BatchRefreshForms(formRefreshType), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    formRefreshType = Constants::REFRESH_ATOMIC_FORM + 1;
    EXPECT_EQ(FormMgr::GetInstance().BatchRefreshForms(formRefreshType), ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrTest_0145 test ends";
}

/**
 * @tc.name: FormMgrTest_0146
 * @tc.desc: Verify BatchRefreshForms (The return value of mock function is not 0)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0146, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0146 starts";
    EXPECT_CALL(*mockProxy, BatchRefreshForms(_))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
        int32_t formRefreshType = Constants::REFRESH_ALL_FORM;
    EXPECT_EQ(FormMgr::GetInstance().BatchRefreshForms(formRefreshType), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0146 test ends";
}

/**
 * @tc.name: FormMgrTest_0147
 * @tc.desc: Verify EnableForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0147, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0147 begin";
    std::string bundleName = "ohos.samples.FormApplication";
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int32_t result = FormMgr::GetInstance().EnableForms(bundleName, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0147 test ends";
}

/**
 * @tc.name: FormMgrTest_0148
 * @tc.desc: Verify EnableForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0148, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0148 begin";
    std::string bundleName = "ohos.samples.FormApplication";
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, EnableForms(_, _))
    .Times(1)
    .WillOnce(Return(OHOS::ERR_OK));
    int32_t result = FormMgr::GetInstance().EnableForms(bundleName, true);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0148 test ends";
}

/**
 * @tc.name: FormMgrTest_0149
 * @tc.desc: Verify EnableForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0149, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0149 begin";
    std::string bundleName;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().EnableForms(bundleName, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrTest_0149 test ends";
}

/**
 * @tc.name: FormMgrTest_0150
 * @tc.desc: Verify IsFormBundleForbidden
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0150, TestSize.Level0) {
    GTEST_LOG_(INFO) << "FormMgrTest_0150 begin";
    std::string bundleName = "ohos.samples.FormApplication";
    bool result = FormMgr::GetInstance().IsFormBundleForbidden(bundleName);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrTest_0150 test ends";
}

/**
 * @tc.name: FormMgrTest_0151
 * @tc.desc: Verify IsFormBundleForbidden
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0151, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0151 begin";
    EXPECT_CALL(*mockProxy, IsFormBundleForbidden(_))
        .Times(1)
        .WillOnce(Return(true));
    std::string bundleName = "ohos.samples.FormApplication";
    bool result = FormMgr::GetInstance().IsFormBundleForbidden(bundleName);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrTest_0151 test ends";
}

/**
 * @tc.name: FormMgrTest_0152
 * @tc.desc: Verify RequestPublishFormWithSnapshot (include data proxies)
 * @tc.type: FUNC
 * @tc.require: issueIA6CAJ
 */
HWTEST_F(FormMgrTest, FormMgrTest_0152, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0152 starts";
    EXPECT_CALL(*mockProxy, RequestPublishFormWithSnapshot(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));
    Want want;
    int64_t formId = 0x00000008fffffffL;
    std::unique_ptr<FormProviderData> formProviderData;
    FormDataProxy formDataProxy("city", "");
    ErrCode result = FormMgr::GetInstance().RequestPublishFormWithSnapshot(want, true, formProviderData, formId);
    EXPECT_EQ(result, ERR_OK);
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.isSystemApp = false;
    FormMgr::GetInstance().resetFlag_ = true;
    result = FormMgr::GetInstance().RequestPublishFormWithSnapshot(want, true, formProviderData, formId);
    EXPECT_NE(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0152 test ends";
}

/**
 * @tc.name: FormMgrTest_0153
 * @tc.desc: Verify StopRenderingForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0153, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0153 starts";
    int64_t formId = FORM_ID;
    std::string compId = "this is compId";
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().StopRenderingForm(formId, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0153 test ends";
}

/**
 * @tc.name: FormMgrTest_0154
 * @tc.desc: Verify ReleaseRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0154, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0154 starts";
    EXPECT_CALL(*mockProxy, ReleaseRenderer(_, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));
    SetUpTestCase();
    int64_t formId = FORM_ID;
    std::string compId = "this is compId";
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().ReleaseRenderer(formId, compId);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0154 test ends";
}

/**
 * @tc.name: FormMgrTest_0155
 * @tc.desc: Verify ReleaseRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0155, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0155 starts";
    int64_t formId = FORM_ID;
    std::string compId = "this is compId";
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().ReleaseRenderer(formId, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_0155 test ends";
}

/**
 * @tc.name: FormMgrTest_0156
 * @tc.desc: Verify SetNextRefreshTime
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0156, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0156 starts";
    EXPECT_CALL(*mockProxy, SetNextRefreshTime(_, _))
        .Times(1)
        .WillOnce(Return(0));
    int64_t formId = FORM_ID;
    int64_t nextTime = 50;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    auto result = FormMgr::GetInstance().SetNextRefreshTime(formId, nextTime);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0156 test ends";
}

/**
 * @tc.name: FormMgrTest_0157
 * @tc.desc: Verify RequestPublishForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0157, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0157 starts";
    EXPECT_CALL(*mockProxy, RequestPublishForm(_, _, _, _))
        .Times(1)
        .WillOnce(Return(NEGATIVE_NUM));
    Want want;
    int64_t formId = FORM_ID;
    std::unique_ptr<FormProviderData> formProviderData;
    std::vector<FormDataProxy> formDataProxies;
    int32_t result = FormMgr::GetInstance().RequestPublishForm(want, true, formProviderData, formId, formDataProxies);
    EXPECT_EQ(result, NEGATIVE_NUM);
    GTEST_LOG_(INFO) << "FormMgrTest_0157 test ends";
}

/**
 * @tc.name: FormMgrTest_0158
 * @tc.desc: Verify SetPublishFormResult
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0158, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0158 starts";
    EXPECT_CALL(*mockProxy, SetPublishFormResult(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    Constants::PublishFormResult errorCodeInfo{Constants::PublishFormErrorCode::SUCCESS, ""};
    int64_t formId = FORM_ID;
    ErrCode result = FormMgr::GetInstance().SetPublishFormResult(formId, errorCodeInfo);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0158 test ends";
}

/**
 * @tc.name: FormMgrTest_0159
 * @tc.desc: Verify AcquireAddFormResult
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0159, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0159 starts";
    EXPECT_CALL(*mockProxy, AcquireAddFormResult(_))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    int64_t formId = FORM_ID;
    EXPECT_EQ(FormMgr::GetInstance().AcquireAddFormResult(formId), OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0159 test ends";
}

/**
 * @tc.name: FormMgrTest_0160
 * @tc.desc: Verify LifecycleUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0160, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0160 starts";
    EXPECT_CALL(*mockProxy, LifecycleUpdate(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    std::vector<int64_t> formIds;
    int64_t formId = FORM_ID;
    formIds.emplace_back(formId);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = FormMgr::GetInstance().LifecycleUpdate(formIds, token, true);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0160 test ends";
}

/**
 * @tc.name: FormMgrTest_0161
 * @tc.desc: Verify GetRecoverStatus
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0161, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0161 starts";
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    EXPECT_TRUE(FormMgr::GetInstance().GetRecoverStatus() == Constants::IN_RECOVERING);
    GTEST_LOG_(INFO) << "FormMgrTest_0161 test ends";
}

/**
 * @tc.name: FormMgrTest_0162
 * @tc.desc: Verify GetFormInstancesByFilter
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0162, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0162 starts";
    EXPECT_CALL(*mockProxy, GetFormInstanceById(_, _, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    int64_t formId = FORM_ID;
    FormInstance formInstance;
    auto result = FormMgr::GetInstance().GetFormInstanceById(formId, true, formInstance);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0162 test ends";
}

/**
 * @tc.name: FormMgrTest_0163
 * @tc.desc: Verify IsSystemAppForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0163, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0163 starts";
    EXPECT_CALL(*mockProxy, IsSystemAppForm(_))
        .Times(1)
        .WillOnce(Return(true));
    std::string bundle = "bundle";
    bool result = FormMgr::GetInstance().IsSystemAppForm(bundle);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrTest_0163 test ends";
}

/**
 * @tc.name: FormMgrTest_0164
 * @tc.desc: Verify GetRunningFormInfosByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0164, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0164 starts";
    std::string bundleName;
    bool isUnusedInclude = false;
    std::vector<RunningFormInfo> runningFormInfos;
    int result = FormMgr::GetInstance().GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME);
    GTEST_LOG_(INFO) << "FormMgrTest_0164 test ends";
}

/**
 * @tc.name: FormMgrTest_0165
 * @tc.desc: Verify GetFormsCount
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0165, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0165 starts";
    EXPECT_CALL(*mockProxy, GetFormsCount(_, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    bool isTempFormFlag = true;
    int32_t formCount = 0;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetFormsCount(isTempFormFlag, formCount);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0165 test ends";
}

/**
 * @tc.name: FormMgrTest_0166
 * @tc.desc: Verify GetHostFormsCount
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0166, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0166 starts";
    EXPECT_CALL(*mockProxy, GetHostFormsCount(_, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    std::string bundleName = "this is bundleName";
    int32_t formCount = 0;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetHostFormsCount(bundleName, formCount);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0166 test ends";
}

/**
 * @tc.name: FormMgrTest_0167
 * @tc.desc: Verify RegisterAddObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0167, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0167 starts";
    EXPECT_CALL(*mockProxy, RegisterAddObserver(_, _))
        .Times(1)
        .WillOnce(Return(0));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "this is a bundleName";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    ErrCode result = FormMgr::GetInstance().RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0167 test ends";
}

/**
 * @tc.name: FormMgrTest_0168
 * @tc.desc: Verify RegisterRemoveObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0168, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0168 starts";
    EXPECT_CALL(*mockProxy, RegisterRemoveObserver(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    ErrCode result = FormMgr::GetInstance().RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0168 test ends";
}

/**
 * @tc.name: FormMgrTest_0169
 * @tc.desc: Verify RegisterFormRouterProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0169, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0169 starts";
    EXPECT_CALL(*mockProxy, RegisterFormRouterProxy(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::vector<int64_t> formIds;
    formIds.push_back(0);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    ErrCode result = FormMgr::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0169 test ends";
}

/**
 * @tc.name: FormMgrTest_0170
 * @tc.desc: Verify UnregisterFormRouterProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0170, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0170 starts";
    EXPECT_CALL(*mockProxy, UnregisterFormRouterProxy(_))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::vector<int64_t> formIds;
    formIds.push_back(0);
    ErrCode result = FormMgr::GetInstance().UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0170 test ends";
}

/**
 * @tc.name: FormMgrTest_0171
 * @tc.desc: Verify UpdateFormLocation
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0171, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0171 starts";
    EXPECT_CALL(*mockProxy, UpdateFormLocation(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int64_t formId = FORM_ID;
    int32_t formLocation = 1;
    EXPECT_EQ(FormMgr::GetInstance().UpdateFormLocation(formId, formLocation), OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0171 test ends";
}

/**
 * @tc.name: FormMgrTest_0172
 * @tc.desc: Verify AddForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0172, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0172 starts";
    int64_t formId = FORM_ID;
    Want want;
    FormJsInfo formInfo;
    FormMgr::GetInstance().resetFlag_ = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    auto data = FormMgr::GetInstance().AddForm(formId, want, token, formInfo);
    EXPECT_EQ(data, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0172 test ends";
}

/**
 * @tc.name: FormMgrTest_0173
 * @tc.desc: Verify CreateForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0173, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0173 starts";
    Want want;
    FormMgr::GetInstance().resetFlag_ = true;
    RunningFormInfo runningFormInfo;
    int result = FormMgr::GetInstance().CreateForm(want, runningFormInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0173 test ends";
}

/**
 * @tc.name: FormMgrTest_0174
 * @tc.desc: Verify DeleteForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0174, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0174 starts";
    int64_t formId = FORM_ID;
    FormMgr::GetInstance().resetFlag_ = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().DeleteForm(formId, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0174 test ends";
}

/**
 * @tc.name: FormMgrTest_0175
 * @tc.desc: Verify StopRenderingForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0175, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0175 starts";
    int64_t formId = FORM_ID;
    std::string compId = "this is compId";
    FormMgr::GetInstance().resetFlag_ = true;
    int result = FormMgr::GetInstance().StopRenderingForm(formId, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0175 test ends";
}

/**
 * @tc.name: FormMgrTest_0176
 * @tc.desc: Verify StopRenderingForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0176, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0176 starts";
    EXPECT_CALL(*mockProxy, StopRenderingForm(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    int64_t formId = FORM_ID;
    std::string compId = "this is compId";
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    int result = FormMgr::GetInstance().StopRenderingForm(formId, compId);
    EXPECT_EQ(result, OHOS::ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrTest_0176 test ends";
}

/**
 * @tc.name: FormMgrTest_0177
 * @tc.desc: Verify ReleaseRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0177, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0177 starts";
    int64_t formId = FORM_ID;
    std::string compId = "this is compId";
    FormMgr::GetInstance().resetFlag_ = true;
    int result = FormMgr::GetInstance().ReleaseRenderer(formId, compId);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0177 test ends";
}

/**
 * @tc.name: FormMgrTest_0178
 * @tc.desc: Verify RequestForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0178, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0178 starts";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormJsInfo formJsInfo;
    formJsInfo.formId = 0x00000008fffffffL;
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().RequestForm(formJsInfo.formId, token, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0178 test ends";
}

/**
 * @tc.name: FormMgrTest_0179
 * @tc.desc: Verify NotifyWhetherVisibleForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0179, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0179 starts";
    std::vector<int64_t> formIds;
    int64_t formId = FORM_ID;
    formIds.emplace_back(formId);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t formVisibleType = 1;
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().NotifyWhetherVisibleForms(formIds, token, formVisibleType);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0179 test ends";
}

/**
 * @tc.name: FormMgrTest_0180
 * @tc.desc: Verify HasFormVisible
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0180, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0180 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    uint32_t tokenId = 0;
    bool result = FormMgr::GetInstance().HasFormVisible(tokenId);
    EXPECT_EQ(result, false);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0180 test ends";
}

/**
 * @tc.name: FormMgrTest_0181
 * @tc.desc: Verify ReleaseForm (Parameters are normal.)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0181, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0181 starts";
    int64_t formId = FORM_ID;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    bool delCache = true;
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().ReleaseForm(formId, token, delCache);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0181 test ends";
}

/**
 * @tc.name: FormMgrTest_0182
 * @tc.desc: Verify CastTempForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0182, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0182 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    int64_t formId = FORM_ID;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = FormMgr::GetInstance().CastTempForm(formId, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0182 test ends";
}

/**
 * @tc.name: FormMgrTest_0183
 * @tc.desc: Verify DumpStorageFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0183, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0183 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    std::string formInfos = "a";
    auto result = FormMgr::GetInstance().DumpStorageFormInfos(formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0183 test ends";
}

/**
 * @tc.name: FormMgrTest_0184
 * @tc.desc: Verify DumpFormInfoByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0184, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0184 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    std::string bundleName = "b";
    std::string formInfos = "a";
    auto result = FormMgr::GetInstance().DumpFormInfoByBundleName(bundleName, formInfos);
    FormMgr::GetInstance().resetFlag_ = false;
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0184 test ends";
}

/**
 * @tc.name: FormMgrTest_0185
 * @tc.desc: Verify DumpFormInfoByFormId
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0185, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0185 starts";
    std::string formInfos = "a";
    FormMgr::GetInstance().resetFlag_ = true;
    auto result = FormMgr::GetInstance().DumpFormInfoByFormId(FORM_ID, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0185 test ends";
}

/**
 * @tc.name: FormMgrTest_0186
 * @tc.desc: Verify DumpFormTimerByFormId
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0186, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0186 starts";
    std::string isTimingService = "b";
    FormMgr::GetInstance().resetFlag_ = true;
    auto result = FormMgr::GetInstance().DumpFormTimerByFormId(FORM_ID, isTimingService);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0186 test ends";
}

/**
 * @tc.name: FormMgrTest_0187
 * @tc.desc: Verify MessageEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0187, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0187 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormJsInfo formJsInfo;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    int32_t result = FormMgr::GetInstance().MessageEvent(formJsInfo.formId, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0187 test ends";
}

/**
 * @tc.name: FormMgrTest_0188
 * @tc.desc: Verify RouterEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0188, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0188 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormJsInfo formJsInfo;
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    int32_t result = FormMgr::GetInstance().RouterEvent(formJsInfo.formId, want, token);
    FormMgr::GetInstance().resetFlag_ = false;
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0188 test ends";
}

/**
 * @tc.name: FormMgrTest_0189
 * @tc.desc: Verify BackgroundEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0189, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0189 starts";
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    Want want;
    std::string bundleName = "a";
    FormMgr::GetInstance().resetFlag_ = true;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().BackgroundEvent(FORM_ID, want, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0189 test ends";
}

/**
 * @tc.name: FormMgrTest_0190
 * @tc.desc: Verify SetNextRefreshTime
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0190, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0190 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    int64_t nextTime = 50;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    auto result = FormMgr::GetInstance().SetNextRefreshTime(FORM_ID, nextTime);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0190 test ends";
}

/**
 * @tc.name: FormMgrTest_0191
 * @tc.desc: Verify SetPublishFormResult
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0191, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0191 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    Constants::PublishFormResult errorCodeInfo{Constants::PublishFormErrorCode::SUCCESS, ""};
    ErrCode result = FormMgr::GetInstance().SetPublishFormResult(FORM_ID, errorCodeInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0191 test ends";
}

/**
 * @tc.name: FormMgrTest_0192
 * @tc.desc: Verify AcquireAddFormResult
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0192, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0192 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    EXPECT_EQ(FormMgr::GetInstance().AcquireAddFormResult(FORM_ID), ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0192 test ends";
}

/**
 * @tc.name: FormMgrTest_0193
 * @tc.desc: Verify LifecycleUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0193, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0193 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    std::vector<int64_t> formIds;
    formIds.emplace_back(FORM_ID);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    bool updateType = true;
    int result = FormMgr::GetInstance().LifecycleUpdate(formIds, token, updateType);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0193 test ends";
}

/**
 * @tc.name: FormMgrTest_0194
 * @tc.desc: Verify OnRemoteDied
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0194, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0194 starts";
    sptr<IRemoteObject> mockFormProviderClient = new (std::nothrow) MockFormProviderClient();
    sptr<FormMgr::FormMgrDeathRecipient> formMgrDeath = new (std::nothrow) FormMgr::FormMgrDeathRecipient();
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    formMgrDeath->OnRemoteDied(mockFormProviderClient);
    EXPECT_TRUE(FormMgr::GetInstance().GetRecoverStatus() == Constants::RECOVER_FAIL);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0194 test ends";
}

/**
 * @tc.name: FormMgrTest_0195
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0195, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0195 starts";
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    bool isProtected = false;
    FormMgr::GetInstance().resetFlag_ = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0195 test ends";
}

/**
 * @tc.name: FormMgrTest_0196
 * @tc.desc: Verify DeleteInvalidForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0196, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0196 starts";
    EXPECT_CALL(*mockProxy, DeleteInvalidForms(_, _, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    std::vector<int64_t> formInfos;
    formInfos.push_back(FORM_ID);
    FormJsInfo formJsInfo;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    FormMgr::GetInstance().resetFlag_ = false;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t numFormsDeleted = 2;
    auto result = FormMgr::GetInstance().DeleteInvalidForms(formInfos, token, numFormsDeleted);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0196 test ends";
}

/**
 * @tc.name: FormMgrTest_0197
 * @tc.desc: Verify AcquireFormState
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0197, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0197 starts";
    EXPECT_CALL(*mockProxy, AcquireFormState(_, _, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormStateInfo stateInfo;
    auto result = FormMgr::GetInstance().AcquireFormState(want, token, stateInfo);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0197 test ends";
}

/**
 * @tc.name: FormMgrTest_0198
 * @tc.desc: Verify DumpStorageFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0198, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0198 starts";
    EXPECT_CALL(*mockProxy, NotifyFormsVisible(_, _, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsVisible(formIds, isProtected, token);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0198 test ends";
}

/**
 * @tc.name: FormMgrTest_0199
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0199, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0199 starts";
    EXPECT_CALL(*mockProxy, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    bool isProtected = false;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, token);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0199 test ends";
}

/**
 * @tc.name: FormMgrTest_0200
 * @tc.desc: Verify NotifyFormsEnableUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0200 starts";
    EXPECT_CALL(*mockProxy, NotifyFormsEnableUpdate(_, _, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsEnableUpdate(formIds, isProtected, token);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0200 test ends";
}

/**
 * @tc.name: FormMgrTest_0201
 * @tc.desc: Verify  GetAllFormsInfo
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0201, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0201 starts";
    EXPECT_CALL(*mockProxy, GetAllFormsInfo(_))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    auto result = FormMgr::GetInstance().GetAllFormsInfo(formInfos);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0201 test ends";
}

/**
 * @tc.name: FormMgrTest_0202
 * @tc.desc: Verify GetFormsInfoByApp
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0202, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0202 starts";
    EXPECT_CALL(*mockProxy, GetFormsInfoByApp(_, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    std::string bundleName = "a";
    auto result = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0202 test ends";
}

/**
 * @tc.name: FormMgrTest_0203
 * @tc.desc: Verify GetFormsInfoByApp
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0203, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0203 starts";
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    FormMgr::GetInstance().resetFlag_ = true;
    expectFormInfos.push_back(formInfo);
    std::string bundleName = "a";
    auto result = FormMgr::GetInstance().GetFormsInfoByApp(bundleName, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0203 test ends";
}

/**
 * @tc.name: FormMgrTest_0204
 * @tc.desc: Verify  GetAllFormsInfo
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0204, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0204 starts";
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    FormMgr::GetInstance().resetFlag_ = true;
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    auto result = FormMgr::GetInstance().GetAllFormsInfo(formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0204 test ends";
}

/**
 * @tc.name: FormMgrTest_0205
 * @tc.desc: Verify NotifyFormsEnableUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0205, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0205 starts";
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    bool isProtected = true;
    FormMgr::GetInstance().resetFlag_ = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsEnableUpdate(formIds, isProtected, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0205 test ends";
}

/**
 * @tc.name: FormMgrTest_0206
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0206, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0206 starts";
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    bool isProtected = false;
    FormMgr::GetInstance().resetFlag_ = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsPrivacyProtected(formIds, isProtected, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0206 test ends";
}

/**
 * @tc.name: FormMgrTest_0207
 * @tc.desc: Verify DumpStorageFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0207, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0207 starts";
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    FormMgr::GetInstance().resetFlag_ = true;
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = FormMgr::GetInstance().NotifyFormsVisible(formIds, isProtected, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0207 test ends";
}

/**
 * @tc.name: FormMgrTest_0208
 * @tc.desc: Verify AcquireFormState
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0208, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0208 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormStateInfo stateInfo;
    auto result = FormMgr::GetInstance().AcquireFormState(want, token, stateInfo);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0208 test ends";
}

/**
 * @tc.name: FormMgrTest_0209
 * @tc.desc: Verify GetFormsInfoByModule
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0209, TestSize.Level1)
{
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormMgr::GetInstance().resetFlag_ = true;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    std::string bundleName = "a";
    std::string moduleName = "A";
    auto result = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0209 test ends";
}

/**
 * @tc.name: FormMgrTest_0210
 * @tc.desc: Verify GetFormsInfoByModule
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0210, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0210 starts";
    EXPECT_CALL(*mockProxy, GetFormsInfoByModule(_, _, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    std::vector<FormInfo> formInfos;
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    formInfo.bundleName = "ohos.samples.FormApplication";
    formInfo.moduleName = "entry";
    expectFormInfos.push_back(formInfo);
    std::string bundleName = "a";
    std::string moduleName = "A";
    auto result = FormMgr::GetInstance().GetFormsInfoByModule(bundleName, moduleName, formInfos);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0210 test ends";
}

/**
 * @tc.name: FormMgrTest_0211
 * @tc.desc: Verify GetFormsInfoByFilter
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0211, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0211 starts";
    FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    FormMgr::GetInstance().resetFlag_ = true;
    auto result = FormMgr::GetInstance().GetFormsInfoByFilter(filter, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0211 test ends";
}

/**
 * @tc.name: FormMgrTest_0212
 * @tc.desc: Verify GetFormsInfoByFilter
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0212, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0212 starts";
    EXPECT_CALL(*mockProxy, GetFormsInfoByFilter(_, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    FormInfoFilter filter;
    std::vector<FormInfo> formInfos;
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    auto result = FormMgr::GetInstance().GetFormsInfoByFilter(filter, formInfos);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0212 test ends";
}

/**
 * @tc.name: FormMgrTest_0213
 * @tc.desc: Verify GetFormsInfo
 * @tc.type: FUNC
 * @tc.require: #I59O23
 */
HWTEST_F(FormMgrTest, FormMgrTest_0213, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0213 starts";
    FormInfoFilter filter;
    FormMgr::GetInstance().resetFlag_ = true;
    std::vector<FormInfo> formInfos;
    auto result = FormMgr::GetInstance().GetFormsInfo(filter, formInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0213 test ends";
}

/**
 * @tc.name: FormMgrTest_0214
 * @tc.desc: Verify IsRequestPublishFormSupported
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0214, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0214 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    bool result = FormMgr::GetInstance().IsRequestPublishFormSupported();
    EXPECT_EQ(result, false);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0214 test ends";
}

/**
 * @tc.name: FormMgrTest_0215
 * @tc.desc: Verify ShareForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0215, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0215 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    std::string deviceId = "aa";
    int64_t requestCode = 1;
    sptr<IRemoteObject> Token = new (std::nothrow) MockFormProviderClient();
    auto result = FormMgr::GetInstance().ShareForm(FORM_ID, deviceId, Token, requestCode);
    EXPECT_EQ(result, OHOS::ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0215 test ends";
}

/**
 * @tc.name: FormMgrTest_0216
 * @tc.desc: Verify AcquireFormData
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0216, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0216 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    int64_t requestCode = 1;
    AAFwk::WantParams formData;
    sptr<IRemoteObject> Token = new (std::nothrow) MockFormProviderClient();
    auto result = FormMgr::GetInstance().AcquireFormData(FORM_ID, requestCode, Token, formData);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0216 test ends";
}

/**
 * @tc.name: FormMgrTest_0217
 * @tc.desc: Verify StartAbility
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0217, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0217 starts";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().resetFlag_ = true;
    int32_t result = FormMgr::GetInstance().StartAbility(want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0217 test ends";
}

/**
 * @tc.name: FormMgrTest_0218
 * @tc.desc: Verify CheckFMSReady
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0218, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0218 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    auto result = FormMgr::GetInstance().CheckFMSReady();
    EXPECT_EQ(result, false);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0218 test ends";
}

/**
 * @tc.name: FormMgrTest_0219
 * @tc.desc: Verify IsSystemAppForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0219, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0219 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    std::string bundle = "bundle";
    bool result = FormMgr::GetInstance().IsSystemAppForm(bundle);
    EXPECT_EQ(result, false);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0219 test ends";
}

/**
 * @tc.name: FormMgrTest_0220
 * @tc.desc: Verify UnregisterPublishFormInterceptor
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0220, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0220 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    sptr<IRemoteObject> interceptorCallback;
    int32_t result = FormMgr::GetInstance().UnregisterPublishFormInterceptor(interceptorCallback);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0220 test ends";
}

/**
 * @tc.name: FormMgrTest_0221
 * @tc.desc: Verify GetRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0221, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0221 starts";
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    FormMgr::GetInstance().resetFlag_ = true;
    std::vector<RunningFormInfo> runningFormInfos;
    bool isUnusedInclude = false;
    int result = FormMgr::GetInstance().GetRunningFormInfos(isUnusedInclude, runningFormInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0221 test ends";
}

/**
 * @tc.name: FormMgrTest_0222
 * @tc.desc: Verify GetRunningFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0222, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0222 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    bool isUnusedInclude = false;
    std::vector<RunningFormInfo> runningFormInfos;
    int result = FormMgr::GetInstance().GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0222 test ends";
}

/**
 * @tc.name: FormMgrTest_0223
 * @tc.desc: Verify RegisterFormAddObserverByBundle
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0223, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0223 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().RegisterFormAddObserverByBundle(bundleName, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0223 test ends";
}

/**
 * @tc.name: FormMgrTest_0224
 * @tc.desc: Verify RegisterFormRemoveObserverByBundle
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0224, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0224 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    int result = FormMgr::GetInstance().RegisterFormRemoveObserverByBundle(bundleName, callerToken);
    FormMgr::GetInstance().resetFlag_ = false;
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0224 test ends";
}

/**
 * @tc.name: FormMgrTest_0225
 * @tc.desc: Verify GetFormsCount
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0225, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0225 starts";
    bool isTempFormFlag = true;
    int32_t formCount = 0;
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetFormsCount(isTempFormFlag, formCount);
    FormMgr::GetInstance().resetFlag_ = false;
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0225 test ends";
}

/**
 * @tc.name: FormMgrTest_0226
 * @tc.desc: Verify GetHostFormsCount
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0226, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0226 starts";
    std::string bundleName = "this is bundleName";
    int32_t formCount = 0;
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int result = FormMgr::GetInstance().GetHostFormsCount(bundleName, formCount);
    FormMgr::GetInstance().resetFlag_ = false;
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0226 test ends";
}

/**
 * @tc.name: FormMgrTest_0227
 * @tc.desc: Verify GetFormInstancesByFilter
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0227, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0227 starts";
    FormInstancesFilter filter;
    std::vector<FormInstance> formInstances;
    FormMgr::GetInstance().resetFlag_ = true;
    ErrCode result = FormMgr::GetInstance().GetFormInstancesByFilter(filter, formInstances);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0227 test ends";
}

/**
 * @tc.name: FormMgrTest_0228
 * @tc.desc: Verify GetFormInstancesByFilter
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0228, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0228 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormInstance formInstance;
    ErrCode result1 = FormMgr::GetInstance().GetFormInstanceById(FORM_ID, formInstance);
    EXPECT_EQ(result1, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0228 test ends";
}

/**
 * @tc.name: FormMgrTest_0229
 * @tc.desc: Verify GetFormInstancesByFilter
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0229, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0229 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormInstance formInstance;
    auto result = FormMgr::GetInstance().GetFormInstanceById(FORM_ID, true, formInstance);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0229 test ends";
}

/**
 * @tc.name: FormMgrTest_0230
 * @tc.desc: Verify RegisterAddObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0230, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0230 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "this is a bundleName";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    ErrCode result = FormMgr::GetInstance().RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0230 test ends";
}

/**
 * @tc.name: FormMgrTest_0231
 * @tc.desc: Verify RegisterRemoveObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0231, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0231 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::string bundleName = "a";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    ErrCode result = FormMgr::GetInstance().RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0231 test ends";
}

/**
 * @tc.name: FormMgrTest_0232
 * @tc.desc: Verify RegisterFormRouterProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0232, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0232 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    ErrCode result = FormMgr::GetInstance().RegisterFormRouterProxy(formIds, callerToken);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0232 test ends";
}

/**
 * @tc.name: FormMgrTest_0233
 * @tc.desc: Verify UnregisterFormRouterProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0233, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0233 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    ErrCode result = FormMgr::GetInstance().UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0233 test ends";
}

/**
 * @tc.name: FormMgrTest_0234
 * @tc.desc: Verify UpdateFormLocation
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0234, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0234 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t formLocation = 1;
    auto result = FormMgr::GetInstance().UpdateFormLocation(FORM_ID, formLocation);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0234 test ends";
}

/**
 * @tc.name: FormMgrTest_0235
 * @tc.desc: Verify UpdateFormLocation
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0235, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0235 starts";
    EXPECT_CALL(*mockProxy, UpdateFormLocation(_, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t formLocation = 1;
    EXPECT_EQ(FormMgr::GetInstance().UpdateFormLocation(FORM_ID, formLocation), ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0235 test ends";
}

/**
 * @tc.name: FormMgrTest_0236
 * @tc.desc: Verify BatchRefreshForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0236, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0236 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t formRefreshType = Constants::REFRESH_ALL_FORM;
    EXPECT_EQ(FormMgr::GetInstance().BatchRefreshForms(formRefreshType), ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0236 test ends";
}

/**
 * @tc.name: FormMgrTest_0237
 * @tc.desc: Verify CreateForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0237, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0237 starts";
    EXPECT_CALL(*mockProxy, CreateForm(_, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    Want want;
    RunningFormInfo runningFormInfo;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    int result = FormMgr::GetInstance().CreateForm(want, runningFormInfo);
    EXPECT_EQ(result, ERR_FAILED);
    FormMgr::GetInstance().resetFlag_ = false;
    GTEST_LOG_(INFO) << "FormMgrTest_0237 test ends";
}

/**
 * @tc.name: FormMgrTest_0238
 * @tc.desc: Verify RequestPublishForm (include data proxies)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0238, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0238 starts";
    FormMgr::GetInstance().resetFlag_ = true;
    Want want;
    int64_t formId = 0x00000008fffffffL;
    std::unique_ptr<FormProviderData> formProviderData;
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("city", "");
    formDataProxies.push_back(formDataProxy);
    int32_t result = FormMgr::GetInstance().RequestPublishForm(want, true, formProviderData, formId, formDataProxies);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0238 test ends";
}

/**
 * @tc.name: FormMgrTest_0239
 * @tc.desc: Verify SetFormsRecyclable
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0239, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0239 test begin";
    FormMgr::GetInstance().resetFlag_ = true;
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0239 test ends";
}

/**
 * @tc.name: FormMgrTest_0240
 * @tc.desc: Verify RecycleForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0240, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0240 begin";
    std::vector<int64_t> formIds;
    FormMgr::GetInstance().resetFlag_ = true;
    formIds.push_back(FORM_ID);
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().RecycleForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0240 test ends";
}

/**
 * @tc.name: FormMgrTest_0241
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0241, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0241 begin";
    FormMgr::GetInstance().resetFlag_ = true;
    std::vector<int64_t> formIds;
    formIds.push_back(FORM_ID);
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0241 test ends";
}

/**
 * @tc.name: FormMgrTest_0242
 * @tc.desc: Verify EnableForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0242, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0242 begin";
    std::string bundleName = "ohos.samples.FormApplication";
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, EnableForms(_, _))
        .Times(1)
        .WillOnce(Return(ERR_FAILED));
    int32_t result = FormMgr::GetInstance().EnableForms(bundleName, true);
    EXPECT_EQ(result, ERR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0242 test ends";
}

/**
 * @tc.name: FormMgrTest_0243
 * @tc.desc: Verify EnableForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0243, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0243 begin";
    FormMgr::GetInstance().resetFlag_ = true;
    std::string bundleName = "ohos.samples.FormApplication";
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().EnableForms(bundleName, true);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0243 test ends";
}

/**
 * @tc.name: FormMgrTest_0244
 * @tc.desc: Verify IsFormBundleForbidden
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0244, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0244 begin";
    FormMgr::GetInstance().resetFlag_ = true;
    std::string bundleName = "ohos.samples.FormApplication";
    bool result = FormMgr::GetInstance().IsFormBundleForbidden(bundleName);
    EXPECT_EQ(result, false);
    FormMgr::GetInstance().resetFlag_ = false;
    FormMgr::GetInstance().SetFormMgrService(mockProxy);
    GTEST_LOG_(INFO) << "FormMgrTest_0244 test ends";
}

/**
 * @tc.name: FormMgrTest_0245
 * @tc.desc: Verify IsFormBundleProtected
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0245, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0245 begin";
    std::string bundleName = "ohos.samples.FormApplication";
    int64_t formId = 1;
    bool result = FormMgr::GetInstance().IsFormBundleProtected(bundleName, formId);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrTest_0245 test ends";
}

/**
 * @tc.name: FormMgrTest_0246
 * @tc.desc: Verify UpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0246, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0246 begin";
    int64_t formId = 1;
    float width = 100;
    float height = 50;
    float borderWidth = 10;
    bool result = FormMgr::GetInstance().UpdateFormSize(formId, width, height, borderWidth);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrTest_0246 test ends";
}

/**
 * @tc.name: FormMgrTest_0247
 * @tc.desc: Verify NotifyFormLocked
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0247, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0247 begin";
    int64_t formId = 1;
    bool isLocked = true;
    int32_t error = FormMgr::GetInstance().NotifyFormLocked(formId, isLocked);
    EXPECT_EQ(error, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);
    GTEST_LOG_(INFO) << "FormMgrTest_0247 test ends";
}

/**
 * @tc.name: FormMgrTest_0248
 * @tc.desc: Verify IsFormBundleExempt
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0248, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0248 begin";
    int64_t formId = 1;
    bool result = FormMgr::GetInstance().IsFormBundleExempt(formId);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrTest_0248 begin";
}

/**
 * @tc.name: FormMgrTest_0249
 * @tc.desc: Verify GetPublishedFormInfoById
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0249, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0249 begin";
    int64_t formId = 1;
    RunningFormInfo runningFormInfo;
    int32_t result = FormMgr::GetInstance().GetPublishedFormInfoById(formId, runningFormInfo);
    HILOG_INFO("FormMgrTest_0249,result: %{public}d", result);
    EXPECT_EQ(result, ERROR_NUMS);
    GTEST_LOG_(INFO) << "FormMgrTest_0249 end";
}

/**
 * @tc.name: FormMgrTest_0250
 * @tc.desc: Verify GetPublishedFormInfoById
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0250, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0250 begin";
    int64_t formId = 2;
    RunningFormInfo runningFormInfo;
    FormMgr::GetInstance().remoteProxy_ = nullptr;
    int32_t result = FormMgr::GetInstance().GetPublishedFormInfoById(formId, runningFormInfo);
    HILOG_INFO("FormMgrTest_0250,result: %{public}d", result);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0250 end";
}

/**
 * @tc.name: FormMgrTest_0251
 * @tc.desc: Verify GetPublishedFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0251, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0251 begin";
    std::vector<RunningFormInfo> runningFormInfos;
    int32_t result = FormMgr::GetInstance().GetPublishedFormInfos(runningFormInfos);
    HILOG_INFO("FormMgrTest_0251,result: %{public}d", result);
    EXPECT_EQ(result, ERROR_NUMS);
    GTEST_LOG_(INFO) << "FormMgrTest_0251 end";
}

/**
 * @tc.name: FormMgrTest_0252
 * @tc.desc: Verify GetPublishedFormInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0252, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0252 begin";
    std::vector<RunningFormInfo> runningFormInfos;
    FormMgr::GetInstance().remoteProxy_ = nullptr;
    int32_t result = FormMgr::GetInstance().GetPublishedFormInfos(runningFormInfos);
    HILOG_INFO("FormMgrTest_0252,result: %{public}d", result);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0252 end";
}

/**
 * @tc.name: FormMgrTest_0253
 * @tc.desc: Verify OpenFormEditAbility
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0253, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0253 begin";
    std::string abilityName = "";
    int64_t formId = 1;
    bool isMainPage = true;
    ErrCode result = FormMgr::GetInstance().OpenFormEditAbility(abilityName, formId, isMainPage);
    HILOG_INFO("FormMgrTest_0253,result: %{public}d", result);
    EXPECT_EQ(result, ERROR_NUMS);
    GTEST_LOG_(INFO) << "FormMgrTest_0253 end";
}

/**
 * @tc.name: FormMgrTest_0254
 * @tc.desc: Verify OpenFormEditAbility
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0254, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0254 begin";
    std::string abilityName = "123";
    int64_t formId = 2;
    bool isMainPage = true;
    FormMgr::GetInstance().remoteProxy_ = nullptr;
    ErrCode result = FormMgr::GetInstance().OpenFormEditAbility(abilityName, formId, isMainPage);
    HILOG_INFO("FormMgrTest_0254,result: %{public}d", result);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0254 end";
}

/**
 * @tc.name: FormMgrTest_0255
 * @tc.desc: Verify OpenFormEditAbility
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0255, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0255 begin";
    std::string abilityName = "456";
    int64_t formId = 2;
    bool isMainPage = false;
    FormMgr::GetInstance().remoteProxy_ = nullptr;
    ErrCode result = FormMgr::GetInstance().OpenFormEditAbility(abilityName, formId, isMainPage);
    HILOG_INFO("FormMgrTest_0255,result: %{public}d", result);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0255 end";
}

/**
 * @tc.name: FormMgrTest_0256
 * @tc.desc: Verify requestOverflow
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0256, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0256 starts";
    EXPECT_CALL(*mockProxy, RequestOverflow(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    OverflowInfo overflowInfo;
    overflowInfo.duration = 3500;
    overflowInfo.area.left = -30;
    overflowInfo.area.top = -30;
    overflowInfo.area.width = 300;
    overflowInfo.area.height = 300;
    bool isOverflow = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    ErrCode result = FormMgr::GetInstance().RequestOverflow(formJsInfo.formId, overflowInfo, isOverflow);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0256 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0257
 * @tc.desc: Verify requestOverflow
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0257, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0257 starts";
    int64_t formId = -1;
    OverflowInfo overflowInfo;
    bool isOverflow = true;
    ErrCode result = FormMgr::GetInstance().RequestOverflow(formId, overflowInfo, isOverflow);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0257 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0258
 * @tc.desc: Verify requestOverflow
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0258, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0258 starts";
    int64_t formId = 1;
    OverflowInfo overflowInfo;
    overflowInfo.duration = -1;
    bool isOverflow = true;
    ErrCode result = FormMgr::GetInstance().RequestOverflow(formId, overflowInfo, isOverflow);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrTest_0258 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0259
 * @tc.desc: Verify requestOverflow
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0259, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0259 begin";
    int64_t formId = 1;
    OverflowInfo overflowInfo;
    overflowInfo.area.left = -30;
    overflowInfo.area.top = -30;
    overflowInfo.area.width = 200;
    overflowInfo.area.height = 200;
    overflowInfo.duration = 3500;
    bool isOverflow = true;
    FormMgr::GetInstance().remoteProxy_ = nullptr;
    ErrCode result = FormMgr::GetInstance().RequestOverflow(formId, overflowInfo, isOverflow);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0259 end";
}
 
/**
 * @tc.name: FormMgrTest_0260
 * @tc.desc: Verify ChangeSceneAnimationState
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0260, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0260 starts";
    EXPECT_CALL(*mockProxy, ChangeSceneAnimationState(_, _))
        .Times(1)
        .WillOnce(Return(0));
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    int32_t state = 1;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    ErrCode result = FormMgr::GetInstance().ChangeSceneAnimationState(formJsInfo.formId, state);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0260 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0261
 * @tc.desc: Verify ChangeSceneAnimationState
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0261, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0261 starts";
    int64_t formId = -1;
    int32_t state = 1;
    ErrCode result = FormMgr::GetInstance().ChangeSceneAnimationState(formId, state);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0261 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0262
 * @tc.desc: Verify ChangeSceneAnimationState
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0262, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0262 begin";
    int64_t formId = 1;
    int32_t state = 1;
    FormMgr::GetInstance().remoteProxy_ = nullptr;
    ErrCode result = FormMgr::GetInstance().ChangeSceneAnimationState(formId, state);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_COMMON_CODE);
    GTEST_LOG_(INFO) << "FormMgrTest_0262 end";
}

/**
 * @tc.name: FormMgrTest_0263
 * @tc.desc: Verify StartAbilityByCrossBundle
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0263, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0263 begin";
    Want want;
    ErrCode result = FormMgr::GetInstance().StartAbilityByCrossBundle(want);
    HILOG_INFO("FormMgrTest_0263,result: %{public}d", result);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED);
    GTEST_LOG_(INFO) << "FormMgrTest_0263 end";
}

/**
 * @tc.name: FormMgrTest_0272
 * @tc.desc: Verify getFormRect
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0272, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0272 starts";
    EXPECT_CALL(*mockProxy, GetFormRect(_, _))
        .Times(1)
        .WillOnce(Return(0));
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1;
    Rect rect;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    sptr<IRemoteObject> providerToken = new (std::nothrow) MockFormProviderClient();
    FormCallerMgr::GetInstance().AddFormHostCaller(formJsInfo, providerToken);
    ErrCode result = FormMgr::GetInstance().GetFormRect(formJsInfo.formId, rect);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrTest_0272 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0273
 * @tc.desc: Verify getFormRect
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0273, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0273 starts";
    int64_t formId = -1;
    Rect rect;
    ErrCode result = FormMgr::GetInstance().GetFormRect(formId, rect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0273 test ends";
}

/**
 * @tc.name: FormMgrTest_0275
 * @tc.desc: Verify RegisterGetFormRectProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0275, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0275 starts";
    EXPECT_CALL(*mockProxy, RegisterGetFormRectProxy(_))
        .Times(1)
        .WillOnce(Return(true));
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    bool result = FormMgr::GetInstance().RegisterGetFormRectProxy(callerToken);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrTest_0275 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0276
 * @tc.desc: Verify RegisterGetFormRectProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0276, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0276 starts";
    EXPECT_CALL(*mockProxy, RegisterGetFormRectProxy(_))
        .Times(1)
        .WillOnce(Return(false));
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    bool result = FormMgr::GetInstance().RegisterGetFormRectProxy(callerToken);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrTest_0276 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0277
 * @tc.desc: Verify UnregisterGetFormRectProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0277, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0277 starts";
    EXPECT_CALL(*mockProxy, UnregisterGetFormRectProxy())
        .Times(1)
        .WillOnce(Return(true));
    bool result = FormMgr::GetInstance().UnregisterGetFormRectProxy();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrTest_0277 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0278
 * @tc.desc: Verify UnregisterGetFormRectProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0278, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0278 starts";
    EXPECT_CALL(*mockProxy, UnregisterGetFormRectProxy())
        .Times(1)
        .WillOnce(Return(false));
    bool result = FormMgr::GetInstance().UnregisterGetFormRectProxy();
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrTest_0278 test ends";
}

/**
 * @tc.name: FormMgrTest_0279
 * @tc.desc: Verify RegisterGetLiveFormStatusProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0279, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0279 starts";
    EXPECT_CALL(*mockProxy, RegisterGetLiveFormStatusProxy(_))
        .Times(1)
        .WillOnce(Return(true));
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    bool result = FormMgr::GetInstance().RegisterGetLiveFormStatusProxy(callerToken);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrTest_0279 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0280
 * @tc.desc: Verify RegisterGetLiveFormStatusProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0280, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0280 starts";
    EXPECT_CALL(*mockProxy, RegisterGetLiveFormStatusProxy(_))
        .Times(1)
        .WillOnce(Return(false));
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    bool result = FormMgr::GetInstance().RegisterGetLiveFormStatusProxy(callerToken);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrTest_0280 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0281
 * @tc.desc: Verify UnregisterGetLiveFormStatusProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0281, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0281 starts";
    EXPECT_CALL(*mockProxy, UnregisterGetLiveFormStatusProxy())
        .Times(1)
        .WillOnce(Return(true));
    bool result = FormMgr::GetInstance().UnregisterGetLiveFormStatusProxy();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrTest_0281 test ends";
}
 
/**
 * @tc.name: FormMgrTest_0282
 * @tc.desc: Verify UnregisterGetLiveFormStatusProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0282, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0282 starts";
    EXPECT_CALL(*mockProxy, UnregisterGetLiveFormStatusProxy())
        .Times(1)
        .WillOnce(Return(false));
    bool result = FormMgr::GetInstance().UnregisterGetLiveFormStatusProxy();
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrTest_0282 test ends";
}

/**
 * @tc.name: FormMgrTest_0283
 * @tc.desc: Verify UpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0283, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0283 starts";
    int64_t formId = -1;
    int32_t newDimension = 1;
    Rect rect;
    ErrCode result = FormMgr::GetInstance().UpdateFormSize(formId, newDimension, rect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_NOT_EXIST_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0283 test ends";
}

/**
 * @tc.name: FormMgrTest_0284
 * @tc.desc: Verify UpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0284, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0284 begin";
    int64_t formId = 1;
    int32_t newDimension = 1;
    Rect rect;
    ErrCode result = FormMgr::GetInstance().UpdateFormSize(formId, newDimension, rect);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SEND_FMS_MSG);
    GTEST_LOG_(INFO) << "FormMgrTest_0284 end";
}

/**
 * @tc.name: FormMgrTest_0285
 * @tc.desc: Verify IsFormBundleDebugSignature
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0285, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormMgrTest_0285 begin";
    std::string bundleName = "ohos.samples.FormApplicationTest";
    ErrCode result = FormMgr::GetInstance().IsFormBundleDebugSignature(bundleName);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrTest_0285 end";
}
} // namespace
