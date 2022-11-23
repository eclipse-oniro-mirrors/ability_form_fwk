/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#undef private
#undef protected
#include "form_mgr_errors.h"
#include "mock_form_provider_client.h"
#include "gmock/gmock.h"
#include "mock_form_mgr_proxy.h"
#include "mock_form_token.h"


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
class FormMgrTest : public testing::Test {
public:
    // TestSuite setup has to be static
    static void SetUpTestCase()
    {
        if (mockProxy == nullptr) {
            GTEST_LOG_(INFO) << "SetUpTestCase";
            sptr<IRemoteObject> impl = nullptr;
            mockProxy = new (std::nothrow) MockFormMgrProxy(impl);
            FormMgr::GetInstance().SetFormMgrService(mockProxy);
        }
    }
    // TearDown is unnecessary.
    // TestSuite setup has to be static
    static sptr<MockFormMgrProxy> mockProxy;
};
// initialize static variable.
sptr<MockFormMgrProxy> FormMgrTest::mockProxy = nullptr;

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
    EXPECT_CALL(*mockProxy, RequestForm(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
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
    EXPECT_CALL(*mockProxy, MessageEvent(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
 */
HWTEST_F(FormMgrTest, FormMgrTest_0017, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0017 starts";
    int64_t formId = 1;
    int64_t nextTime = 2;
    auto result = FormMgr::GetInstance().SetNextRefreshTime(formId, nextTime);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_REFRESH_TIME);
    GTEST_LOG_(INFO) << "FormMgrTest_0017 test ends";
}

/**
 * @tc.name: FormMgrTest_0018
 * @tc.desc: Verify GetErrorMessage
 * @tc.type: FUNC
 * @tc.require: I5ST27
 */
HWTEST_F(FormMgrTest, FormMgrTest_0018, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0018 starts";
    FormErrors::GetInstance().InitErrorMessageMap();
    int errCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    auto result = FormMgr::GetInstance().GetErrorMessage(errCode);

    EXPECT_EQ(result, "check permission deny, need to request ohos.permission.REQUIRE_FORM.");
    GTEST_LOG_(INFO) << "FormMgrTest_0018 test ends";
}

/**
 * @tc.name: FormMgrTest_0019
 * @tc.desc: Verify DeleteInvalidForms
 * @tc.type: FUNC
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
 */
HWTEST_F(FormMgrTest, FormMgrTest_0025, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0025 starts";
    auto result = FormMgr::GetInstance().CheckFMSReady();

    EXPECT_TRUE(result);
    GTEST_LOG_(INFO) << "FormMgrTest_0025 test ends";
}

/**
 * @tc.name: FormMgrTest_0026
 * @tc.desc: Verify DumpFormInfoByBundleName
 * @tc.type: FUNC
 * @tc.require: I5ST27
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
 * @tc.require: I5ST27
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

} // namespace