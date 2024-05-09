/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_REFRESH_TIME);
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
        .Times(2)
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
    EXPECT_CALL(*mockProxy, CastTempForm(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
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
    EXPECT_CALL(*mockProxy, DeleteInvalidForms(_, _, _))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
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
    EXPECT_CALL(*mockProxy, AcquireFormState(_, _, _))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
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
    EXPECT_CALL(*mockProxy, NotifyFormsVisible(_, _, _))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
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
    EXPECT_CALL(*mockProxy, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
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
    EXPECT_CALL(*mockProxy, NotifyFormsEnableUpdate(_, _, _))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
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
    EXPECT_CALL(*mockProxy, GetAllFormsInfo(_))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
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
    EXPECT_CALL(*mockProxy, GetFormsInfoByApp(_, _))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
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
    EXPECT_CALL(*mockProxy, GetFormsInfoByModule(_, _, _))
        .Times(1)
        .WillOnce(Return(POSITIVE_NUM));
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
    EXPECT_CALL(*mockProxy, GetRunningFormInfos(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
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
    EXPECT_CALL(*mockProxy, GetRunningFormInfosByBundleName(_, _, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
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
    EXPECT_CALL(*mockProxy, RegisterFormAddObserverByBundle(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
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
    EXPECT_CALL(*mockProxy, RegisterFormRemoveObserverByBundle(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
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
    EXPECT_CALL(*mockProxy, RegisterAddObserver(_, _))
        .Times(1)
        .WillOnce(Return(ERROR_NUMS));
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
    EXPECT_CALL(*mockProxy, RegisterRemoveObserver(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
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
    EXPECT_CALL(*mockProxy, RegisterFormRouterProxy(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
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
    EXPECT_CALL(*mockProxy, UnregisterFormRouterProxy(_))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
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
    EXPECT_CALL(*mockProxy, UpdateFormLocation(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
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
 * @tc.name: FormMgrTest_RegisterClickEventObserver_001
 * @tc.desc: Verify RegisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_RegisterClickEventObserver_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_RegisterClickEventObserver_001 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    sptr<IRemoteObject> observer = nullptr;
    int result = FormMgr::GetInstance().RegisterClickEventObserver(bundleName, formEventType, observer);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrTest_RegisterClickEventObserver_001 end";
}

/**
 * @tc.name: FormMgrTest_RegisterClickEventObserver_002
 * @tc.desc: Verify RegisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_RegisterClickEventObserver_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_RegisterClickEventObserver_002 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().RegisterClickEventObserver(bundleName, formEventType, iremoteObject);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_RegisterClickEventObserver_002 end";
}

/**
 * @tc.name: FormMgrTest_RegisterClickEventObserver_003
 * @tc.desc: Verify RegisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_RegisterClickEventObserver_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_RegisterClickEventObserver_003 begin";
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
    GTEST_LOG_(INFO) << "FormMgrTest_RegisterClickEventObserver_003 end";
}

/**
 * @tc.name: FormMgrTest_UnregisterClickEventObserver_001
 * @tc.desc: Verify UnregisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_UnregisterClickEventObserver_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_UnregisterClickEventObserver_001 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    sptr<IRemoteObject> observer = nullptr;
    int result = FormMgr::GetInstance().UnregisterClickEventObserver(bundleName, formEventType, observer);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormMgrTest_UnregisterClickEventObserver_001 end";
}

/**
 * @tc.name: FormMgrTest_UnregisterClickEventObserver_002
 * @tc.desc: Verify UnregisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_UnregisterClickEventObserver_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_UnregisterClickEventObserver_002 begin";
    std::string bundleName = "";
    std::string formEventType = "formAdd";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int result = FormMgr::GetInstance().UnregisterClickEventObserver(bundleName, formEventType, iremoteObject);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "FormMgrTest_UnregisterClickEventObserver_002 end";
}

/**
 * @tc.name: FormMgrTest_UnregisterClickEventObserver_003
 * @tc.desc: Verify UnregisterClickEventObserver
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_UnregisterClickEventObserver_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormMgrTest_UnregisterClickEventObserver_003 begin";
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
    GTEST_LOG_(INFO) << "FormMgrTest_UnregisterClickEventObserver_003 end";
}

/**
 * @tc.name: SetFormsRecyclable_001
 * @tc.desc: Verify SetFormsRecyclable
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, SetFormsRecyclable_001, TestSize.Level0) {
    GTEST_LOG_(INFO) << "SetFormsRecyclable_001 test begin";
    std::vector<int64_t> formIds;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int32_t result = FormMgr::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "SetFormsRecyclable_001 test ends";
}

/**
 * @tc.name: SetFormsRecyclable_002
 * @tc.desc: Verify SetFormsRecyclable
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, SetFormsRecyclable_002, TestSize.Level0) {
    GTEST_LOG_(INFO) << "SetFormsRecyclable_002 test begin";
    std::vector<int64_t> formIds;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().SetFormsRecyclable(formIds);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "SetFormsRecyclable_002 test ends";
}

/**
 * @tc.name: SetFormsRecyclable_003
 * @tc.desc: Verify SetFormsRecyclable
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, SetFormsRecyclable_003, TestSize.Level0) {
    GTEST_LOG_(INFO) << "SetFormsRecyclable_003 test begin";
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
    GTEST_LOG_(INFO) << "SetFormsRecyclable_003 test ends";
}

/**
 * @tc.name: RecycleForms_001
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, RecycleForms_001, TestSize.Level0) {
    GTEST_LOG_(INFO) << "RecycleForms_001 begin";
    std::vector<int64_t> formIds;
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int32_t result = FormMgr::GetInstance().RecycleForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "RecycleForms_001 test ends";
}

/**
 * @tc.name: RecoverForms_002
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, RecycleForms_002, TestSize.Level0) {
    GTEST_LOG_(INFO) << "RecycleForms_002 begin";
    std::vector<int64_t> formIds;
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().RecycleForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "RecycleForms_002 test ends";
}

/**
 * @tc.name: RecycleForms_003
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, RecycleForms_003, TestSize.Level0) {
    GTEST_LOG_(INFO) << "RecycleForms_003 begin";
    std::vector<int64_t> formIds;
    int64_t formId1 = 1;
    formIds.push_back(formId1);
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    EXPECT_CALL(*mockProxy, RecoverForms(_, _))
    .Times(1)
    .WillOnce(Return(OHOS::ERR_OK));
    int32_t result = FormMgr::GetInstance().RecycleForms(formIds, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "RecycleForms_003 test ends";
}

/**
 * @tc.name: RecoverForms_001
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, RecoverForms_001, TestSize.Level0) {
    GTEST_LOG_(INFO) << "RecoverForms_001 begin";
    std::vector<int64_t> formIds;
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int32_t result = FormMgr::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR);
    GTEST_LOG_(INFO) << "RecoverForms_001 test ends";
}

/**
 * @tc.name: RecoverForms_002
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, RecoverForms_002, TestSize.Level0) {
    GTEST_LOG_(INFO) << "RecoverForms_002 begin";
    std::vector<int64_t> formIds;
    Want want;
    FormMgr::GetInstance().SetRecoverStatus(Constants::NOT_IN_RECOVERY);
    int32_t result = FormMgr::GetInstance().RecoverForms(formIds, want);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "RecoverForms_002 test ends";
}

/**
 * @tc.name: RecoverForms_003
 * @tc.desc: Verify RecoverForms
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, RecoverForms_003, TestSize.Level0) {
    GTEST_LOG_(INFO) << "RecoverForms_003 begin";
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
    GTEST_LOG_(INFO) << "RecoverForms_003 test ends";
}

/**
 * @tc.name: FormMgrTest_0125
 * @tc.desc: Verify SetPublishFormResult (The return value of mock function is not 0)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0125, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0125 starts";
    EXPECT_CALL(*mockProxy, SetPublishFormResult(_, _))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int64_t formId = 0;
    Constants::PublishFormResult result {Constants::PublishFormErrorCode::SUCCESS, ""};
    EXPECT_EQ(FormMgr::GetInstance().SetPublishFormResult(formId, result), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0125 test ends";
}

/**
 * @tc.name: FormMgrTest_0126
 * @tc.desc: Verify AcquireAddFormResult (The return value of mock function is not 0)
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrTest, FormMgrTest_0126, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0126 starts";
    EXPECT_CALL(*mockProxy, AcquireAddFormResult(_))
        .Times(1)
        .WillOnce(Return(OHOS::ERR_OK));
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    FormMgr::GetInstance().SetRecoverStatus(Constants::IN_RECOVERING);
    int64_t formId = 0;
    EXPECT_EQ(FormMgr::GetInstance().AcquireAddFormResult(formId), ERR_APPEXECFWK_FORM_INVALID_FORM_ID);
    GTEST_LOG_(INFO) << "FormMgrTest_0126 test ends";
}
} // namespace
