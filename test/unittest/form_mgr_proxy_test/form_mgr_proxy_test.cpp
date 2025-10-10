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

#include "appexecfwk_errors.h"
#include "form_mgr_proxy.h"
#include "gmock/gmock.h"
#include "mock_form_mgr_service.h"
#include "mock_form_token.h"
#include "form_provider_proxy.h"
#include "form_mgr_errors.h"
#include "form_mgr_proxy.h"

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
class FormMgrProxyTest : public testing::Test {
public:
    void SetUp() override
    {
        mockFormMgrService = new MockFormMgrService();
        formMgrProxy = new FormMgrProxy(mockFormMgrService);
        formProviderProxy = new FormProviderProxy(mockFormMgrService);
    }
    // TearDown() is unnecessary.
    sptr<MockFormMgrService> mockFormMgrService;
    sptr<FormMgrProxy> formMgrProxy;
    sptr<FormProviderProxy> formProviderProxy;
};

/**
 * @tc.name: FormMgrProxyTest_0001
 * @tc.desc: Verify GetFormsInfo
 * @tc.type: FUNC
 * @tc.require: #I59O23
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_001 starts";
    // initialize input parameters.
    FormInfoFilter filter;
    filter.moduleName = "";
    std::vector<FormInfo> formInfos;
    // setup expectations.
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    expectFormInfos.push_back(formInfo);
    EXPECT_CALL(*mockFormMgrService, GetFormsInfo(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(expectFormInfos), Return(ERR_OK)));
    // test.
    formMgrProxy->GetFormsInfo(filter, formInfos);
    // expect result.
    EXPECT_THAT(formInfos, ContainerEq(expectFormInfos));
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0001 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0002
 * @tc.desc: Verify GetFormsInfo
 * @tc.type: FUNC
 * @tc.require: #I59O23
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0002 starts";
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
    EXPECT_CALL(*mockFormMgrService, GetFormsInfo(_, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));
    // test.
    formMgrProxy->GetFormsInfo(filter, formInfos);
    // expect result.
    EXPECT_EQ(formInfos.size(), 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0002 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0003
 * @tc.desc: Verify IsRequestPublishFormSupported
 * @tc.type: FUNC
 * @tc.require: #I58Y0A
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0003 starts";
    // initialize input parameters.
    EXPECT_CALL(*mockFormMgrService, IsRequestPublishFormSupported())
        .Times(1)
        .WillOnce(Return(true));
    // test.
    bool result = formMgrProxy->IsRequestPublishFormSupported();
    // expect result.
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0003 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0004
 * @tc.desc: Verify StartAbility
 * @tc.type: FUNC
 * @tc.require: #I5EFDX
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0004 starts";
    // initialize input parameters.
    EXPECT_CALL(*mockFormMgrService, StartAbility(_, _))
        .Times(1)
        .WillOnce(Return(0));
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = formMgrProxy->StartAbility(want, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0004 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0005
 * @tc.desc: Verify StartAbility
 * @tc.type: FUNC
 * @tc.require: #I5EFDX
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0005, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0005 starts";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int32_t result = formMgrProxy->StartAbility(want, nullptr);
    // expect result.
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0005 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0006
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0006, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0006 starts";
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // initialize input parameters.
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    bool isProtected = false;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = formMgrProxy->NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0006 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0007
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0007, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0007 starts";
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // initialize input parameters.
    int64_t formId = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = formMgrProxy->NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0007 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0008
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0008, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0008 starts";
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
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
    int32_t result = formMgrProxy->NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0008 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0009
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0009, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0009 starts";
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
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
    int32_t result = formMgrProxy->NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0009 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0010
 * @tc.desc: text GetRunningFormInfos function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0010, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0010 starts";
    bool isUnusedInclude = false;
    std::vector<RunningFormInfo> runningFormInfos;
    int result = formMgrProxy->GetRunningFormInfos(isUnusedInclude, runningFormInfos);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0010 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0011
 * @tc.desc: text GetRunningFormInfosByBundleName function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0011, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0011 starts";
    std::vector<RunningFormInfo> runningFormInfos;
    std::string bundleName = "ohos.samples.FormApplication";
    bool isUnusedInclude = false;
    int result = formMgrProxy->GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0011 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0012
 * @tc.desc: text RegisterFormAddObserverByBundle function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0012, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0012 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    int result = formMgrProxy->RegisterFormAddObserverByBundle(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0012 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0013
 * @tc.desc: text RegisterFormAddObserverByBundle function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0013, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0013 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    int result = formMgrProxy->RegisterFormAddObserverByBundle(bundleName, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0013 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0014
 * @tc.desc: text RegisterFormRemoveObserverByBundle function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0014, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0012 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    int result = formMgrProxy->RegisterFormRemoveObserverByBundle(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0014 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0015
 * @tc.desc: text RegisterFormRemoveObserverByBundle function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0015, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0015 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    int result = formMgrProxy->RegisterFormRemoveObserverByBundle(bundleName, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0015 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0016
 * @tc.desc: text RegisterFormRouterProxy function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0016, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0016 starts";
    int64_t formId = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formMgrProxy->RegisterFormRouterProxy(formIds, token);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0016 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0017
 * @tc.desc: text RegisterFormRouterProxy function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0017, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0016 starts";
    int64_t formId = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    int result = formMgrProxy->RegisterFormRouterProxy(formIds, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0016 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0018
 * @tc.desc: text UnregisterFormRouterProxy function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0018, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0018 starts";
    int64_t formId = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    int result = formMgrProxy->UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0018 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0019
 * @tc.desc: text StartAbilityByFms function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0019, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0019 starts";
    Want want;
    auto result = formMgrProxy->StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0019 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0020
 * @tc.desc: text RegisterAddObserver function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0020, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0020 starts";
    std::string bundleName = "bundleName";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    auto result = formMgrProxy->RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0020 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0021
 * @tc.desc: text RegisterRemoveObserver function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0021, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0021 starts";
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    auto result = formMgrProxy->RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0021 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0022
 * @tc.desc: text LockForms function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0022, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0022 starts";
    std::vector<FormLockInfo> formLockInfos;
    LockChangeType type = LockChangeType::SWITCH_CHANGE;
    auto result = formMgrProxy->LockForms(formLockInfos, type);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0022 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0023
 * @tc.desc: text NotifyFormLocked function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0023, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0023 starts";
    int64_t formId = 1;
    bool isLocked = true;
    auto result = formMgrProxy->NotifyFormLocked(formId, isLocked);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0023 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0024
 * @tc.desc: text GetRunningFormInfosByBundleName function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0024, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0024 starts";
    std::vector<RunningFormInfo> runningFormInfos;
    std::string bundleName = "ohos.samples.FormApplication";
    bool isUnusedInclude = false;
    int result = formMgrProxy->GetRunningFormInfosByBundleName(bundleName, isUnusedInclude, runningFormInfos);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0024 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0025
 * @tc.desc: text RegisterFormAddObserverByBundle function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0025, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0025 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    int result = formMgrProxy->RegisterFormAddObserverByBundle(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0025 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0026
 * @tc.desc: text RegisterFormAddObserverByBundle function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0026, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0026 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    int result = formMgrProxy->RegisterFormAddObserverByBundle(bundleName, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0026 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0027
 * @tc.desc: text RegisterFormRemoveObserverByBundle function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0027, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0027 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    int result = formMgrProxy->RegisterFormRemoveObserverByBundle(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0027 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0028
 * @tc.desc: text RegisterFormRemoveObserverByBundle function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0028, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0028 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    int result = formMgrProxy->RegisterFormRemoveObserverByBundle(bundleName, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0028 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0029
 * @tc.desc: text RegisterFormRouterProxy function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0029, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0029 starts";
    int64_t formId = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formMgrProxy->RegisterFormRouterProxy(formIds, token);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0029 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0030
 * @tc.desc: text RegisterFormRouterProxy function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0030, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0030 starts";
    int64_t formId = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    int result = formMgrProxy->RegisterFormRouterProxy(formIds, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0030 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0031
 * @tc.desc: text UnregisterFormRouterProxy function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0031, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0031 starts";
    int64_t formId = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    int result = formMgrProxy->UnregisterFormRouterProxy(formIds);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0031 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0032
 * @tc.desc: text StartAbilityByFms function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0032, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0032 starts";
    Want want;
    auto result = formMgrProxy->StartAbilityByFms(want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0032 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0033
 * @tc.desc: text RegisterAddObserver function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0033, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0033 starts";
    std::string bundleName = "bundleName";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    auto result = formMgrProxy->RegisterAddObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0033 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0034
 * @tc.desc: text RegisterRemoveObserver function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0034, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0034 starts";
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    auto result = formMgrProxy->RegisterRemoveObserver(bundleName, callerToken);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0034 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0035
 * @tc.desc: text LockForms function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0035, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0035 starts";
    std::vector<FormLockInfo> formLockInfos;
    LockChangeType type = LockChangeType::SWITCH_CHANGE;
    auto result = formMgrProxy->LockForms(formLockInfos, type);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0035 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0036
 * @tc.desc: text NotifyFormLocked function.
 * @tc.type: FUNC
 * @tc.require: IssueI8H9R5
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0036, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0036 starts";
    int64_t formId = 1;
    bool isLocked = true;
    auto result = formMgrProxy->NotifyFormLocked(formId, isLocked);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0036 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0037
 * @tc.desc: Verify GetFormsInfo
 * @tc.type: FUNC
 * @tc.require: #I59O23
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0037, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0037 starts";
    // initialize input parameters.
    FormInfoFilter filter;
    filter.moduleName = "";
    std::vector<FormInfo> formInfos;
    // setup expectations.
    std::vector<FormInfo> expectFormInfos;
    FormInfo formInfo = {};
    formInfo.bundleName = "ohos.samples.FormApplication";
    expectFormInfos.push_back(formInfo);
    EXPECT_CALL(*mockFormMgrService, GetFormsInfo(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(expectFormInfos), Return(ERR_OK)));
    // test.
    formMgrProxy->GetFormsInfo(filter, formInfos);
    // expect result.
    EXPECT_THAT(formInfos, ContainerEq(expectFormInfos));
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0037 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0038
 * @tc.desc: Verify GetFormsInfo
 * @tc.type: FUNC
 * @tc.require: #I59O23
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0038, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0038 starts";
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
    EXPECT_CALL(*mockFormMgrService, GetFormsInfo(_, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));
    // test.
    formMgrProxy->GetFormsInfo(filter, formInfos);
    // expect result.
    EXPECT_EQ(formInfos.size(), 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0038 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0039
 * @tc.desc: Verify IsRequestPublishFormSupported
 * @tc.type: FUNC
 * @tc.require: #I58Y0A
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0039, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0039 starts";
    // initialize input parameters.
    EXPECT_CALL(*mockFormMgrService, IsRequestPublishFormSupported())
        .Times(1)
        .WillOnce(Return(true));
    // test.
    bool result = formMgrProxy->IsRequestPublishFormSupported();
    // expect result.
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0039 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0040
 * @tc.desc: Verify StartAbility
 * @tc.type: FUNC
 * @tc.require: #I5EFDX
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0040, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0040 starts";
    // initialize input parameters.
    EXPECT_CALL(*mockFormMgrService, StartAbility(_, _))
        .Times(1)
        .WillOnce(Return(0));
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = formMgrProxy->StartAbility(want, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0040 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0041
 * @tc.desc: Verify StartAbility
 * @tc.type: FUNC
 * @tc.require: #I5EFDX
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0041, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0041 starts";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int32_t result = formMgrProxy->StartAbility(want, nullptr);
    // expect result.
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0041 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0042
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0042, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0042 starts";
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // initialize input parameters.
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    bool isProtected = false;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = formMgrProxy->NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0042 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0043
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0043, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0043 starts";
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // initialize input parameters.
    int64_t formId = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId);
    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int32_t result = formMgrProxy->NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0043 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0044
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0044, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0044 starts";
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
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
    int32_t result = formMgrProxy->NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0044 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0045
 * @tc.desc: Verify NotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0045, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0045 starts";
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
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
    int32_t result = formMgrProxy->NotifyFormsPrivacyProtected(formIds, isProtected, token);
    // expect result.
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0045 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0046
 * @tc.desc: text GetRunningFormInfos function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0046, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0046 starts";
    bool isUnusedInclude = false;
    std::vector<RunningFormInfo> runningFormInfos;
    int result = formMgrProxy->GetRunningFormInfos(isUnusedInclude, runningFormInfos);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0046 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0001
 * @tc.desc: text AcquireProviderFormInfo function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0001 starts";
    FormJsInfo formJsInfo;
    formJsInfo.formId = 1001L;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->AcquireProviderFormInfo(formJsInfo, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0001 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0002
 * @tc.desc: text AcquireProviderFormInfo function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0002 starts";
    FormJsInfo formJsInfo;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->AcquireProviderFormInfo(formJsInfo, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0002 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0003
 * @tc.desc: text NotifyFormDelete function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0003 starts";
    int64_t formId = 1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->NotifyFormDelete(formId, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0003 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0004
 * @tc.desc: text NotifyFormDelete function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0004 starts";
    int64_t formId = 1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->NotifyFormDelete(formId, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0004 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0005
 * @tc.desc: text NotifyFormsDelete function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0005, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0005 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->NotifyFormsDelete(formIds, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0005 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0006
 * @tc.desc: text NotifyFormsDelete function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0006, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0006 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->NotifyFormsDelete(formIds, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0006 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0007
 * @tc.desc: text NotifyFormUpdate function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0007, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0007 starts";
    int64_t formId = 1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->NotifyFormUpdate(formId, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0007 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0008
 * @tc.desc: text NotifyFormUpdate function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0008, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0008 starts";
    int64_t formId = 1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->NotifyFormUpdate(formId, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0008 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0009
 * @tc.desc: text EventNotify function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0009, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0009 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    int32_t formVisibleType = 2;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->EventNotify(formIds, formVisibleType, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0009 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0010
 * @tc.desc: text EventNotify function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0010, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0010 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    int32_t formVisibleType = 2;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->EventNotify(formIds, formVisibleType, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0010 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0011
 * @tc.desc: text NotifyFormCastTempForm function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0011, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0011 starts";
    int64_t formId = 1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->NotifyFormCastTempForm(formId, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0011 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0012
 * @tc.desc: text NotifyFormCastTempForm function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0012, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0012 starts";
    int64_t formId = 1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->NotifyFormCastTempForm(formId, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0012 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0013
 * @tc.desc: text FireFormEvent function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0013, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0013 starts";
    int64_t formId = 1;
    std::string message = "this is message";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->FireFormEvent(formId, message, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0013 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0014
 * @tc.desc: text FireFormEvent function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0014, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0014 starts";
    int64_t formId = 1;
    std::string message = "this is message";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->FireFormEvent(formId, message, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0014 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0015
 * @tc.desc: text AcquireState function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0015, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0015 starts";
    Want wantArg;
    std::string provider = "this is provider";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->AcquireState(wantArg, provider, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0015 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0016
 * @tc.desc: text AcquireState function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0016, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0016 starts";
    Want wantArg;
    std::string provider = "this is provider";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->AcquireState(wantArg, provider, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0016 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0017
 * @tc.desc: text AcquireShareFormData function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0017, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0017 starts";
    int64_t formId = 2;
    std::string remoteDeviceId = "this is remoteDeviceId";
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int64_t requestCode = 1;
    int result = formProviderProxy->AcquireShareFormData(formId, remoteDeviceId, token, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0017 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0018
 * @tc.desc: text AcquireShareFormData function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0018, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0018 starts";
    int64_t formId = 2;
    std::string remoteDeviceId = "this is remoteDeviceId";
    int64_t requestCode = 1;
    int result = formProviderProxy->AcquireShareFormData(formId, remoteDeviceId, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0018 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0019
 * @tc.desc: text AcquireFormData function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0019, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0019 starts";
    int64_t formId = 2;
    std::string remoteDeviceId = "this is remoteDeviceId";
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int64_t requestCode = 1;
    int result = formProviderProxy->AcquireFormData(formId, token, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0019 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0020
 * @tc.desc: text AcquireFormData function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0020, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0020 starts";
    int64_t formId = 2;
    std::string remoteDeviceId = "this is remoteDeviceId";
    int64_t requestCode = 1;
    int result = formProviderProxy->AcquireFormData(formId, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0020 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0021
 * @tc.desc: text EventNotify function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0021, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0021 starts";
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.emplace_back(formId);
    int32_t formVisibleType = 2;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->EventNotify(formIds, formVisibleType, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0021 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0022
 * @tc.desc: text NotifyFormCastTempForm function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0022, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0022 starts";
    int64_t formId = 1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->NotifyFormCastTempForm(formId, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0022 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0023
 * @tc.desc: text NotifyFormCastTempForm function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0023, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0023 starts";
    int64_t formId = 1;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->NotifyFormCastTempForm(formId, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0023 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0024
 * @tc.desc: text FireFormEvent function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0024, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0024 starts";
    int64_t formId = 1;
    std::string message = "this is message";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->FireFormEvent(formId, message, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0024 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0025
 * @tc.desc: text FireFormEvent function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0025, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0025 starts";
    int64_t formId = 1;
    std::string message = "this is message";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->FireFormEvent(formId, message, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0025 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0026
 * @tc.desc: text AcquireState function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0026, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0026 starts";
    Want wantArg;
    std::string provider = "this is provider";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int result = formProviderProxy->AcquireState(wantArg, provider, want, token);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0026 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0027
 * @tc.desc: text AcquireState function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0027, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0027 starts";
    Want wantArg;
    std::string provider = "this is provider";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    int result = formProviderProxy->AcquireState(wantArg, provider, want, nullptr);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0027 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0028
 * @tc.desc: text AcquireShareFormData function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0028, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0028 starts";
    int64_t formId = 2;
    std::string remoteDeviceId = "this is remoteDeviceId";
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int64_t requestCode = 1;
    int result = formProviderProxy->AcquireShareFormData(formId, remoteDeviceId, token, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0028 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0029
 * @tc.desc: text AcquireShareFormData function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0029, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0029 starts";
    int64_t formId = 2;
    std::string remoteDeviceId = "this is remoteDeviceId";
    int64_t requestCode = 1;
    int result = formProviderProxy->AcquireShareFormData(formId, remoteDeviceId, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0029 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0030
 * @tc.desc: text AcquireFormData function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0030, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0030 starts";
    int64_t formId = 2;
    std::string remoteDeviceId = "this is remoteDeviceId";
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    int64_t requestCode = 1;
    int result = formProviderProxy->AcquireFormData(formId, token, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0030 test ends";
}

/**
 * @tc.name: FormProviderProxyTest_0031
 * @tc.desc: text AcquireFormData function.
 * @tc.type: FUNC
 * @tc.require: issueI639Z3
 */
HWTEST_F(FormMgrProxyTest, FormProviderProxyTest_0031, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0031 starts";
    int64_t formId = 2;
    std::string remoteDeviceId = "this is remoteDeviceId";
    int64_t requestCode = 1;
    int result = formProviderProxy->AcquireFormData(formId, nullptr, requestCode);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderProxyTest_0031 test ends";
}

/**
 * @tc.name: GetFormInstanceById_0100
 * @tc.desc: text the return of GetFormInstanceById.
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrProxyTest, GetFormInstanceById_0100, TestSize.Level1) {
    GTEST_LOG_(INFO) << "GetFormInstanceById_0100 starts";
    int64_t formId = 2;
    bool isUnusedIncluded = false;
    FormInstance formInstance;
    auto result = formMgrProxy->GetFormInstanceById(formId, isUnusedIncluded, formInstance);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "GetFormInstanceById_0100 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0101
 * @tc.desc: Verify HasFormVisible
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0101, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0101 starts";
    EXPECT_CALL(*mockFormMgrService, HasFormVisible(_))
        .Times(1)
        .WillOnce(Return(true));
    uint32_t tokenId = 0;
    bool result = formMgrProxy->HasFormVisible(tokenId);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0101 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0102
 * @tc.desc: Verify GetFormsInfoByFilter is called.
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0102, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0102 starts";
    EXPECT_CALL(*mockFormMgrService, GetFormsInfoByFilter(_, _))
        .Times(1)
        .WillOnce(Return(true));
    std::vector<FormInfo> formInfos;
    FormInfoFilter filter;
    bool result = formMgrProxy->GetFormsInfoByFilter(filter, formInfos);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0102 test ends";
}

/**
 * @tc.number: FormMgrProxyTest_0103
 * @tc.name: test UpdateFormLocation function.
 * @tc.desc: Verify that the UpdateFormLocation interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0103, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0103 starts";
    int64_t formId = 0;
    int32_t formLocation = 1;
    EXPECT_EQ(formMgrProxy->UpdateFormLocation(formId, formLocation), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0103 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_0104
 * @tc.desc: Verify CreateForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0104, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0104 starts";
    EXPECT_CALL(*mockFormMgrService, CreateForm(_, _))
        .Times(1)
        .WillOnce(Return(0));
    Want want;
    RunningFormInfo runningFormInfo;
    int result = formMgrProxy->CreateForm(want, runningFormInfo);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0104 test ends";
}

/**
 * @tc.number: FormMgrProxyTest_0105
 * @tc.name: test SetPublishFormResult function.
 * @tc.desc: Verify that the SetPublishFormResult interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0105, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0105 starts";
    int64_t formId = 0;
    Constants::PublishFormResult result {Constants::PublishFormErrorCode::SUCCESS, ""};
    EXPECT_EQ(formMgrProxy->SetPublishFormResult(formId, result), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0105 test ends";
}

/**
 * @tc.number: FormMgrProxyTest_0106
 * @tc.name: test AcquireAddFormResult function.
 * @tc.desc: Verify that the AcquireAddFormResult interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_0106, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0106 starts";
    int64_t formId = 0;
    EXPECT_EQ(formMgrProxy->AcquireAddFormResult(formId), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_0106 test ends";
}

/**
 * @tc.number: FormMgrProxyTest_BatchRefreshForms_001
 * @tc.name: test BatchRefreshForms function.
 * @tc.desc: Verify that the BatchRefreshForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_BatchRefreshForms_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_BatchRefreshForms_001 starts";
    int32_t formRefreshType = Constants::REFRESH_ALL_FORM;
    EXPECT_EQ(formMgrProxy->BatchRefreshForms(formRefreshType), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_BatchRefreshForms_001 test ends";
}

/**
 * @tc.number: FormMgrProxyTest_BatchRefreshForms_002
 * @tc.name: test BatchRefreshForms function.
 * @tc.desc: Verify that the BatchRefreshForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_BatchRefreshForms_002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_BatchRefreshForms_002 starts";
    int32_t formRefreshType = Constants::REFRESH_ALL_FORM;
    EXPECT_EQ(formMgrProxy->BatchRefreshForms(formRefreshType), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_BatchRefreshForms_002 test ends";
}

/**
 * @tc.number: FormMgrProxyTest_IsFormBundleForbidden_001
 * @tc.name: test IsFormBundleForbidden function.
 * @tc.desc: Verify that the IsFormBundleForbidden.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_IsFormBundleForbidden_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsFormBundleForbidden_001 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    bool result = formMgrProxy->IsFormBundleForbidden(bundleName);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsFormBundleForbidden_001 test ends";
}

/**
 * @tc.number: FormMgrProxyTest_IsFormBundleForbidden_002
 * @tc.name: test IsFormBundleForbidden function.
 * @tc.desc: Verify that the IsFormBundleForbidden.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_IsFormBundleForbidden_002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsFormBundleForbidden_002 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    bool result = formMgrProxy->IsFormBundleForbidden(bundleName);
    EXPECT_EQ(result, false);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsFormBundleForbidden_002 test ends";
}

/**
 * @tc.number: FormMgrProxyTest_EnableForms_001
 * @tc.name: test EnableForms function.
 * @tc.desc: Verify that the EnableForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_EnableForms_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_EnableForms_001 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    EXPECT_EQ(formMgrProxy->EnableForms(bundleName, true), ERR_OK);
    EXPECT_EQ(formMgrProxy->EnableForms(bundleName, false), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_EnableForms_001 test ends";
}

/**
 * @tc.number: FormMgrProxyTest_EnableForms_002
 * @tc.name: test EnableForms function.
 * @tc.desc: Verify that the EnableForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_EnableForms_002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_EnableForms_002 starts";
    std::string bundleName = "ohos.samples.FormApplication";
    EXPECT_EQ(formMgrProxy->EnableForms(bundleName, true), ERR_OK);
    EXPECT_EQ(formMgrProxy->EnableForms(bundleName, false), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_EnableForms_002 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_IsSystemAppForm_001
 * @tc.desc: Verify IsSystemAppForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_IsSystemAppForm_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsSystemAppForm_001 starts";
    EXPECT_CALL(*mockFormMgrService, IsSystemAppForm(_))
        .Times(1)
        .WillOnce(Return(true));
    std::string bundleName = "ohos.samples.FormApplicationTest";
    bool result = formMgrProxy->IsSystemAppForm(bundleName);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsSystemAppForm_001 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_IsSystemAppForm_002
 * @tc.desc: Verify IsSystemAppForm
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_IsSystemAppForm_002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsSystemAppForm_002 starts";
    EXPECT_CALL(*mockFormMgrService, IsSystemAppForm(_))
        .Times(1)
        .WillOnce(Return(true));
    std::string bundleName = "ohos.samples.FormApplicationTest";
    bool result = formMgrProxy->IsSystemAppForm(bundleName);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsSystemAppForm_002 test ends";
}

/**
 * @tc.name: FormMgrProxyTest_StartAbilityByCrossBundle_001
 * @tc.desc: test StartAbilityByCrossBundle function.
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_StartAbilityByCrossBundle_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_StartAbilityByCrossBundle_001 start";
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    auto result = formMgrProxy->StartAbilityByCrossBundle(want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_StartAbilityByCrossBundle_001 end";
}

/*
 * @tc.number: FormMgrProxyTest_RegisterGetFormRectProxy_001
 * @tc.name: Verify RegisterGetFormRectProxy
 * @tc.desc: text RegisterGetFormRectProxy function.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_RegisterGetFormRectProxy_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_RegisterGetFormRectProxy_001 starts";
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    auto result = formMgrProxy->RegisterGetFormRectProxy(token);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_RegisterGetFormRectProxy_001 ends";
}

/**
 * @tc.number: FormMgrProxyTest_UnregisterGetFormRectProxy_001
 * @tc.name: Verify UnregisterGetFormRectProxy
 * @tc.desc: text UnregisterGetFormRectProxy function.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_UnregisterGetFormRectProxy_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_UnregisterGetFormRectProxy_001 starts";
    auto result = formMgrProxy->UnregisterGetFormRectProxy();
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_UnregisterGetFormRectProxy_001 ends";
}

/**
 * @tc.number: FormMgrProxyTest_GetFormRect_001
 * @tc.name: Verify GetFormRect
 * @tc.desc: When the parameter code is FORM_MGR_GET_FORM_RECT, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_GetFormRect_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_GetFormRect_001 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    EXPECT_CALL(*mockFormMgrService, GetFormRect(_, _)).Times(1).WillOnce(Return(ERR_OK));
    constexpr int64_t formId = 1;
    Rect rect;
    auto result = formMgrProxy->GetFormRect(formId, rect);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_GetFormRect_001 ends";
}

/*
 * @tc.number: FormMgrProxyTest_RegisterGetLiveFormStatusProxy_001
 * @tc.name: Verify RegisterGetLiveFormStatusProxy
 * @tc.desc: text RegisterGetLiveFormStatusProxy function.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_RegisterGetLiveFormStatusProxy_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_RegisterGetLiveFormStatusProxy_001 starts";
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    auto result = formMgrProxy->RegisterGetLiveFormStatusProxy(token);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_RegisterGetLiveFormStatusProxy_001 ends";
}

/**
 * @tc.number: FormMgrProxyTest_UnregisterGetLiveFormStatusProxy_001
 * @tc.name: Verify UnregisterGetLiveFormStatusProxy
 * @tc.desc: text UnregisterGetLiveFormStatusProxy function.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_UnregisterGetLiveFormStatusProxy_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_UnregisterGetLiveFormStatusProxy_001 starts";
    auto result = formMgrProxy->UnregisterGetLiveFormStatusProxy();
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_UnregisterGetLiveFormStatusProxy_001 ends";
}

/**
 * @tc.number: FormMgrProxyTest_IsFormBundleDebugSignature_001
 * @tc.name: Verify IsFormBundleDebugSignature
 * @tc.desc: text IsFormBundleDebugSignature function.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_IsFormBundleDebugSignature_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsFormBundleDebugSignature_001 starts";
    std::string bundleName = "ohos.samples.FormApplicationTest";
    auto result = formMgrProxy->IsFormBundleDebugSignature(bundleName);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_IsFormBundleDebugSignature_001 ends";
}

/**
 * @tc.number: FormMgrProxyTest_ReloadForms_001
 * @tc.name: Verify ReloadForms
 * @tc.desc: text ReloadForms function.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_ReloadForms_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_ReloadForms_001 starts";
    int32_t reloadNum = 0;
    std::string moduleName = "A";
    std::string abilityName = "B";
    std::string formName = "C";
    int32_t result = formMgrProxy->ReloadForms(reloadNum, moduleName, abilityName, formName);
    // expect result.
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_ReloadForms_001 ends";
}

/**
 * @tc.number: FormMgrProxyTest_ReloadAllForms_001
 * @tc.name: Verify ReloadAllForms
 * @tc.desc: text ReloadAllForms function.
 */
HWTEST_F(FormMgrProxyTest, FormMgrProxyTest_ReloadAllForms_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrProxyTest_ReloadAllForms_001 starts";
    int32_t reloadNum = 0;
    int32_t result = formMgrProxy->ReloadAllForms(reloadNum);
    // expect result.
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrProxyTest_ReloadForms_001 ends";
}
}