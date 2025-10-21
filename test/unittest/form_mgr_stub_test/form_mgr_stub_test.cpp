/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#define private public
#include "appexecfwk_errors.h"
#include "form_mgr_stub.h"
#undef private
#include "gmock/gmock.h"
#include "mock_form_mgr_service.h"
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
class FormMgrStubTest : public testing::Test {
public:
    void SetUp() override
    {
        mockFormMgrService = new (std::nothrow) MockFormMgrService();
    }
    sptr<MockFormMgrService> mockFormMgrService;
};

void GetParcelableInfos(MessageParcel &reply, std::vector<FormInfo> &parcelableInfos)
    {
    int32_t infoSize = reply.ReadInt32();
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<FormInfo> info(reply.ReadParcelable<FormInfo>());
        parcelableInfos.emplace_back(*info);
    }
}

bool WriteFormDataProxies(MessageParcel &data, const std::vector<FormDataProxy> &formDataProxies)
{
    if (!data.WriteInt32(formDataProxies.size())) {
        return false;
    }
    for (const auto &formDataProxy : formDataProxies) {
        if (!data.WriteString16(Str8ToStr16(formDataProxy.key))) {
            return false;
        }
        if (!data.WriteString16(Str8ToStr16(formDataProxy.subscribeId))) {
            return false;
        }
    }
    return true;
}

/**
 * @tc.name: FormMgrStubTest_0001
 * @tc.desc: Verify HandleGetFormsInfo
 * @tc.type: FUNC
 * @tc.require: #I59O23
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrTest_0001 starts";
    // initialize input parameters.
    MessageParcel data;
    FormInfoFilter filter;
    filter.moduleName = "";
    data.WriteParcelable(&filter);
    MessageParcel reply;
    // set up return vector.
    std::vector<FormInfo> returnInfos;
    // set up 2 infos from different modules.
    FormInfo info1 = {};
    info1.bundleName = "bundle1";
    info1.moduleName = "module1";
    info1.name = "widget1";
    FormInfo info2 = {};
    info2.bundleName = "bundle1";
    info2.moduleName = "module2";
    info2.name = "widget2";
    returnInfos.push_back(info1);
    returnInfos.push_back(info2);
    // Set Expectations
    EXPECT_CALL(*mockFormMgrService, GetFormsInfo(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgReferee<1>(returnInfos), Return(ERR_OK)));
    // test.
    mockFormMgrService->HandleGetFormsInfo(data, reply);
    // check errorcode
    EXPECT_EQ(ERR_OK, reply.ReadInt32());
    // check resulting infos.
    std::vector<FormInfo> resultInfos;
    GetParcelableInfos(reply, resultInfos);
    EXPECT_THAT(resultInfos, ContainerEq(returnInfos));
    GTEST_LOG_(INFO) << "FormMgrStubTest_0001 ends";
}

/**
 * @tc.name: FormMgrStubTest_0002
 * @tc.desc: Verify HandleGetFormsInfo
 * @tc.type: FUNC
 * @tc.require: #I59O23
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0002 starts";
    // initialize input parameters.
    MessageParcel data;
    FormInfoFilter filter;
    filter.moduleName = "";
    data.WriteParcelable(&filter);
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, GetFormsInfo(_, _))
        .Times(1)
        .WillOnce(Return(-1));
    // test.
    mockFormMgrService->HandleGetFormsInfo(data, reply);
    // check errorcode
    EXPECT_NE(ERR_OK, reply.ReadInt32());
    // check resulting infos.
    std::vector<FormInfo> resultInfos;
    GetParcelableInfos(reply, resultInfos);
    EXPECT_EQ(0, resultInfos.size());
    GTEST_LOG_(INFO) << "FormMgrStubTest_0002 ends";
}

/**
 * @tc.name: FormMgrStubTest_0003
 * @tc.desc: Verify HandleIsRequestPublishFormSupported
 * @tc.type: FUNC
 * @tc.require: #I58Y0A
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0003 starts";
    // initialize input parameters.
    MessageParcel data;
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, IsRequestPublishFormSupported()).Times(1).WillOnce(Return(true));
    // test.
    int32_t errCode = mockFormMgrService->HandleIsRequestPublishFormSupported(data, reply);
    // check errorcode
    EXPECT_EQ(ERR_OK, errCode);
    // check resulting infos.
    bool result;
    reply.ReadBool(result);
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0003 ends";
}

/**
 * @tc.name: FormMgrStubTest_0004
 * @tc.desc: Verify HandleStartAbility
 * @tc.type: FUNC
 * @tc.require: #I5EFDX
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0004 starts";
    // initialize input parameters.
    MessageParcel data;
    MessageParcel reply;
    Want want;
    want = want.SetElementName("", "com.example.FormAbility", "MainAbility");
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();
    // write in want
    data.WriteParcelable(&want);
    // write in token
    data.WriteRemoteObject(token);
    EXPECT_CALL(*mockFormMgrService, StartAbility(_, _))
        .Times(1)
        .WillOnce(Return(0));
    // test.
    int32_t errCode = mockFormMgrService->HandleStartAbility(data, reply);
    // check errorcode
    EXPECT_EQ(ERR_OK, errCode);
    // check resulting infos.
    int32_t result;
    reply.ReadInt32(result);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0004 ends";
}

/**
 * @tc.name: FormMgrStubTest_0005
 * @tc.desc: Verify HandleNotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0005, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0005 starts";
    // initialize input parameters.
    MessageParcel data;
    MessageParcel reply;
    int64_t formId1 = 1;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);

    bool isProtected = false;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();

    // write in formIds
    data.WriteInt64Vector(formIds);
    // write in isProtected
    data.WriteBool(isProtected);
    // write in token
    data.WriteRemoteObject(token);
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // test.
    int32_t errCode = mockFormMgrService->HandleNotifyFormsPrivacyProtected(data, reply);
    // check errorcode
    EXPECT_EQ(0, errCode);
    // check resulting infos.
    int32_t result;
    reply.ReadInt32(result);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0005 ends";
}

/**
 * @tc.name: FormMgrStubTest_0006
 * @tc.desc: Verify HandleNotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0006, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0006 starts";
    // initialize input parameters.
    MessageParcel data;
    MessageParcel reply;
    int64_t formId1 = 2;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);

    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();

    // write in formIds
    data.WriteInt64Vector(formIds);
    // write in isProtected
    data.WriteBool(isProtected);
    // write in token
    data.WriteRemoteObject(token);
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // test.
    int32_t errCode = mockFormMgrService->HandleNotifyFormsPrivacyProtected(data, reply);
    // check errorcode
    EXPECT_EQ(0, errCode);
    // check resulting infos.
    int32_t result;
    reply.ReadInt32(result);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0006 ends";
}

/**
 * @tc.name: FormMgrStubTest_0007
 * @tc.desc: Verify HandleNotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0007, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0007 starts";
    // initialize input parameters.
    MessageParcel data;
    MessageParcel reply;
    int64_t formId1 = 3;
    int64_t formId2 = 4;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);
    formIds.push_back(formId2);

    bool isProtected = false;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();

    // write in formIds
    data.WriteInt64Vector(formIds);
    // write in isProtected
    data.WriteBool(isProtected);
    // write in token
    data.WriteRemoteObject(token);
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // test.
    int32_t errCode = mockFormMgrService->HandleNotifyFormsPrivacyProtected(data, reply);
    // check errorcode
    EXPECT_EQ(0, errCode);
    // check resulting infos.
    int32_t result;
    reply.ReadInt32(result);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0007 ends";
}

/**
 * @tc.name: FormMgrStubTest_0008
 * @tc.desc: Verify HandleNotifyFormsPrivacyProtected
 * @tc.type: FUNC
 * @tc.require: #I5ST27
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0008, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0008 starts";
    // initialize input parameters.
    MessageParcel data;
    MessageParcel reply;
    int64_t formId1 = 5;
    int64_t formId2 = 6;
    std::vector<int64_t> formIds;
    formIds.push_back(formId1);
    formIds.push_back(formId2);

    bool isProtected = true;
    sptr<MockFormToken> token = new (std::nothrow) MockFormToken();

    // write in formIds
    data.WriteInt64Vector(formIds);
    // write in isProtected
    data.WriteBool(isProtected);
    // write in token
    data.WriteRemoteObject(token);
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _))
        .Times(1)
        .WillOnce(Return(0));
    // test.
    int32_t errCode = mockFormMgrService->HandleNotifyFormsPrivacyProtected(data, reply);
    // check errorcode
    EXPECT_EQ(0, errCode);
    // check resulting infos.
    int32_t result;
    reply.ReadInt32(result);
    EXPECT_EQ(result, 0);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0008 ends";
}

/**
 * @tc.number: FormMgrStubTest_0009
 * @tc.name: Verify OnRemoteRequest
 * @tc.desc: When the parameter code is FORM_MGR_ADD_FORM, the interface calls normally.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0009, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0009 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ADD_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0009 ends";
}

/**
 * @tc.number: FormMgrStubTest_0010
 * @tc.name: Verify OnRemoteRequest and HandleAddForm
 * @tc.desc: When the parameter code is FORM_MGR_ADD_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0010, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0010 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ADD_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, AddForm(_, _, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0010 ends";
}

/**
 * @tc.number: FormMgrStubTest_0011
 * @tc.name: Verify OnRemoteRequest and HandleAddForm
 * @tc.desc: When the parameter code is FORM_MGR_ADD_FORM, the interface return
 *           value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0011, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0011 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const Want want = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ADD_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0011 ends";
}

/**
 * @tc.number: FormMgrStubTest_0012
 * @tc.name: Verify OnRemoteRequest and HandleAddForm
 * @tc.desc: When the parameter code is FORM_MGR_ADD_FORM, the interface return value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0012, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0012 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ADD_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0012 ends";
}

/**
 * @tc.number: FormMgrStubTest_0013
 * @tc.name: Verify OnRemoteRequest and HandleDeleteForm
 * @tc.desc: When the parameter code is FORM_MGR_DELETE_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0013, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0013 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DELETE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, DeleteForm(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0013 ends";
}

/**
 * @tc.number: FormMgrStubTest_0014
 * @tc.name: Verify OnRemoteRequest and HandleDeleteForm
 * @tc.desc: When the parameter code is FORM_MGR_DELETE_FORM, the interface return
 *           value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0014, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0014 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DELETE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0014 ends";
}

/**
 * @tc.number: FormMgrStubTest_0015
 * @tc.name: Verify OnRemoteRequest and HandleReleaseForm
 * @tc.desc: When the parameter code is FORM_MGR_RELEASE_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0015, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0015 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr bool delCache = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELEASE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteRemoteObject(callerToken);
    data.WriteBool(delCache);
    EXPECT_CALL(*mockFormMgrService, ReleaseForm(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0015 ends";
}

/**
 * @tc.number: FormMgrStubTest_0016
 * @tc.name: Verify OnRemoteRequest and HandleReleaseForm
 * @tc.desc: When the parameter code is FORM_MGR_RELEASE_FORM, the interface return
 *           value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0016, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0016 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELEASE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0016 ends";
}

/**
 * @tc.number: FormMgrStubTest_0017
 * @tc.name: Verify OnRemoteRequest and HandleUpdateForm
 * @tc.desc: When the parameter code is FORM_MGR_UPDATE_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0017, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0017 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const FormProviderData formProviderData = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteParcelable(&formProviderData);
    EXPECT_CALL(*mockFormMgrService, UpdateForm(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0017 ends";
}

/**
 * @tc.number: FormMgrStubTest_0018
 * @tc.name: Verify OnRemoteRequest and HandleRequestForm
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0018, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0018 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteRemoteObject(callerToken);
    data.WriteParcelable(&want);
    EXPECT_CALL(*mockFormMgrService, RequestForm(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0018 ends";
}

/**
 * @tc.number: FormMgrStubTest_0019
 * @tc.name: Verify OnRemoteRequest and HandleRequestForm
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_FORM, the interface return
 *           value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0019, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0019 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteRemoteObject(callerToken);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0019 ends";
}

/**
 * @tc.number: FormMgrStubTest_0020
 * @tc.name: Verify OnRemoteRequest and HandleRequestForm
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_FORM, the interface return
 *           value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0020, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0020 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0020 ends";
}

/**
 * @tc.number: FormMgrStubTest_0021
 * @tc.name: Verify OnRemoteRequest and HandleNotifyWhetherVisibleForms
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE, the interface return
 *           value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0021, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0021 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    const int32_t formVisibleType = 0;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteRemoteObject(callerToken);
    data.WriteInt32(formVisibleType);
    EXPECT_CALL(*mockFormMgrService, NotifyWhetherVisibleForms(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0021 ends";
}

/**
 * @tc.number: FormMgrStubTest_0022
 * @tc.name: Verify OnRemoteRequest and HandleNotifyWhetherVisibleForms
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE, the interface return
 *           value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0022, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0022 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0022 ends";
}

/**
 * @tc.number: FormMgrStubTest_0023
 * @tc.name: Verify OnRemoteRequest and HandleNotifyWhetherVisibleForms
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE, the interface return
 *           value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0023, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0023 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORM_WHETHER_VISIBLE);
    constexpr int32_t valueCode = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt32(valueCode);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0023 ends";
}

/**
 * @tc.number: FormMgrStubTest_0024
 * @tc.name: Verify OnRemoteRequest and HandleCastTempForm
 * @tc.desc: When the parameter code is FORM_MGR_CAST_TEMP_FORM, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0024, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0024 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CAST_TEMP_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0024 ends";
}

/**
 * @tc.number: FormMgrStubTest_0025
 * @tc.name: Verify OnRemoteRequest and HandleDumpStorageFormInfos
 * @tc.desc: When the parameter code is FORM_MGR_STORAGE_FORM_INFOS, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0025, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0025 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_STORAGE_FORM_INFOS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, DumpStorageFormInfos(_)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0025 ends";
}

/**
 * @tc.number: FormMgrStubTest_0026
 * @tc.name: Verify OnRemoteRequest and HandleDumpStorageFormInfos
 * @tc.desc: When the parameter code is FORM_MGR_STORAGE_FORM_INFOS, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0026, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0026 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_STORAGE_FORM_INFOS);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, DumpStorageFormInfos(_))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0026 ends";
}

/**
 * @tc.number: FormMgrStubTest_0027
 * @tc.name: Verify OnRemoteRequest and HandleDumpFormInfoByBundleName
 * @tc.desc: When the parameter code is FORM_MGR_STORAGE_FORM_INFOS, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0027, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0027 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::string bundleName = "abc";
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_NAME);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    EXPECT_CALL(*mockFormMgrService, DumpFormInfoByBundleName(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0027 ends";
}

/**
 * @tc.number: FormMgrStubTest_0028
 * @tc.name: Verify OnRemoteRequest and HandleDumpFormInfoByBundleName
 * @tc.desc: When the parameter code is FORM_MGR_FORM_INFOS_BY_NAME, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0028, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0028 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::string bundleName = "abc";
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_NAME);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    EXPECT_CALL(*mockFormMgrService, DumpFormInfoByBundleName(_, _))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0028 ends";
}

/**
 * @tc.number: FormMgrStubTest_0029
 * @tc.name: Verify OnRemoteRequest and HandleDumpFormInfoByFormId
 * @tc.desc: When the parameter code is FORM_MGR_FORM_INFOS_BY_ID, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0029, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0029 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_ID);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, DumpFormInfoByFormId(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0029 ends";
}

/**
 * @tc.number: FormMgrStubTest_0030
 * @tc.name: Verify OnRemoteRequest and HandleDumpFormInfoByFormId
 * @tc.desc: When the parameter code is FORM_MGR_FORM_INFOS_BY_ID, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0030, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0030 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_INFOS_BY_ID);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, DumpFormInfoByFormId(_, _))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0030 ends";
}

/**
 * @tc.number: FormMgrStubTest_0031
 * @tc.name: Verify OnRemoteRequest and HandleDumpFormTimerByFormId
 * @tc.desc: When the parameter code is FORM_MGR_FORM_TIMER_INFO_BY_ID, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0031, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0031 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, DumpFormTimerByFormId(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0031 ends";
}

/**
 * @tc.number: FormMgrStubTest_0032
 * @tc.name: Verify OnRemoteRequest and HandleDumpFormTimerByFormId
 * @tc.desc: When the parameter code is FORM_MGR_FORM_TIMER_INFO_BY_ID, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0032, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0032 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_FORM_TIMER_INFO_BY_ID);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, DumpFormTimerByFormId(_, _))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0032 ends";
}

/**
 * @tc.number: FormMgrStubTest_0033
 * @tc.name: Verify OnRemoteRequest and HandleSetNextRefreshTime
 * @tc.desc: When the parameter code is FORM_MGR_SET_NEXT_REFRESH_TIME, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0033, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0033 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr int64_t nextTime = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_SET_NEXT_REFRESH_TIME);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteInt64(nextTime);
    EXPECT_CALL(*mockFormMgrService, SetNextRefreshTime(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0033 ends";
}

/**
 * @tc.number: FormMgrStubTest_0034
 * @tc.name: Verify OnRemoteRequest and HandleLifecycleUpdate
 * @tc.desc: When the parameter code is FORM_MGR_LIFECYCLE_UPDATE, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0034, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0034 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr bool updateType = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_LIFECYCLE_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteRemoteObject(callerToken);
    data.WriteBool(updateType);
    EXPECT_CALL(*mockFormMgrService, LifecycleUpdate(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0034 ends";
}

/**
 * @tc.number: FormMgrStubTest_0035
 * @tc.name: Verify OnRemoteRequest and HandleLifecycleUpdate
 * @tc.desc: When the parameter code is FORM_MGR_LIFECYCLE_UPDATE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0035, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0035 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_LIFECYCLE_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0035 ends";
}

/**
 * @tc.number: FormMgrStubTest_0036
 * @tc.name: Verify OnRemoteRequest and HandleLifecycleUpdate
 * @tc.desc: When the parameter code is FORM_MGR_LIFECYCLE_UPDATE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0036, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0036 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_LIFECYCLE_UPDATE);
    constexpr int32_t valueCode = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt32(valueCode);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0036 ends";
}

/**
 * @tc.number: FormMgrStubTest_0037
 * @tc.name: Verify OnRemoteRequest and HandleMessageEvent
 * @tc.desc: When the parameter code is FORM_MGR_MESSAGE_EVENT, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0037, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0037 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_MESSAGE_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, MessageEvent(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0037 ends";
}

/**
 * @tc.number: FormMgrStubTest_0038
 * @tc.name: Verify OnRemoteRequest and HandleMessageEvent
 * @tc.desc: When the parameter code is FORM_MGR_MESSAGE_EVENT, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0038, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0038 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const Want want = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_MESSAGE_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0038 ends";
}

/**
 * @tc.number: FormMgrStubTest_0039
 * @tc.name: Verify OnRemoteRequest and HandleMessageEvent
 * @tc.desc: When the parameter code is FORM_MGR_MESSAGE_EVENT, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0039, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0039 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_MESSAGE_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0039 ends";
}

/**
 * @tc.number: FormMgrStubTest_0040
 * @tc.name: Verify OnRemoteRequest and HandleDeleteInvalidForms
 * @tc.desc: When the parameter code is FORM_MGR_DELETE_INVALID_FORMS, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0040, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0040 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DELETE_INVALID_FORMS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, DeleteInvalidForms(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0040 ends";
}

/**
 * @tc.number: FormMgrStubTest_0041
 * @tc.name: Verify OnRemoteRequest and HandleDeleteInvalidForms
 * @tc.desc: When the parameter code is FORM_MGR_DELETE_INVALID_FORMS, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0041, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0041 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DELETE_INVALID_FORMS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0041 ends";
}

/**
 * @tc.number: FormMgrStubTest_0042
 * @tc.name: Verify OnRemoteRequest and HandleDeleteInvalidForms
 * @tc.desc: When the parameter code is FORM_MGR_DELETE_INVALID_FORMS, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0042, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0042 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DELETE_INVALID_FORMS);
    constexpr int32_t valueCode = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt32(valueCode);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0042 ends";
}

/**
 * @tc.number: FormMgrStubTest_0043
 * @tc.name: Verify OnRemoteRequest and HandleAcquireFormState
 * @tc.desc: When the parameter code is FORM_MGR_ACQUIRE_FORM_STATE, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0043, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0043 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    const Want want = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_FORM_STATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, AcquireFormState(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0043 ends";
}

/**
 * @tc.number: FormMgrStubTest_0044
 * @tc.name: Verify OnRemoteRequest and HandleAcquireFormState
 * @tc.desc: When the parameter code is FORM_MGR_ACQUIRE_FORM_STATE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0044, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0044 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const Want want = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_FORM_STATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&want);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0044 ends";
}

/**
 * @tc.number: FormMgrStubTest_0045
 * @tc.name: Verify OnRemoteRequest and HandleAcquireFormState
 * @tc.desc: When the parameter code is FORM_MGR_ACQUIRE_FORM_STATE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0045, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0045 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_FORM_STATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0045 ends";
}

/**
 * @tc.number: FormMgrStubTest_0046
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsVisible
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_VISIBLE, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0046, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0046 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    const std::vector<int64_t> formIds;
    constexpr bool isVisible = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_VISIBLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteBool(isVisible);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, NotifyFormsVisible(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0046 ends";
}

/**
 * @tc.number: FormMgrStubTest_0047
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsVisible
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_VISIBLE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0047, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0047 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr bool isVisible = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_VISIBLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteBool(isVisible);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0047 ends";
}

/**
 * @tc.number: FormMgrStubTest_0048
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsVisible
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_VISIBLE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0048, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0048 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_VISIBLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0048 ends";
}

/**
 * @tc.number: FormMgrStubTest_0049
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsVisible
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_VISIBLE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0049, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0049 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_VISIBLE);
    constexpr int32_t valueCode = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt32(valueCode);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0049 ends";
}

/**
 * @tc.number: FormMgrStubTest_0050
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsPrivacyProtected
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0050, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0050 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    const std::vector<int64_t> formIds;
    constexpr bool isVisible = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteBool(isVisible);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, NotifyFormsPrivacyProtected(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0050 ends";
}

/**
 * @tc.number: FormMgrStubTest_0051
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsPrivacyProtected
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0051, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0051 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr bool isVisible = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteBool(isVisible);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0051 ends";
}

/**
 * @tc.number: FormMgrStubTest_0052
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsPrivacyProtected
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0052, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0052 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0052 ends";
}

/**
 * @tc.number: FormMgrStubTest_0053
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsPrivacyProtected
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0053, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0053 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_PRIVACY_PROTECTED);
    constexpr int32_t valueCode = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt32(valueCode);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0053 ends";
}

/**
 * @tc.number: FormMgrStubTest_0054
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsEnableUpdate
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0054, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0054 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    const std::vector<int64_t> formIds;
    constexpr bool isVisible = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteBool(isVisible);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, NotifyFormsEnableUpdate(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0054 ends";
}

/**
 * @tc.number: FormMgrStubTest_0055
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsEnableUpdate
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0055, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0055 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr bool isVisible = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteBool(isVisible);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0055 ends";
}

/**
 * @tc.number: FormMgrStubTest_0056
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsEnableUpdate
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0056, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0056 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0056 ends";
}

/**
 * @tc.number: FormMgrStubTest_0057
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormsEnableUpdate
 * @tc.desc: When the parameter code is FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0057, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0057 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORMS_ENABLE_UPDATE);
    constexpr int32_t valueCode = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt32(valueCode);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0057 ends";
}

/**
 * @tc.number: FormMgrStubTest_0058
 * @tc.name: Verify OnRemoteRequest and HandleGetAllFormsInfo
 * @tc.desc: When the parameter code is FORM_MGR_GET_ALL_FORMS_INFO, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0058, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0058 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_ALL_FORMS_INFO);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    EXPECT_CALL(*mockFormMgrService, GetAllFormsInfo(_)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0058 ends";
}

/**
 * @tc.number: FormMgrStubTest_0059
 * @tc.name: Verify OnRemoteRequest and HandleGetAllFormsInfo
 * @tc.desc: When the parameter code is FORM_MGR_GET_ALL_FORMS_INFO, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0059, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0059 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_ALL_FORMS_INFO);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    EXPECT_CALL(*mockFormMgrService, GetAllFormsInfo(_))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0059 ends";
}

/**
 * @tc.number: FormMgrStubTest_0060
 * @tc.name: Verify OnRemoteRequest and HandleGetFormsInfoByApp
 * @tc.desc: When the parameter code is FORM_MGR_GET_FORMS_INFO_BY_APP, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0060, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0060 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::string bundleName = "bundleName";
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_APP);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    EXPECT_CALL(*mockFormMgrService, GetFormsInfoByApp(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0060 ends";
}

/**
 * @tc.number: FormMgrStubTest_0061
 * @tc.name: Verify OnRemoteRequest and HandleGetFormsInfoByApp
 * @tc.desc: When the parameter code is FORM_MGR_GET_FORMS_INFO_BY_APP, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0061, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0061 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::string bundleName = "bundleName";
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_APP);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    EXPECT_CALL(*mockFormMgrService, GetFormsInfoByApp(_, _))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0061 ends";
}

/**
 * @tc.number: FormMgrStubTest_0062
 * @tc.name: Verify OnRemoteRequest and HandleGetFormsInfoByModule
 * @tc.desc: When the parameter code is FORM_MGR_GET_FORMS_INFO_BY_MODULE, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0062, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0062 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::string bundleName = "bundleName";
    const std::string moduleName = "moduleName";
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_MODULE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    data.WriteString(moduleName);
    EXPECT_CALL(*mockFormMgrService, GetFormsInfoByModule(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0062 ends";
}

/**
 * @tc.number: FormMgrStubTest_0063
 * @tc.name: Verify OnRemoteRequest and HandleGetFormsInfoByModule
 * @tc.desc: When the parameter code is FORM_MGR_GET_FORMS_INFO_BY_MODULE, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0063, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0063 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::string bundleName = "bundleName";
    const std::string moduleName = "moduleName";
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_MODULE);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    data.WriteString(moduleName);
    EXPECT_CALL(*mockFormMgrService, GetFormsInfoByModule(_, _, _))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0063 ends";
}

/**
 * @tc.number: FormMgrStubTest_0064
 * @tc.name: Verify OnRemoteRequest and HandleGetFormsInfo
 * @tc.desc: When the parameter code is FORM_MGR_GET_FORMS_INFO, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0064, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0064 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const FormInfoFilter filter = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&filter);
    EXPECT_CALL(*mockFormMgrService, GetFormsInfo(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0064 ends";
}

/**
 * @tc.number: FormMgrStubTest_0065
 * @tc.name: Verify OnRemoteRequest and HandleGetFormsInfo
 * @tc.desc: When the parameter code is FORM_MGR_GET_FORMS_INFO, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0065, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0065 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const FormInfoFilter filter = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&filter);
    EXPECT_CALL(*mockFormMgrService, GetFormsInfo(_, _))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0065 ends";
}

/**
 * @tc.number: FormMgrStubTest_0066
 * @tc.name: Verify OnRemoteRequest and HandleRouterEvent
 * @tc.desc: When the parameter code is FORM_MGR_ROUTER_EVENT, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0066, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0066 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ROUTER_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, RouterEvent(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0066 ends";
}

/**
 * @tc.number: FormMgrStubTest_0067
 * @tc.name: Verify OnRemoteRequest and HandleRouterEvent
 * @tc.desc: When the parameter code is FORM_MGR_ROUTER_EVENT, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0067, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0067 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const Want want = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ROUTER_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0067 ends";
}

/**
 * @tc.number: FormMgrStubTest_0068
 * @tc.name: Verify OnRemoteRequest and HandleRouterEvent
 * @tc.desc: When the parameter code is FORM_MGR_ROUTER_EVENT, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0068, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0068 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ROUTER_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0068 ends";
}

/**
 * @tc.number: FormMgrStubTest_0069
 * @tc.name: Verify OnRemoteRequest and HandleRequestPublishForm
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_PUBLISH_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0069, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0069 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const Want want = {};
    constexpr bool withFormBindingData = true;
    const FormProviderData formProviderData = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteBool(withFormBindingData);
    data.WriteParcelable(&formProviderData);
    EXPECT_CALL(*mockFormMgrService, RequestPublishForm(_, _, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0069 ends";
}

/**
 * @tc.number: FormMgrStubTest_0070
 * @tc.name: Verify OnRemoteRequest and HandleRequestPublishForm
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_PUBLISH_FORM, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0070, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0070 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const Want want = {};
    constexpr bool withFormBindingData = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteBool(withFormBindingData);
    EXPECT_CALL(*mockFormMgrService, RequestPublishForm(_, _, _, _))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0070 ends";
}

/**
 * @tc.number: FormMgrStubTest_0071
 * @tc.name: Verify OnRemoteRequest and HandleRequestPublishForm
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_PUBLISH_FORM, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0071, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0071 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0071 ends";
}

/**
 * @tc.number: FormMgrStubTest_0072
 * @tc.name: Verify OnRemoteRequest and HandleShareForm
 * @tc.desc: When the parameter code is FORM_MGR_SHARE_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0072, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0072 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const std::string deviceId = "ABCDEFG";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr int64_t requestCode = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_SHARE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteString(deviceId);
    data.WriteRemoteObject(callerToken);
    data.WriteInt64(requestCode);
    EXPECT_CALL(*mockFormMgrService, ShareForm(_, _, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0072 ends";
}

/**
 * @tc.number: FormMgrStubTest_0073
 * @tc.name: Verify OnRemoteRequest and HandleRecvFormShareInfoFromRemote
 * @tc.desc: When the parameter code is FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE, the interface return
 *           value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0073, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0073 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const FormShareInfo info = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&info);
    EXPECT_CALL(*mockFormMgrService, RecvFormShareInfoFromRemote(_)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0073 ends";
}

/**
 * @tc.number: FormMgrStubTest_0074
 * @tc.name: Verify OnRemoteRequest and HandleRecvFormShareInfoFromRemote
 * @tc.desc: When the parameter code is FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE, the interface return
 *           value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0074, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0074 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECV_FORM_SHARE_INFO_FROM_REMOTE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0074 ends";
}

/**
 * @tc.number: FormMgrStubTest_0075
 * @tc.name: Verify OnRemoteRequest and HandleIsRequestPublishFormSupported
 * @tc.desc: When the parameter code is FORM_MGR_IS_REQUEST_PUBLISH_FORM_SUPPORTED, the interface return
 *           value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0075, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0075 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_REQUEST_PUBLISH_FORM_SUPPORTED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    EXPECT_CALL(*mockFormMgrService, IsRequestPublishFormSupported()).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0075 ends";
}

/**
 * @tc.number: FormMgrStubTest_0076
 * @tc.name: Verify OnRemoteRequest and HandleStartAbility
 * @tc.desc: When the parameter code is FORM_MGR_START_ABILITY, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0076, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0076 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_ABILITY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, StartAbility(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0076 ends";
}

/**
 * @tc.number: FormMgrStubTest_0077
 * @tc.name: Verify OnRemoteRequest and HandleStartAbility
 * @tc.desc: When the parameter code is FORM_MGR_START_ABILITY, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0077, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0077 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const Want want = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_ABILITY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&want);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0077 ends";
}

/**
 * @tc.number: FormMgrStubTest_0078
 * @tc.name: Verify OnRemoteRequest and HandleStartAbility
 * @tc.desc: When the parameter code is FORM_MGR_START_ABILITY, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0078, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0078 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_ABILITY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0078 ends";
}

/**
 * @tc.number: FormMgrStubTest_0079
 * @tc.name: Verify OnRemoteRequest and HandleCheckFMSReady
 * @tc.desc: When the parameter code is FORM_MGR_CHECK_FMS_READY, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0079, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0079 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CHECK_FMS_READY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    EXPECT_CALL(*mockFormMgrService, CheckFMSReady()).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0079 ends";
}

/**
 * @tc.number: FormMgrStubTest_0080
 * @tc.name: Verify OnRemoteRequest and HandleCastTempForm
 * @tc.desc: When the parameter code is FORM_MGR_CAST_TEMP_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0080, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0080 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CAST_TEMP_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, CastTempForm(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0080 ends";
}

/**
 * @tc.number: FormMgrStubTest_0081
 * @tc.name: Verify OnRemoteRequest and HandleStopRenderingForm
 * @tc.desc: When the parameter code is FORM_MGR_STOP_RENDERING_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0081, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0081 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_STOP_RENDERING_FORM);
    constexpr int64_t formId = 1;
    const std::string compId = "ABC";
    MessageParcel data;
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteString(compId);
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    EXPECT_CALL(*mockFormMgrService, StopRenderingForm(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0081 ends";
}

/**
 * @tc.number: FormMgrStubTest_0082
 * @tc.name: Verify OnRemoteRequest
 * @tc.desc: When the parameter code is UINT32_MAX, the interface return value is
 *           IPC_STUB_UNKNOW_TRANS_ERR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0082, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0082 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = UINT32_MAX;
    constexpr int64_t formId = 1;
    const std::string compId = "ABC";
    MessageParcel data;
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteString(compId);
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0082 ends";
}

/**
 * @tc.number: FormMgrStubTest_0083
 * @tc.name: Verify OnRemoteRequest and HandleStopRenderingForm
 * @tc.desc: When the parameter code is FORM_MGR_ACQUIRE_DATA, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0083, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0083 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_DATA);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr int64_t formId = 1;
    constexpr int64_t requestCode = 1;
    MessageParcel data;
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteInt64(requestCode);
    data.WriteRemoteObject(callerToken);
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    EXPECT_CALL(*mockFormMgrService, AcquireFormData(_, _, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0083 ends";
}

/**
 * @tc.number: FormMgrStubTest_0084
 * @tc.name: Verify OnRemoteRequest
 * @tc.desc: When the parameter code is FORM_MGR_ACQUIRE_DATA + 1, the interface return value is
 *           IPC_STUB_UNKNOW_TRANS_ERR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0084, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0084 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ACQUIRE_DATA) + 500;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0084 ends";
}

/**
 * @tc.number: FormMgrStubTest_0085
 * @tc.name: Verify OnRemoteRequest
 * @tc.desc: When the parameter code is UINT32_MAX, the interface return value is
 *           IPC_STUB_UNKNOW_TRANS_ERR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0085, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0085 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE);
    const std::string bundleName = "ABC";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    MessageParcel data;
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    data.WriteRemoteObject(callerToken);
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0085 ends";
}

/**
 * @tc.number: FormMgrStubTest_0086
 * @tc.name: Verify OnRemoteRequest
 * @tc.desc: When the parameter code is UINT32_MAX, the interface return value is
 *           IPC_STUB_UNKNOW_TRANS_ERR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0086, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0086 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ADD_OBSERVER_BY_BUNDLE);
    const std::string bundleName = "ABC";
    MessageParcel data;
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0086 ends";
}

/**
 * @tc.number: FormMgrStubTest_0087
 * @tc.name: Verify OnRemoteRequest
 * @tc.desc: When the parameter code is UINT32_MAX, the interface return value is
 *           IPC_STUB_UNKNOW_TRANS_ERR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0087, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0087 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code =
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE);
    const std::string bundleName = "ABC";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    MessageParcel data;
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    data.WriteRemoteObject(callerToken);
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0087 ends";
}

/**
 * @tc.number: FormMgrStubTest_0088
 * @tc.name: Verify OnRemoteRequest
 * @tc.desc: When the parameter code is UINT32_MAX, the interface return value is
 *           IPC_STUB_UNKNOW_TRANS_ERR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0088, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0088 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code =
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_REMOVE_OBSERVER_BY_BUNDLE);
    const std::string bundleName = "ABC";
    MessageParcel data;
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0088 ends";
}

/**
 * @tc.number: FormMgrStubTest_0089
 * @tc.name: Verify OnRemoteRequest
 * @tc.desc: When the parameter code is UINT32_MAX, the interface return value is
 *           IPC_STUB_UNKNOW_TRANS_ERR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0089, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0089 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS);
    MessageParcel data;
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0089 ends";
}

/**
 * @tc.number: FormMgrStubTest_0090
 * @tc.name: Verify OnRemoteRequest
 * @tc.desc: When the parameter code is UINT32_MAX, the interface return value is
 *           IPC_STUB_UNKNOW_TRANS_ERR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0090, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0090 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_RUNNING_FORM_INFOS_BY_BUNDLE);
    MessageParcel data;
    const std::string bundleName = "ABC";
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0090 ends";
}

/**
 * @tc.number: FormMgrStubTest_0091
 * @tc.name: Verify OnRemoteRequest and HandleUpdateProxyForm
 * @tc.desc: When the parameter code is FORM_MGR_UPDATE_PROXY_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0091, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0091 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    const FormProviderData formProviderData = {};
    std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0091");
    formDataProxies.push_back(formDataProxy);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_PROXY_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteParcelable(&formProviderData);
    WriteFormDataProxies(data, formDataProxies);
    EXPECT_CALL(*mockFormMgrService, UpdateProxyForm(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0091 ends";
}

/**
 * @tc.number: FormMgrStubTest_0092
 * @tc.name: Verify OnRemoteRequest and HandleRequestPublishProxyForm
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_PUBLISH_PROXY_FORM, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0092, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0092 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const Want want = {};
    constexpr bool withFormBindingData = true;
    const FormProviderData formProviderData = {};
        std::vector<FormDataProxy> formDataProxies;
    FormDataProxy formDataProxy("test", "0092");
    formDataProxies.push_back(formDataProxy);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_PROXY_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteBool(withFormBindingData);
    data.WriteParcelable(&formProviderData);
    WriteFormDataProxies(data, formDataProxies);
    EXPECT_CALL(*mockFormMgrService, RequestPublishProxyForm(_, _, _, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0092 ends";
}

/**
 * @tc.number: FormMgrStubTest_0093
 * @tc.name: Verify OnRemoteRequest and HandleRegisterFormRouterProxy
 * @tc.desc: When the parameter code is FORM_MGR_REGISTER_FORM_ROUTER_PROXY, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0093, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0093 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ROUTER_PROXY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, RegisterFormRouterProxy(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0093 ends";
}

/**
 * @tc.number: FormMgrStubTest_0094
 * @tc.name: Verify OnRemoteRequest and HandleRegisterFormRouterProxy
 * @tc.desc: When the parameter code is FORM_MGR_REGISTER_FORM_ROUTER_PROXY, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0094, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0094 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ROUTER_PROXY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0094 ends";
}

/**
 * @tc.number: FormMgrStubTest_0095
 * @tc.name: Verify OnRemoteRequest and HandleLifecycleUpdate
 * @tc.desc: When the parameter code is FORM_MGR_REGISTER_FORM_ROUTER_PROXY, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0095, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0095 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_FORM_ROUTER_PROXY);
    constexpr int32_t valueCode = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt32(valueCode);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0095 ends";
}

/**
 * @tc.number: FormMgrStubTest_0096
 * @tc.name: Verify OnRemoteRequest and HandleUnregisterFormRouterProxy
 * @tc.desc: When the parameter code is FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0096, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0096 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64Vector(formIds);
    EXPECT_CALL(*mockFormMgrService, UnregisterFormRouterProxy(_)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0096 ends";
}

/**
 * @tc.number: FormMgrStubTest_0097
 * @tc.name: Verify OnRemoteRequest and HandleUnregisterFormRouterProxy
 * @tc.desc: When the parameter code is FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0097, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0097 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_FORM_ROUTER_PROXY);
    constexpr int32_t valueCode = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt32(valueCode);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0097 ends";
}

/**
 * @tc.number: FormMgrStubTest_0098
 * @tc.name: HandleGetFormInstancesByFilter
 * @tc.desc: return ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0098, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0098 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    FormInstancesFilter formInstancesFilter;
    std::string bundleName = "com.example.test";
    formInstancesFilter.bundleName = bundleName;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_FILTER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&formInstancesFilter);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0098 ends";
}

/**
 * @tc.number: FormMgrStubTest_0099
 * @tc.name: HandleGetFormInstancesByFilter
 * @tc.desc: return ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0099, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0099 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_FILTER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0099 ends";
}

/**
 * @tc.number: FormMgrStubTest_0100
 * @tc.name: HandleGetFormInstancesById
 * @tc.desc: return ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0100, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0100 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORM_INSTANCES_FROM_BY_ID);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(0);
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0100 ends";
}

/**
 * @tc.name: HandleGetFormInstanceById_0100
 * @tc.desc: Verify that the return value and the size of resultInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrStubTest, HandleGetFormInstanceById_0100, TestSize.Level1) {
    GTEST_LOG_(INFO) << "HandleGetFormInstanceById_0100 starts";
    MessageParcel data;
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, GetFormInstanceById(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->HandleGetFormInstanceById(data, reply);
    std::vector<FormInfo> resultInfos;
    GetParcelableInfos(reply, resultInfos);
    EXPECT_EQ(resultInfos.size(), 0);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "HandleGetFormInstanceById_0100 ends";
}

/**
 * @tc.name: HandleGetRunningFormInfos_0100
 * @tc.desc: Verify that the return value and the size of resultInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrStubTest, HandleGetRunningFormInfos_0100, TestSize.Level1) {
    GTEST_LOG_(INFO) << "HandleGetRunningFormInfos_0100 starts";
    MessageParcel data;
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, GetRunningFormInfos(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->HandleGetRunningFormInfos(data, reply);
    std::vector<FormInfo> resultInfos;
    GetParcelableInfos(reply, resultInfos);
    EXPECT_EQ(resultInfos.size(), 0);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "HandleGetRunningFormInfos_0100 ends";
}

/**
 * @tc.number: HandleUpdateFormLocation_0100
 * @tc.name: test UpdateFormLocation function.
 * @tc.desc: Verify that the UpdateFormLocation interface is called normally
 * and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, HandleUpdateFormLocation_0100, TestSize.Level1) {
    GTEST_LOG_(INFO) << "HandleUpdateFormLocation_0100 starts";
    MessageParcel data;
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, UpdateFormLocation(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(ERR_OK, mockFormMgrService->HandleUpdateFormLocation(data, reply));
    GTEST_LOG_(INFO) << "HandleUpdateFormLocation_0100 ends";
}

/**
 * @tc.name: HandleGetRunningFormInfosByBundleName_0100
 * @tc.desc: Verify that the return value and the size of resultInfos
 * @tc.type: FUNC
 */
HWTEST_F(FormMgrStubTest, HandleGetRunningFormInfosByBundleName_0100, TestSize.Level1) {
    GTEST_LOG_(INFO) << "HandleGetRunningFormInfosByBundleName_0100 starts";
    MessageParcel data;
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, GetRunningFormInfosByBundleName(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->HandleGetRunningFormInfosByBundleName(data, reply);
    std::vector<FormInfo> resultInfos;
    GetParcelableInfos(reply, resultInfos);
    EXPECT_EQ(resultInfos.size(), 0);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "HandleGetRunningFormInfosByBundleName_0100 ends";
}

/**
 * @tc.number: FormMgrStubTest_0101
 * @tc.name: Verify OnRemoteRequest and HandleGetFormsInfoByFilter
 * @tc.desc: When the parameter code is FORM_MGR_GET_FORMS_INFO_BY_FILTER, the interface return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0101, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0101 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::string bundleName = "bundleName";
    const std::string moduleName = "moduleName";
    std::vector<int32_t> supportDimensions{1, 2};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO_BY_FILTER);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteString(bundleName);
    data.WriteString(moduleName);
    data.WriteInt32Vector(supportDimensions);
    EXPECT_CALL(*mockFormMgrService, GetFormsInfoByFilter(_, _))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0101 ends";
}

/**
 * @tc.number: FormMgrStubTest_0102
 * @tc.name: test SetPublishFormResult function.
 * @tc.desc: Verify that the SetPublishFormResult interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0102, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0102 starts";
    MessageParcel data;
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, SetPublishFormResult(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->HandleSetPublishFormResult(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0102 ends";
}

/**
 * @tc.number: FormMgrStubTest_0103
 * @tc.name: test AcquireAddFormResult function.
 * @tc.desc: Verify that the AcquireAddFormResult interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0103, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0103 starts";
    MessageParcel data;
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, AcquireAddFormResult(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->HandleAcquireAddFormResult(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0103 ends";
}

/**
 * @tc.number: FormMgrStubTest_0104
 * @tc.name: Verify OnRemoteRequest and HandleRequestPublishFormWithSnapshot
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT, the interface return
 *           value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0104, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0104 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const Want want = {};
    constexpr bool withFormBindingData = true;
    const FormProviderData formProviderData = {};
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteBool(withFormBindingData);
    data.WriteParcelable(&formProviderData);
    EXPECT_CALL(*mockFormMgrService, RequestPublishFormWithSnapshot(_, _, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0104 ends";
}

/**
 * @tc.number: FormMgrStubTest_0105
 * @tc.name: Verify OnRemoteRequest and HandleRequestPublishFormWithSnapshot
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT, the interface
 *           return value is ERR_OK + 1.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0105, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0105 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const Want want = {};
    constexpr bool withFormBindingData = false;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT);
    constexpr int32_t errorCode = ERR_OK + 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteBool(withFormBindingData);
    EXPECT_CALL(*mockFormMgrService, RequestPublishFormWithSnapshot(_, _, _, _))
        .Times(1)
        .WillOnce(Return(errorCode));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, errorCode);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0105 ends";
}

/**
 * @tc.number: FormMgrStubTest_0106
 * @tc.name: Verify OnRemoteRequest and HandleRequestPublishFormWithSnapshot
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT, the interface return value is
 *           ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0106, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0106 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0106 ends";
}

/**
 * @tc.number: FormMgrStubTest_0107
 * @tc.name: test HandleRegisterPublishFormInterceptor function.
 * @tc.desc: Verify that the HandleRegisterPublishFormInterceptor interface is called normally
 *           and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0107, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0107 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_PUBLISH_FORM_INTERCEPTOR);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, RegisterPublishFormInterceptor(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0107 ends";
}

/**
 * @tc.number: FormMgrStubTest_0108
 * @tc.name: test HandleUnregisterPublishFormInterceptor function.
 * @tc.desc: Verify that the HandleUnregisterPublishFormInterceptor interface is called normally
 *           and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0108, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0108 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_PUBLISH_FORM_INTERCEPTOR);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, UnregisterPublishFormInterceptor(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0108 ends";
}

/**
 * @tc.number: FormMgrStubTest_0109
 * @tc.name: test HandleRegisterClickCallbackEventObserver function.
 * @tc.desc: Verify that the HandleRegisterClickCallbackEventObserver interface is called normally
 *           and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0109, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0109 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_CLICK_EVENT_OBSERVER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    const std::string formEventType = "formEventType";
    data.WriteString(formEventType);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, RegisterClickEventObserver(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0109 ends";
}

/**
 * @tc.number: FormMgrStubTest_0110
 * @tc.name: test HandleUnregisterClickCallbackEventObserver function.
 * @tc.desc: Verify that the HandleUnregisterClickCallbackEventObserver interface is called normally
 *           and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0110, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0110 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_CLICK_EVENT_OBSERVER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    const std::string formEventType = "formEventType";
    data.WriteString(formEventType);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, UnregisterClickEventObserver(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0110 ends";
}

/**
 * @tc.number: FormMgrStubTest_0111
 * @tc.name: test HandleRegisterAddObserver function.
 * @tc.desc: Verify that the HandleRegisterAddObserver interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0111, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0111 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_ADD_OBSERVER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, RegisterAddObserver(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0111 ends";
}

/**
 * @tc.number: FormMgrStubTest_0112
 * @tc.name: test HandleRegisterRemoveObserver function.
 * @tc.desc: Verify that the HandleRegisterRemoveObserver interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0112, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0112 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_REMOVE_OBSERVER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, RegisterRemoveObserver(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0112 ends";
}

/**
 * @tc.number: FormMgrStubTest_0113
 * @tc.name: test HandleRegisterRemoveObserver function.
 * @tc.desc: Verify that the HandleRegisterRemoveObserver interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0113, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0113 starts";
    MessageParcel data;
    MessageParcel reply;
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, RegisterRemoveObserver(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->HandleRegisterRemoveObserver(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0113 ends";
}

/**
 * @tc.number: FormMgrStubTest_0114
 * @tc.name: test HandleSetFormsRecyclable function.
 * @tc.desc: Verify that the HandleSetFormsRecyclable interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0114, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0114 starts";
    MessageParcel data;
    MessageParcel reply;
    std::vector<int64_t> formIds;
    data.WriteInt64Vector(formIds);
    EXPECT_CALL(*mockFormMgrService, SetFormsRecyclable(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->HandleSetFormsRecyclable(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0114 ends";
}

/**
 * @tc.number: FormMgrStubTest_0115
 * @tc.name: test HandleRecycleForms function.
 * @tc.desc: Verify that the HandleRecycleForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0115, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0115 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECYCLE_FORMS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const Want want = {};
    data.WriteParcelable(&want);
    EXPECT_CALL(*mockFormMgrService, RecycleForms(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0115 ends";
}

/**
 * @tc.number: FormMgrStubTest_0116
 * @tc.name: test HandleRecoverForms function.
 * @tc.desc: Verify that the HandleRecoverForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0116, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0116 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RECOVER_FORMS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const Want want = {};
    data.WriteParcelable(&want);
    EXPECT_CALL(*mockFormMgrService, RecoverForms(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0116 ends";
}


/**
 * @tc.number: FormMgrStubTest_0117
 * @tc.name: Verify OnRemoteRequest and HandleBackgroundEvent function.
 * @tc.desc: Verify that the HandleBackgroundEvent interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0117, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0117 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_BACKGROUND_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    int64_t formId = 1;
    data.WriteInt64(formId);
    const Want want = {};
    data.WriteParcelable(&want);
    const sptr<IRemoteObject> client = new (std::nothrow) MockFormToken();
    data.WriteRemoteObject(client);
    EXPECT_CALL(*mockFormMgrService, BackgroundEvent(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0117 ends";
}

/**
 * @tc.number: FormMgrStubTest_0118
 * @tc.name: Verify OnRemoteRequest and HandleGetFormsCount function.
 * @tc.desc: Verify that the HandleGetFormsCount interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0118, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0118 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_COUNT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    bool isTempFormFlag = false;
    data.WriteBool(isTempFormFlag);
    EXPECT_CALL(*mockFormMgrService, GetFormsCount(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0118 ends";
}

/**
 * @tc.number: FormMgrStubTest_0119
 * @tc.name: Verify OnRemoteRequest and HandleGetHostFormsCount function.
 * @tc.desc: Verify that the HandleGetHostFormsCount interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0119, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0119 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_HOST_FORMS_COUNT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    EXPECT_CALL(*mockFormMgrService, GetHostFormsCount(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0119 ends";
}

/**
 * @tc.number: FormMgrStubTest_0120
 * @tc.name: Verify OnRemoteRequest and HandleStartAbilityByFms function.
 * @tc.desc: Verify that the HandleStartAbilityByFms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0120, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0120 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_ABILITY_BY_FMS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const Want want = {};
    data.WriteParcelable(&want);
    EXPECT_CALL(*mockFormMgrService, StartAbilityByFms(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0120 ends";
}

/**
 * @tc.number: FormMgrStubTest_0121
 * @tc.name: Verify OnRemoteRequest and HandleIsFormProtected function.
 * @tc.desc: Verify that the HandleIsFormProtected interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0121, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0121 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_PEOTECTED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    const int64_t formId = 1;
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, IsFormBundleProtected(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0121 ends";
}

/**
 * @tc.number: FormMgrStubTest_0122
 * @tc.name: Verify OnRemoteRequest and HandleIsFormExempt function.
 * @tc.desc: Verify that the HandleIsFormExempt interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0122, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0122 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_FORM_BUNDLE_EXEMPT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const int64_t formId = 1;
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, IsFormBundleExempt(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0122 ends";
}

/**
 * @tc.number: FormMgrStubTest_0123
 * @tc.name: Verify OnRemoteRequest and HandleNotifyFormLocked function.
 * @tc.desc: Verify that the HandleNotifyFormLocked interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0123, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0123 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_NOTIFY_FORM_LOCKED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const int64_t formId = 1;
    data.WriteInt64(formId);
    const bool isLocked = true;
    data.WriteBool(isLocked);
    EXPECT_CALL(*mockFormMgrService, NotifyFormLocked(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0123 ends";
}


/**
 * @tc.number: FormMgrStubTest_0124
 * @tc.name: Verify OnRemoteRequest and HandleUpdateFormSize function.
 * @tc.desc: Verify that the HandleUpdateFormSize interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0124, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0124 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_FORM_SIZE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const int64_t formId = 1;
    data.WriteInt64(formId);
    const float width = 1.1;
    data.WriteFloat(width);
    const float height = 1.1;
    data.WriteFloat(height);
    const float borderWidth = 1.1;
    data.WriteFloat(borderWidth);
    EXPECT_CALL(*mockFormMgrService, UpdateFormSize(_, _, _, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0124 ends";
}


/**
 * @tc.number: FormMgrStubTest_0125
 * @tc.name: Verify OnRemoteRequest and HandleLockForms function.
 * @tc.desc: Verify that the HandleLockForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0125, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0125 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_LOCK_FORMS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const int32_t infoSize = 1;
    data.WriteInt32(infoSize);
    const int32_t dataValue = 0;
    data.WriteInt32(dataValue);
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0125 ends";
}

/**
 * @tc.number: FormMgrStubTest_0126
 * @tc.name: Verify OnRemoteRequest and HandleLockForms function.
 * @tc.desc: Verify that the HandleLockForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0126, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0126 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_LOCK_FORMS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const int32_t infoSize = 1;
    data.WriteInt32(infoSize);
    const int32_t dataValue = -1;
    data.WriteInt32(dataValue);
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0126 ends";
}

/**
 * @tc.number: FormMgrStubTest_0127
 * @tc.name: Verify OnRemoteRequest and HandleOpenFormEditAbility function.
 * @tc.desc: Verify that the HandleOpenFormEditAbility interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0127, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0127 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_OPEN_FORM_EDIT_ABILITY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const std::string abilityName = "abilityName";
    data.WriteString(abilityName);
    const int64_t formId = 1;
    data.WriteInt64(formId);
    const bool isMainPage = true;
    data.WriteBool(isMainPage);
    EXPECT_CALL(*mockFormMgrService, OpenFormEditAbility(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0127 ends";
}

/**
 * @tc.number: FormMgrStubTest_0131
 * @tc.name: Verify OnRemoteRequest and HandleGetPublishedFormInfoById function.
 * @tc.desc: Verify that the HandleGetPublishedFormInfoById interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0131, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0131 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFO_BY_ID);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    const int64_t formId = 1;
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, GetPublishedFormInfoById(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0131 ends";
}

/**
 * @tc.number: FormMgrStubTest_0132
 * @tc.name: Verify OnRemoteRequest and HandleGetPublishedFormInfos function.
 * @tc.desc: Verify that the HandleGetPublishedFormInfos interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0132, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0132 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFOS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    EXPECT_CALL(*mockFormMgrService, GetPublishedFormInfos(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0132 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleIsFormBundleForbidden_001
 * @tc.name: test HandleIsFormBundleForbidden function.
 * @tc.desc: Verify that the HandleIsFormBundleForbidden interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleIsFormBundleForbidden_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleIsFormBundleForbidden_001 starts";
    MessageParcel data;
    MessageParcel reply;
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    EXPECT_EQ(mockFormMgrService->HandleIsFormBundleForbidden(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleIsFormBundleForbidden_001 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleBatchRefreshForms_001
 * @tc.name: test HandleBatchRefreshForms function.
 * @tc.desc: Verify that the HandleBatchRefreshForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleBatchRefreshForms_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleBatchRefreshForms_001 starts";
    MessageParcel data;
    MessageParcel reply;
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    EXPECT_CALL(*mockFormMgrService, BatchRefreshForms(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->HandleBatchRefreshForms(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleBatchRefreshForms_001 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleEnableForms_001
 * @tc.name: test HandleEnableForms function.
 * @tc.desc: Verify that the HandleEnableForms interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleEnableForms_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleEnableForms_001 starts";
    MessageParcel data;
    MessageParcel reply;
    const std::string bundleName = "bundleName";
    const int32_t userId = 100;
    data.WriteString(bundleName);
    data.WriteInt32(userId);
    data.WriteBool(true);
    EXPECT_CALL(*mockFormMgrService, EnableForms(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->HandleEnableForms(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleEnableForms_001 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleReleaseRenderer_001
 * @tc.name: test HandleReleaseRenderer function.
 * @tc.desc: Verify that the HandleReleaseRenderer interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleReleaseRenderer_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleReleaseRenderer_001 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELEASE_RENDERER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    constexpr int64_t formId = 1;
    data.WriteInt64(formId);
    const std::string compId = "compId";
    data.WriteString(compId);
    EXPECT_CALL(*mockFormMgrService, ReleaseRenderer(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->OnRemoteRequest(code, data, reply, option), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleReleaseRenderer_001 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleHasFormVisible_001
 * @tc.name: test HandleHasFormVisible function.
 * @tc.desc: Verify that the HandleHasFormVisible interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleHasFormVisible_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleHasFormVisible_001 starts";
    MessageParcel data;
    MessageParcel reply;
    constexpr int64_t tokenId = 1;
    data.WriteInt64(tokenId);
    EXPECT_CALL(*mockFormMgrService, HasFormVisible(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->HandleHasFormVisible(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleHasFormVisible_001 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleCreateForm_001
 * @tc.name: test HandleCreateForm function.
 * @tc.desc: Verify that the HandleCreateForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleCreateForm_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleCreateForm_001 starts";
    MessageParcel data;
    MessageParcel reply;
    const Want want = {};
    data.WriteParcelable(&want);
    EXPECT_CALL(*mockFormMgrService, CreateForm(_, _)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->HandleCreateForm(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleCreateForm_001 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleCreateForm_001
 * @tc.name: test HandleCreateForm function.
 * @tc.desc: Verify that the HandleCreateForm interface is called with null want
 *           and the return value is ERR_APPEXECFWK_PARCEL_ERROR.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleCreateForm_002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleCreateForm_002 starts";
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(mockFormMgrService->HandleCreateForm(data, reply), ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleCreateForm_002 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleIsSystemAppForm_001
 * @tc.name: test HandleIsSystemAppForm function.
 * @tc.desc: Verify that the HandleIsSystemAppForm interface is called normally and the return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleIsSystemAppForm_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleIsSystemAppForm_001 starts";
    MessageParcel data;
    MessageParcel reply;
    const std::string bundleName = "bundleName";
    data.WriteString(bundleName);
    EXPECT_CALL(*mockFormMgrService, IsSystemAppForm(_)).Times(1).WillOnce(Return(ERR_OK));
    EXPECT_EQ(mockFormMgrService->HandleIsSystemAppForm(data, reply), ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleIsSystemAppForm_001 ends";
}


/**
 * @tc.number: FormMgrStubTest_0133
 * @tc.name: Verify OnRemoteRequest and HandleRequestOverflow
 * @tc.desc: When the parameter code is FORM_MGR_REQUEST_OVERFLOW, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0133, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0133 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    OverflowInfo overflowInfo;
    overflowInfo.area.left = -30;
    overflowInfo.area.top = -30;
    overflowInfo.area.width = 200;
    overflowInfo.area.height = 200;
    overflowInfo.duration = 3500;
    bool isOverflow = true;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_OVERFLOW);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteBool(isOverflow);
    data.WriteParcelable(&overflowInfo);
    EXPECT_CALL(*mockFormMgrService, RequestOverflow(_, _, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0133 ends";
}
 
/**
 * @tc.number: FormMgrStubTest_0133
 * @tc.name: Verify OnRemoteRequest and HandleChangeSceneAnimationState
 * @tc.desc: When the parameter code is FORM_MGR_CHANGE_SCENE_ANIMATION_STATE, the interface return value is ERR_OK.
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0134, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0134 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    int32_t state = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CHANGE_SCENE_ANIMATION_STATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormMgrService::GetDescriptor());
    data.WriteInt64(formId);
    data.WriteInt32(state);
    EXPECT_CALL(*mockFormMgrService, ChangeSceneAnimationState(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0134 ends";
}

/**
 * @tc.number: FormMgrStubTest_0135
 * @tc.name: Verify OnRemoteRequest and HandleRegisterGetFormRectProxy
 * @tc.desc: test HandleRegisterGetFormRectProxy
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0135, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0135 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    MessageParcel data;
    MessageParcel reply;
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, RegisterGetFormRectProxy(_))
        .Times(1)
        .WillOnce(Return(true));
    auto result = mockFormMgrService->HandleRegisterGetFormRectProxy(data, reply);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0135 ends";
}

/**
 * @tc.number: FormMgrStubTest_0136
 * @tc.name: Verify OnRemoteRequest and HandleUnregisterGetFormRectProxy
 * @tc.desc: test HandleUnregisterGetFormRectProxy
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0136, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0136 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, UnregisterGetFormRectProxy())
        .Times(1)
        .WillOnce(Return(true));
    auto result = mockFormMgrService->HandleUnregisterGetFormRectProxy(data, reply);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0136 ends";
}

/**
 * @tc.number: FormMgrStubTest_0137
 * @tc.name: Verify OnRemoteRequest and HandleGetFormRect
 * @tc.desc: test HandleGetFormRect
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0137, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0137 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    constexpr int64_t formId = 1;
    Rect rect;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt64(formId);
    EXPECT_CALL(*mockFormMgrService, GetFormRect(_, _)).Times(1).WillOnce(Return(ERR_OK));
    auto result = mockFormMgrService->HandleGetFormRect(data, reply);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0137 ends";
}

/**
 * @tc.number: FormMgrStubTest_0138
 * @tc.name: Verify OnRemoteRequest and HandleRegisterGetLiveFormStatusProxy
 * @tc.desc: test HandleRegisterGetLiveFormStatusProxy
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0138, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0138 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormToken();
    MessageParcel data;
    MessageParcel reply;
    data.WriteRemoteObject(callerToken);
    EXPECT_CALL(*mockFormMgrService, RegisterGetLiveFormStatusProxy(_))
        .Times(1)
        .WillOnce(Return(true));
    auto result = mockFormMgrService->HandleRegisterGetLiveFormStatusProxy(data, reply);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0138 ends";
}

/**
 * @tc.number: FormMgrStubTest_0139
 * @tc.name: Verify OnRemoteRequest and HandleUnregisterGetLiveFormStatusProxy
 * @tc.desc: test HandleUnregisterGetLiveFormStatusProxy
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_0139, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_0139 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    const std::vector<int64_t> formIds;
    MessageParcel data;
    MessageParcel reply;
    EXPECT_CALL(*mockFormMgrService, UnregisterGetLiveFormStatusProxy())
        .Times(1)
        .WillOnce(Return(true));
    auto result = mockFormMgrService->HandleUnregisterGetLiveFormStatusProxy(data, reply);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_0139 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleReloadForms_001
 * @tc.name: Verify OnRemoteRequest and HandleReloadForms
 * @tc.desc: test HandleReloadForms
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleReloadForms_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleReloadForms_001 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    EXPECT_CALL(*mockFormMgrService, ReloadForms(_, _, _, _))
        .Times(1)
        .WillOnce(Return(ERR_OK));
    const std::string moduleName = "A";
    const std::string abilityName = "B";
    const std::string formName = "C";
    MessageParcel data;
    MessageParcel reply;
    data.WriteString(moduleName);
    data.WriteString(abilityName);
    data.WriteString(formName);
    auto result = mockFormMgrService->HandleReloadForms(data, reply);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleReloadForms_001 ends";
}

/**
 * @tc.number: FormMgrStubTest_HandleReloadAllForms_001
 * @tc.name: Verify OnRemoteRequest and HandleReloadAllForms
 * @tc.desc: test HandleReloadAllForms
 */
HWTEST_F(FormMgrStubTest, FormMgrStubTest_HandleReloadAllForms_001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleReloadAllForms_001 starts";
    EXPECT_TRUE(mockFormMgrService != nullptr);
    EXPECT_CALL(*mockFormMgrService, ReloadAllForms(_))
        .Times(1)
        .WillOnce(Return(ERR_OK));
    MessageParcel data;
    MessageParcel reply;
    auto result = mockFormMgrService->HandleReloadAllForms(data, reply);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormMgrStubTest_HandleReloadAllForms_001 ends";
}
}