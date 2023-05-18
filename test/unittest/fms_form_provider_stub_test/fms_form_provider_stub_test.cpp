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
#define private public
#define protected public
#include "appexecfwk_errors.h"
#include "element_name.h"
#include "form_mgr_errors.h"
#include "form_provider_stub.h"
#include "form_supply_interface.h"
#include "form_supply_stub.h"
#include "mock_form_token.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "message_parcel.h"
#include "mock_form_provider_client.h"
#undef private
#undef protected
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FormProviderStubTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormProviderStubTest::SetUpTestCase()
{}

void FormProviderStubTest::TearDownTestCase()
{}

void FormProviderStubTest::SetUp()
{}

void FormProviderStubTest::TearDown()
{}

class MockFormSupplyStub : public FormSupplyStub {
public:
    MockFormSupplyStub() {};
    virtual ~MockFormSupplyStub() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return number_;
    };
    int HandleOnAcquire(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int HandleOnEventHandle(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int HandleOnAcquireStateResult(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int32_t HandleOnShareAcquire(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override
    {
        return number_;
    };
    int OnEventHandle(const Want &want) override
    {
        return number_;
    };
    int OnAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg,
        const Want &want) override
    {
        return number_;
    };
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    };
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode) override
    {
        return ERR_OK;
    };
    const int number_ = 1;
};
/**
 * @tc.name: FormProviderStubTest_001
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_001, TestSize.Level0)
{
    MockFormProviderClient callback;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormProviderStubTest_002
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_002, TestSize.Level0)
{
    MockFormProviderClient callback;
    uint32_t code = 2;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormProviderStubTest_003
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_003, TestSize.Level0)
{
    MockFormProviderClient callback;
    uint32_t code = 3;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormProviderStubTest_004
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_004, TestSize.Level0)
{
    MockFormProviderClient callback;
    uint32_t code = 4;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormProviderStubTest_005
 * @tc.desc: 1.Verify that the OnRemoteRequest interface executes as expected.
 *           2.The interface return value IPC_STUB_UNKNOW_TRANS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_005, TestSize.Level1)
{
    MockFormProviderClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FORM_INFO) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormProviderStubTest_006
 * @tc.desc: 1.Verify that the OnRemoteRequest interface executes as expected.
 *           2.The interface return value IPC_STUB_UNKNOW_TRANS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_006, TestSize.Level1)
{
    MockFormProviderClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FORM_INFO) + 100;
    callback.memberFuncMap_[code] = nullptr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormProviderStubTest_007
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireProviderFormInfo interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_007 start";
    const FormJsInfo formJsInfo = {};
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FORM_INFO);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteParcelable(&formJsInfo);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_007 end";
}

/**
 * @tc.name: FormProviderStubTest_008
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireProviderFormInfo interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_008 start";
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FORM_INFO);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_008 end";
}

/**
 * @tc.name: FormProviderStubTest_009
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireProviderFormInfo interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_009 start";
    const FormJsInfo formJsInfo = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FORM_INFO);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteParcelable(&formJsInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_009 end";
}

/**
 * @tc.name: FormProviderStubTest_010
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireProviderFormInfo interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_010 start";
    const FormJsInfo formJsInfo = {};
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FORM_INFO);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteParcelable(&formJsInfo);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_010 end";
}

/**
 * @tc.name: FormProviderStubTest_011
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormDelete interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_011 start";
    const int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORM_DELETE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_011 end";
}

/**
 * @tc.name: FormProviderStubTest_012
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormDelete interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_012 start";
    const int64_t formId = 1;
    const Want want = {};
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORM_DELETE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_012 end";
}

/**
 * @tc.name: FormProviderStubTest_013
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormDelete interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_013 start";
    const int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORM_DELETE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_013 end";
}

/**
 * @tc.name: FormProviderStubTest_014
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormsDelete interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_014 start";
    const std::vector<int64_t> formIds;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORMS_DELETE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64Vector(formIds);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_014 end";
}

/**
 * @tc.name: FormProviderStubTest_015
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormsDelete interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_015 start";
    const std::vector<int64_t> formIds;
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORMS_DELETE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64Vector(formIds);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_015 end";
}

/**
 * @tc.name: FormProviderStubTest_016
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormsDelete interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_016 start";
    const std::vector<int64_t> formIds;
    const Want want = {};
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORMS_DELETE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64Vector(formIds);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_016 end";
}

/**
 * @tc.name: FormProviderStubTest_017
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormsDelete interface executes as expected.
 *           2.The interface return value ERR_INVALID_DATA.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_017 start";
    const int64_t number = -1;
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORMS_DELETE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(number);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
    GTEST_LOG_(INFO) << "FormProviderStubTest_017 end";
}

/**
 * @tc.name: FormProviderStubTest_018
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormUpdate interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_018 start";
    const int64_t formId = 1;
    const Want want = {};
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORM_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_018 end";
}

/**
 * @tc.name: FormProviderStubTest_019
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormUpdate interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_019 start";
    const int64_t formId = 1;
    const Want want = {};
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORM_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_019 end";
}

/**
 * @tc.name: FormProviderStubTest_020
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormUpdate interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_020 start";
    const int64_t formId = 1;
    const Want want = {};
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_FORM_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_020 end";
}

/**
 * @tc.name: FormProviderStubTest_021
 * @tc.desc: Verify OnRemoteRequest and HandleEventNotify interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_021 start";
    const int32_t formVisibleType = 1;
    const Want want = {};
    std::vector<int64_t> formIds;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_EVENT_NOTIFY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64Vector(formIds);
    data.WriteInt32(formVisibleType);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_021 end";
}

/**
 * @tc.name: FormProviderStubTest_022
 * @tc.desc: Verify OnRemoteRequest and HandleEventNotify interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_022 start";
    std::vector<int64_t> formIds;
    const int32_t formVisibleType = 1;
    const Want want = {};
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_EVENT_NOTIFY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64Vector(formIds);
    data.WriteInt32(formVisibleType);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_022 end";
}

/**
 * @tc.name: FormProviderStubTest_023
 * @tc.desc: Verify OnRemoteRequest and HandleEventNotify interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_023 start";
    std::vector<int64_t> formIds;
    const int32_t formVisibleType = 1;
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_EVENT_NOTIFY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64Vector(formIds);
    data.WriteInt32(formVisibleType);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_023 end";
}

/**
 * @tc.name: FormProviderStubTest_024
 * @tc.desc: Verify OnRemoteRequest and HandleEventNotify interface executes as expected.
 *           2.The interface return value ERR_INVALID_DATA.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_024 start";
    const Want want = {};
    std::vector<int64_t> formIds;
    const int64_t number = -1;
    const int32_t formVisibleType = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_EVENT_NOTIFY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(number);
    data.WriteInt64Vector(formIds);
    data.WriteInt32(formVisibleType);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
    GTEST_LOG_(INFO) << "FormProviderStubTest_024 end";
}

/**
 * @tc.name: FormProviderStubTest_025
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormCastTempForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_025 start";
    const Want want = {};
    const int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_TEMP_FORM_CAST);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_025 end";
}

/**
 * @tc.name: FormProviderStubTest_026
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormCastTempForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_026 start";
    const int64_t formId = 1;
    const Want want = {};
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_TEMP_FORM_CAST);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_026 end";
}

/**
 * @tc.name: FormProviderStubTest_027
 * @tc.desc: Verify OnRemoteRequest and HandleNotifyFormCastTempForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_027 start";
    const int64_t formId = 1;
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_TEMP_FORM_CAST);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_027 end";
}

/**
 * @tc.name: FormProviderStubTest_028
 * @tc.desc: Verify OnRemoteRequest and HandleFireFormEvent interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_028 start";
    const Want want = {};
    const int64_t formId = 1;
    const std::string message = "";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_EVENT_MESSAGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteString(message);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_028 end";
}

/**
 * @tc.name: FormProviderStubTest_029
 * @tc.desc: Verify OnRemoteRequest and HandleFireFormEvent interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_029, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_029 start";
    const int64_t formId = 1;
    const std::string message = "";
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_EVENT_MESSAGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteString(message);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_029 end";
}

/**
 * @tc.name: FormProviderStubTest_030
 * @tc.desc: Verify OnRemoteRequest and HandleFireFormEvent interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_030, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_030 start";
    const Want want = {};
    const int64_t formId = 1;
    const std::string message = "";
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_EVENT_MESSAGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteString(message);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_030 end";
}

/**
 * @tc.name: FormProviderStubTest_031
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireState interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_031, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_031 start";
    const Want want = {};
    const std::string provider = "";
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_STATE_ACQUIRE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteParcelable(&want);
    data.WriteString(provider);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_031 end";
}

/**
 * @tc.name: FormProviderStubTest_032
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireState interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_032, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_032 start";
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_STATE_ACQUIRE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_032 end";
}

/**
 * @tc.name: FormProviderStubTest_033
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireState interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_033, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_033 start";
    const Want want = {};
    const std::string provider = "";
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_STATE_ACQUIRE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteParcelable(&want);
    data.WriteString(provider);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_033 end";
}

/**
 * @tc.name: FormProviderStubTest_034
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireState interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_034, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_034 start";
    const Want want = {};
    const std::string provider = "";
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_PROVIDER_NOTIFY_STATE_ACQUIRE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteParcelable(&want);
    data.WriteString(provider);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_034 end";
}

/**
 * @tc.name: FormProviderStubTest_035
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireShareFormData interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_035, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_035 start";
    const std::string remoteDeviceId = "";
    const int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_SHARE_FOMR_INFO);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteString(remoteDeviceId);
    data.WriteRemoteObject(callerToken);
    data.WriteInt64(formId);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_035 end";
}

/**
 * @tc.name: FormProviderStubTest_036
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireShareFormData interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_036, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_036 start";
    const std::string remoteDeviceId = "";
    const int64_t formId = 1;
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_SHARE_FOMR_INFO);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteString(remoteDeviceId);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_036 end";
}

/**
 * @tc.name: FormProviderStubTest_037
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireFormData interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_037, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_037 start";
    const std::string remoteDeviceId = "";
    const int64_t formId = 1;
    const sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FOMR_DATA);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    data.WriteRemoteObject(callerToken);
    data.WriteInt64(formId);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "FormProviderStubTest_037 end";
}

/**
 * @tc.name: FormProviderStubTest_038
 * @tc.desc: Verify OnRemoteRequest and HandleAcquireFormData interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderStubTest, FormProviderStubTest_038, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderStubTest_038 start";
    const std::string remoteDeviceId = "";
    const int64_t formId = 1;
    const sptr<MockFormProviderClient> callback = new (std::nothrow) MockFormProviderClient();
    constexpr uint32_t code = static_cast<uint32_t>(IFormProvider::Message::FORM_ACQUIRE_PROVIDER_FOMR_DATA);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormProvider");
    data.WriteInt64(formId);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "FormProviderStubTest_038 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS
