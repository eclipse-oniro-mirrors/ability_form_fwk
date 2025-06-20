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
#include <gmock/gmock.h>
#define private public
#define protected public
#include "appexecfwk_errors.h"
#include "element_name.h"
#include "form_mgr_errors.h"
#include "form_constants.h"
#include "form_provider/form_supply_callback.h"
#include "form_supply_stub.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "message_parcel.h"
#undef public
#undef protected
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FormSupplyStubTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormSupplyStubTest::SetUpTestCase()
{}

void FormSupplyStubTest::TearDownTestCase()
{}

void FormSupplyStubTest::SetUp()
{}

void FormSupplyStubTest::TearDown()
{}

class MockFormSupplyCallback : public FormSupplyStub {
public:
    MockFormSupplyCallback() {};
    virtual ~MockFormSupplyCallback() {};

    sptr<IRemoteObject> AsObject() override
    {
        if (!asObject_) {
            return nullptr;
        }
        return this;
    };

    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override
    {
        return ERR_OK;
    };

    int OnEventHandle(const Want &want) override
    {
        return ERR_OK;
    };

    int OnAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg,
        const Want &want) override
    {
        return ERR_OK;
    };

    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override
    {};

    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }

    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }

    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode) override
    {
        return ERR_OK;
    }

    int OnRecoverFormsByConfigUpdate(std::vector<int64_t> &formIds) override
    {
        return ERR_OK;
    }

    bool asObject_ = true;
};

/**
 * @tc.name: FormSupplyStubTest_001
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_001, TestSize.Level0)
{
    FormSupplyCallback callback;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormSupplyStubTest_002
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_002, TestSize.Level0)
{
    FormSupplyCallback callback;
    uint32_t code = 2;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormSupplyStubTest_003
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_003, TestSize.Level0)
{
    FormSupplyCallback callback;
    uint32_t code = 3;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormSupplyStubTest_004
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_004, TestSize.Level0)
{
    FormSupplyCallback callback;
    uint32_t code = 4;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormSupplyStubTest_005
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_005, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    FormProviderInfo formInfo;
    want.SetParam(Constants::PROVIDER_FLAG, ERR_OK);
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteParcelable(&formInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_006
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_006, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    want.SetParam(Constants::PROVIDER_FLAG, ERR_OK);
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_007
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_007, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    want.SetParam(Constants::PROVIDER_FLAG, ERR_APPEXECFWK_PARCEL_ERROR);
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_008
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_008, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_009
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_009, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    FormProviderInfo formInfo = {};
    want.SetParam(Constants::PROVIDER_FLAG, ERR_OK);
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteParcelable(&formInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_010
 * @tc.desc: Verify function HandleOnEventHandle the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_010, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_EVENT_HANDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_011
 * @tc.desc: Verify function HandleOnEventHandle the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_011, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_EVENT_HANDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_012
 * @tc.desc: Verify function HandleOnAcquireStateResult the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_012, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_STATE_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_013
 * @tc.desc: Verify function HandleOnAcquireStateResult the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_013, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_STATE_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want wantArg = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt32(1);
    data.WriteString("");
    data.WriteParcelable(&wantArg);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_014
 * @tc.desc: Verify function HandleOnAcquireStateResult the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_014, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_STATE_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    Want wantArg = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt32(1);
    data.WriteString("");
    data.WriteParcelable(&wantArg);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_015
 * @tc.desc: Verify function HandleOnShareAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_015, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_SHARE_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_016
 * @tc.desc: Verify function HandleOnShareAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_016, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_SHARE_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_017
 * @tc.desc: Verify function HandleOnShareAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_017, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_SHARE_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteString("abc");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_018
 * @tc.desc: Verify function HandleOnShareAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_018, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_SHARE_ACQUIRED);
    AAFwk::WantParams wantParams = {};
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteString("abc");
    data.WriteParcelable(&wantParams);
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_019
 * @tc.desc: Verify function HandleOnShareAcquire the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_019, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_SHARE_ACQUIRED);
    AAFwk::WantParams wantParams = {};
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteString("abc");
    data.WriteParcelable(&wantParams);
    data.WriteInt64(1);
    data.WriteBool(true);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_020
 * @tc.desc: Verify function HandleOnAcquire the return value is IPC_STUB_UNKNOW_TRANS_ERR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_020, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    EXPECT_EQ(callback->OnRemoteRequest(code, data, reply, option), IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormSupplyStubTest_021
 * @tc.desc: Verify function HandleOnAcquireDataResult the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_021, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED_DATA);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_022
 * @tc.desc: Verify function HandleOnAcquireDataResult the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_022, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED_DATA);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    AAFwk::WantParams wantParams;
    data.WriteParcelable(&wantParams);
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_023
 * @tc.desc: Verify function HandleOnAcquireDataResult the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_023, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED_DATA);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    AAFwk::WantParams wantParams;
    data.WriteParcelable(&wantParams);
    data.WriteInt64(1);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_024
 * @tc.desc: Verify function HandleOnRecoverFormsByConfigUpdate the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_024, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code =
        static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RECOVER_FORM_BY_CONFIG_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    std::vector<int64_t> formIds;
    data.WriteInt64Vector(formIds);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_025
 * @tc.desc: Verify function HandleOnRecoverFormsByConfigUpdate the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_025, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code =
        static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RECOVER_FORM_BY_CONFIG_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    std::vector<int64_t> formIds;
    int64_t formId = 1;
    formIds.push_back(formId);
    data.WriteInt64Vector(formIds);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_026
 * @tc.desc: Verify function HandleOnRenderTaskDone the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_026, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RENDER_TASK_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_027
 * @tc.desc: Verify function HandleOnRenderTaskDone the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_027, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RENDER_TASK_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_028
 * @tc.desc: Verify function HandleOnRenderTaskDone the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_028, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RENDER_TASK_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_029
 * @tc.desc: Verify function HandleOnStopRenderingTaskDone the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_029, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_STOP_RENDERING_TASK_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_030
 * @tc.desc: Verify function HandleOnStopRenderingTaskDone the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_030, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_STOP_RENDERING_TASK_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_031
 * @tc.desc: Verify function HandleOnStopRenderingTaskDone the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_031, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_STOP_RENDERING_TASK_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_032
 * @tc.desc: Verify function HandleOnRenderingBlock the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_032, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RENDERING_BLOCK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_033
 * @tc.desc: Verify function HandleOnRenderingBlock the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_033, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RENDERING_BLOCK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteString("bundleName");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_034
 * @tc.desc: Verify function HandleOnRecycleForm the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_034, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RECYCLE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_035
 * @tc.desc: Verify function HandleOnRecycleForm the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_035, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RECYCLE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_036
 * @tc.desc: Verify function HandleOnRecycleForm the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_036, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RECYCLE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_037
 * @tc.desc: Verify function HandleOnNotifyRefreshForm the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_037, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_NOTIFY_REFRESH);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_041
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_041, TestSize.Level0)
{
    FormSupplyCallback callback;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormSupplyStubTest_042
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_042, TestSize.Level0)
{
    FormSupplyCallback callback;
    uint32_t code = 2;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormSupplyStubTest_043
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_043, TestSize.Level0)
{
    FormSupplyCallback callback;
    uint32_t code = 3;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormSupplyStubTest_044
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require: #I5SNG1
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_044, TestSize.Level0)
{
    FormSupplyCallback callback;
    uint32_t code = 4;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormSupplyStubTest_045
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_045, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    FormProviderInfo formInfo;
    want.SetParam(Constants::PROVIDER_FLAG, ERR_OK);
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteParcelable(&formInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_046
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_046, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    want.SetParam(Constants::PROVIDER_FLAG, ERR_OK);
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_047
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_047, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    want.SetParam(Constants::PROVIDER_FLAG, ERR_APPEXECFWK_PARCEL_ERROR);
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_048
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_048, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_049
 * @tc.desc: Verify function HandleOnAcquire the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_049, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    FormProviderInfo formInfo = {};
    want.SetParam(Constants::PROVIDER_FLAG, ERR_OK);
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    data.WriteParcelable(&formInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_050
 * @tc.desc: Verify function HandleOnEventHandle the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_050, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_EVENT_HANDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_051
 * @tc.desc: Verify function HandleOnEventHandle the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_051, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_EVENT_HANDLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_052
 * @tc.desc: Verify function HandleOnAcquireStateResult the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_052, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_STATE_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_053
 * @tc.desc: Verify function HandleOnAcquireStateResult the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_053, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_STATE_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want wantArg = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt32(1);
    data.WriteString("");
    data.WriteParcelable(&wantArg);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_054
 * @tc.desc: Verify function HandleOnDeleteFormDone the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_054, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_DELETE_FORM_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);

    MessageParcel dataNew;
    dataNew.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    dataNew.WriteInt64(1);
    result = callback->OnRemoteRequest(code, dataNew, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_055
 * @tc.desc: Verify function HandleOnDeleteFormDone the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_055, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_DELETE_FORM_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_056
 * @tc.desc: Verify function HandleOnRenderFormDone the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_056, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RENDER_FORM_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);

    MessageParcel dataNew;
    dataNew.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    dataNew.WriteInt64(1);
    result = callback->OnRemoteRequest(code, dataNew, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_057
 * @tc.desc: Verify function HandleOnRenderFormDone the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_057, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RENDER_FORM_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_058
 * @tc.desc: Verify function HandleOnRecoverFormDone the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_058, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RECOVER_FORM_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);

    MessageParcel dataNew;
    dataNew.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    dataNew.WriteInt64(1);
    result = callback->OnRemoteRequest(code, dataNew, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_059
 * @tc.desc: Verify function HandleOnRecoverFormDone the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_059, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RECOVER_FORM_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormSupplyStubTest_060
 * @tc.desc: Verify function HandleOnRecycleFormDone the return value is ERR_APPEXECFWK_PARCEL_ERROR
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_060, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RECYCLE_FORM_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(0);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);

    MessageParcel dataNew;
    dataNew.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    dataNew.WriteInt64(1);
    result = callback->OnRemoteRequest(code, dataNew, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormSupplyStubTest_061
 * @tc.desc: Verify function HandleOnRecycleFormDone the return value is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormSupplyStubTest, FormSupplyStubTest_061, TestSize.Level1)
{
    sptr<MockFormSupplyCallback> callback = new (std::nothrow) MockFormSupplyCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormSupply::Message::TRANSACTION_FORM_RECYCLE_FORM_DONE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Want want = {};
    data.WriteInterfaceToken(MockFormSupplyCallback::GetDescriptor());
    data.WriteInt64(1);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace AppExecFwk
}  // namespace OHOS
