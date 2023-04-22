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
#define private public
#include "appexecfwk_errors.h"
#include "element_name.h"
#include "form_host_stub.h"
#include "form_mgr_errors.h"
#include "form_state_info.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "message_parcel.h"
#include "mock_form_host_client.h"
#undef private
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FormHostStubTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void FormHostStubTest::SetUpTestCase()
{}

void FormHostStubTest::TearDownTestCase()
{}

void FormHostStubTest::SetUp()
{}

void FormHostStubTest::TearDown()
{}

/**
 * @tc.name: FormHostStubTest_001
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_001, TestSize.Level0)
{
    MockFormHostClient callback;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormHostStubTest_002
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_002, TestSize.Level0)
{
    MockFormHostClient callback;
    uint32_t code = 2;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormHostStubTest_003
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_003, TestSize.Level0)
{
    MockFormHostClient callback;
    uint32_t code = 3;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormHostStubTest_004
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_004, TestSize.Level0)
{
    MockFormHostClient callback;
    uint32_t code = 4;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormHostStubTest_005
 * @tc.desc: Verify OnRemoteRequest and HandleAcquired
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_005, TestSize.Level1)
{
    MockFormHostClient callback;
    FormJsInfo formInfo = {};
    formInfo.formId = 1;
    const sptr<IRemoteObject> token;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    data.WriteParcelable(&formInfo);
    data.WriteBool(true);
    data.WriteRemoteObject(token);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormHostStubTest_006
 * @tc.desc: Verify OnRemoteRequest and HandleAcquired
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_006, TestSize.Level1)
{
    MockFormHostClient callback;
    FormJsInfo formInfo = {};
    formInfo.formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    data.WriteParcelable(&formInfo);
    data.WriteBool(false);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormHostStubTest_007
 * @tc.desc: Verify OnRemoteRequest and HandleOnUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_007, TestSize.Level1)
{
    MockFormHostClient callback;
    FormJsInfo formInfo = {};
    formInfo.formId = 1;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    data.WriteParcelable(&formInfo);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormHostStubTest_008
 * @tc.desc: Verify OnRemoteRequest and HandleOnUpdate
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_008, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_UPDATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormHostStubTest_009
 * @tc.desc: Verify OnRemoteRequest and HandleOnUninstall
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_009, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_UNINSTALL);
    const std::vector<int64_t> formIds;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    data.WriteInt64Vector(formIds);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormHostStubTest_010
 * @tc.desc: Verify OnRemoteRequest and HandleOnUninstall
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_010, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_UNINSTALL);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    data.WriteInt32(-1);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormHostStubTest_011
 * @tc.desc: Verify OnRemoteRequest and HandleOnAcquireState
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_011, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_STATE);
    constexpr FormState state = FormState::DEFAULT;
    const AAFwk::Want want = {};
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(state));
    data.WriteParcelable(&want);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormHostStubTest_012
 * @tc.desc: Verify OnRemoteRequest and HandleOnAcquireState
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_012, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_STATE);
    constexpr FormState state = FormState::DEFAULT;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(state));
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormHostStubTest_013
 * @tc.desc: Verify OnRemoteRequest and HandleOnAcquireState
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_013, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_SHARE_FORM_RESPONSE);
    constexpr int64_t requestCode = 0;
    constexpr int32_t resultValue = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    data.WriteInt64(requestCode);
    data.WriteInt32(resultValue);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormHostStubTest_014
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_014, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_SHARE_FORM_RESPONSE) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormHostStubTest_015
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_015, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_SHARE_FORM_RESPONSE) + 100;
    callback.memberFuncMap_[code] = nullptr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormHostStubTest_016
 * @tc.desc: Verify OnRemoteRequest and HandleOnAcquireState
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_016, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_DATA);
    constexpr int64_t requestCode = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    data.WriteParcelable(nullptr);
    data.WriteInt64(requestCode);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormHostStubTest_017
 * @tc.desc: Verify OnRemoteRequest and HandleOnAcquireState
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_017, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_DATA);
    constexpr int64_t requestCode = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    AAFwk::WantParams wantParams;
    data.WriteParcelable(&wantParams);
    data.WriteInt64(requestCode);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormHostStubTest_018
 * @tc.desc: Verify OnRemoteRequest and HandleOnAcquireState
 * @tc.type: FUNC
 */
HWTEST_F(FormHostStubTest, FormHostStubTest_018, TestSize.Level1)
{
    MockFormHostClient callback;
    constexpr uint32_t code = static_cast<uint32_t>(IFormHost::Message::FORM_HOST_ON_ACQUIRE_FORM_DATA);
    constexpr int64_t requestCode = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostClient::GetDescriptor());
    AAFwk::WantParams wantParams;
    data.WriteParcelable(&wantParams);
    data.WriteInt64(requestCode);
    auto result = callback.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace AppExecFwk
}  // namespace OHOS
