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

#include "provider_connect_stub.h"
#include <gtest/gtest.h>
#include "form_ability_connection.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "message_parcel.h"
#include "appexecfwk_errors.h"
#include "element_name.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class ProviderConnectStubTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void ProviderConnectStubTest::SetUpTestCase() {}

void ProviderConnectStubTest::TearDownTestCase() {}

void ProviderConnectStubTest::SetUp() {}

void ProviderConnectStubTest::TearDown() {}

/**
 * @tc.name: ProviderConnectStubTest_001
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(ProviderConnectStubTest, ProviderConnectStubTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ProviderConnectStubTest_001 start";
    FormAbilityConnection formAbility;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string value = u"ohos.abilityshell.DistributedConnection";
    data.WriteString16(value);
    auto result = formAbility.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_INVALID_STATE);
    GTEST_LOG_(INFO) << "ProviderConnectStubTest_001 end";
}

/**
 * @tc.name: ProviderConnectStubTest_002
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(ProviderConnectStubTest, ProviderConnectStubTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ProviderConnectStubTest_002 start";
    FormAbilityConnection formAbility;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string metaDescriptor_ = u"ohos.abilityshell.DistributedConnection";
    data.WriteInterfaceToken(metaDescriptor_);
    auto result = formAbility.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "ProviderConnectStubTest_002 end";
}

/**
 * @tc.name: ProviderConnectStubTest_003
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(ProviderConnectStubTest, ProviderConnectStubTest_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ProviderConnectStubTest_003 start";
    FormAbilityConnection formAbility;
    uint32_t code = 2;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string metaDescriptor_ = u"ohos.abilityshell.DistributedConnection";
    data.WriteInterfaceToken(metaDescriptor_);
    auto result = formAbility.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
    GTEST_LOG_(INFO) << "ProviderConnectStubTest_003 end";
}

/**
 * @tc.name: ProviderConnectStubTest_004
 * @tc.desc: Verify OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(ProviderConnectStubTest, ProviderConnectStubTest_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "ProviderConnectStubTest_004 start";
    FormAbilityConnection formAbility;
    uint32_t code = 3;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::u16string metaDescriptor_ = u"ohos.abilityshell.DistributedConnection";
    data.WriteInterfaceToken(metaDescriptor_);
    auto result = formAbility.OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
    GTEST_LOG_(INFO) << "ProviderConnectStubTest_004 end";
}

}
}