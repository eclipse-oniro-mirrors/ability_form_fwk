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

#define private public
#define protected public
#include "provider_connect_proxy.h"
#include "provider_connect_stub.h"
#include <gtest/gtest.h>
#include "ipc_types.h"
#include "message_parcel.h"
#undef private
#undef protected

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class ProviderConnectProxyTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void ProviderConnectProxyTest::SetUpTestCase() {}

void ProviderConnectProxyTest::TearDownTestCase() {}

void ProviderConnectProxyTest::SetUp() {}

void ProviderConnectProxyTest::TearDown() {}

class MockProviderConnectStub : public ProviderConnectStub {
public:
    MockProviderConnectStub() {};
    ~MockProviderConnectStub() {};

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        GTEST_LOG_(INFO) << "MockProviderConnectStub::SendRequest called. return value " << returnCode_;
        reply.WriteInt32(ERR_NONE);
        flag = true;
        return returnCode_;
    }

    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override
        {
            GTEST_LOG_(INFO) << "MockProviderConnectStub::OnAbilityConnectDone called.";
            return;
    }

    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override
    {
        GTEST_LOG_(INFO) << "MockProviderConnectStub::OnAbilityDisconnectDone called.";
        return;
    }

    int32_t returnCode_ = 0;
    bool flag = false;
};

class MockProviderConnect : public ProviderConnectStub {
public:
    MockProviderConnect() {};
    ~MockProviderConnect() {};

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        GTEST_LOG_(INFO) << "MockProviderConnectStub::SendRequest called. return value " << returnCode_;
        reply.WriteInt32(ERR_NONE);
        flag = true;
        return returnCode_;
    }

    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override
    {
            GTEST_LOG_(INFO) << "MockProviderConnectStub::OnAbilityConnectDone called.";
            return;
    }

    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override
    {
        GTEST_LOG_(INFO) << "MockProviderConnectStub::OnAbilityDisconnectDone called.";
        return;
    }

    int32_t returnCode_ = 1;
    bool flag = false;
};

/**
 * @tc.number: ProviderConnectProxyTest_OnAbilityConnectDone_001
 * @tc.name: OnAbilityConnectDone
 * @tc.desc: Verify whether the OnAbilityConnectDone interface is called normally
 */
HWTEST_F(ProviderConnectProxyTest, ProviderConnectProxyTest_OnAbilityConnectDone_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityConnectDone_001 start";
    sptr<MockProviderConnectStub> remoteObject = new (std::nothrow) MockProviderConnectStub();
    sptr<ProviderConnectProxy> testProxy = new (std::nothrow) ProviderConnectProxy(remoteObject);
    EXPECT_TRUE(remoteObject != nullptr);
    ElementName element;
    int resultCode = 0;
    testProxy->OnAbilityConnectDone(element, remoteObject, resultCode);
    EXPECT_TRUE(remoteObject->flag);
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityConnectDone_001 end";
}

/**
 * @tc.number: ProviderConnectProxyTest_OnAbilityConnectDone_002
 * @tc.name: OnAbilityConnectDone
 * @tc.desc: Verify that when the parameter remoteObject passed is nullptr, Whether the
 *           OnAbilityConnectDone interface is called normally
 */
HWTEST_F(ProviderConnectProxyTest, ProviderConnectProxyTest_OnAbilityConnectDone_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityConnectDone_002 start";
    sptr<MockProviderConnectStub> Object = new (std::nothrow) MockProviderConnectStub();
    sptr<ProviderConnectProxy> testProxy = new (std::nothrow) ProviderConnectProxy(Object);
    ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 0;
    testProxy->OnAbilityConnectDone(element, remoteObject, resultCode);
    EXPECT_TRUE(remoteObject == nullptr);
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityConnectDone_002 end";
}

/**
 * @tc.number: ProviderConnectProxyTest_OnAbilityConnectDone_003
 * @tc.name: OnAbilityConnectDone
 * @tc.desc: Verify that when error is not ERR_ When OK, Whether the OnAbilityConnectDone interface is called normally
 */
HWTEST_F(ProviderConnectProxyTest, ProviderConnectProxyTest_OnAbilityConnectDone_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityConnectDone_003 start";
    sptr<MockProviderConnect> remoteObject = new (std::nothrow) MockProviderConnect();
    sptr<ProviderConnectProxy> testProxy = new (std::nothrow) ProviderConnectProxy(remoteObject);
    ElementName element;
    int resultCode = 0;
    testProxy->OnAbilityConnectDone(element, remoteObject, resultCode);
    EXPECT_TRUE(remoteObject->flag);
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityConnectDone_003 end";
}

/**
 * @tc.number: ProviderConnectProxyTest_OnAbilityDisconnectDone_001
 * @tc.name: OnAbilityDisconnectDone
 * @tc.desc: Verify whether the OnAbilityDisconnectDone interface is called normally
 */
HWTEST_F(ProviderConnectProxyTest, ProviderConnectProxyTest_OnAbilityDisconnectDone_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityDisconnectDone_001 start";
    sptr<MockProviderConnectStub> remoteObject = new (std::nothrow) MockProviderConnectStub();
    sptr<ProviderConnectProxy> testProxy = new (std::nothrow) ProviderConnectProxy(remoteObject);
    EXPECT_TRUE(remoteObject != nullptr);
    ElementName element;
    int resultCode = 0;
    testProxy->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_TRUE(remoteObject->flag);
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityDisconnectDone_001 end";
}

/**
 * @tc.number: ProviderConnectProxyTest_OnAbilityDisconnectDone_002
 * @tc.name: OnAbilityDisconnectDone
 * @tc.desc: Verify that when error is not ERR_ When OK, Whether the OnAbilityDisconnectDone
 *           interface is called normally
 */
HWTEST_F(ProviderConnectProxyTest, ProviderConnectProxyTest_OnAbilityDisconnectDone_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityDisconnectDone_002 start";
    sptr<MockProviderConnect> remoteObject = new (std::nothrow) MockProviderConnect();
    sptr<ProviderConnectProxy> testProxy = new (std::nothrow) ProviderConnectProxy(remoteObject);
    EXPECT_TRUE(remoteObject != nullptr);
    ElementName element;
    int resultCode = 0;
    testProxy->OnAbilityDisconnectDone(element, resultCode);
    EXPECT_TRUE(remoteObject->flag);
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_OnAbilityDisconnectDone_002 end";
}

/**
 * @tc.number: ProviderConnectProxyTest_WriteInterfaceToken_001
 * @tc.name: WriteInterfaceToken
 * @tc.desc: Verify whether the WriteInterfaceToken interface is called normally
 */
HWTEST_F(ProviderConnectProxyTest, ProviderConnectProxyTest_WriteInterfaceToken_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_WriteInterfaceToken_001 start";
    sptr<MockProviderConnectStub> remoteObject = new (std::nothrow) MockProviderConnectStub();
    sptr<ProviderConnectProxy> testProxy = new (std::nothrow) ProviderConnectProxy(remoteObject);
    MessageParcel data;
    EXPECT_TRUE(testProxy->WriteInterfaceToken(data));
    GTEST_LOG_(INFO) << "ProviderConnectProxyTest_WriteInterfaceToken_001 end";
}
}
}