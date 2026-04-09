/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "common/util/form_proxy_registry.h"
#include "form_mgr_errors.h"
#include "mock_i_remote_object.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t UID_A = 20000001;
constexpr int32_t UID_B = 20000002;
constexpr int32_t UID_C = 20000003;
}

class FmsFormProxyRegistryTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

    FormProxyRegistry registry_{"Test"};
};

void FmsFormProxyRegistryTest::SetUp()
{
    registry_.Clear();
}

void FmsFormProxyRegistryTest::TearDown()
{
    registry_.Clear();
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Register_0001
 * @tc.desc: test Register with null proxy.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Register_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Register_0001 start";
    sptr<IRemoteObject> nullProxy = nullptr;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, registry_.Register(UID_A, nullProxy));
    EXPECT_EQ(0u, registry_.Size());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Register_0001 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Register_0002
 * @tc.desc: test Register with valid proxy.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Register_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Register_0002 start";
    sptr<IRemoteObject> proxy = new (std::nothrow) MockIRemoteObject();
    EXPECT_EQ(ERR_OK, registry_.Register(UID_A, proxy));
    EXPECT_EQ(1u, registry_.Size());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Register_0002 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Unregister_0001
 * @tc.desc: test Unregister without prior register.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Unregister_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Unregister_0001 start";
    EXPECT_EQ(ERR_APPEXECFWK_FORM_COMMON_CODE, registry_.Unregister(UID_A));
    EXPECT_EQ(0u, registry_.Size());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Unregister_0001 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Unregister_0002
 * @tc.desc: test Register then Unregister.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Unregister_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Unregister_0002 start";
    sptr<IRemoteObject> proxy = new (std::nothrow) MockIRemoteObject();
    EXPECT_EQ(ERR_OK, registry_.Register(UID_A, proxy));
    EXPECT_EQ(ERR_OK, registry_.Unregister(UID_A));
    EXPECT_EQ(0u, registry_.Size());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Unregister_0002 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Get_0001
 * @tc.desc: test Get without register.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Get_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Get_0001 start";
    sptr<IRemoteObject> proxy;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, registry_.Get(UID_A, proxy));
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Get_0001 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Get_0002
 * @tc.desc: test Register then Get returns stored proxy.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Get_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Get_0002 start";
    sptr<IRemoteObject> proxy = new (std::nothrow) MockIRemoteObject();
    ASSERT_EQ(ERR_OK, registry_.Register(UID_A, proxy));

    sptr<IRemoteObject> outProxy;
    EXPECT_EQ(ERR_OK, registry_.Get(UID_A, outProxy));
    EXPECT_EQ(proxy.GetRefPtr(), outProxy.GetRefPtr());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Get_0002 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Get_0003
 * @tc.desc: test Register then Unregister then Get fails.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Get_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Get_0003 start";
    sptr<IRemoteObject> proxy = new (std::nothrow) MockIRemoteObject();
    ASSERT_EQ(ERR_OK, registry_.Register(UID_A, proxy));
    ASSERT_EQ(ERR_OK, registry_.Unregister(UID_A));

    sptr<IRemoteObject> outProxy;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, registry_.Get(UID_A, outProxy));
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Get_0003 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_MultiUid_0001
 * @tc.desc: test multiple UIDs are independent.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_MultiUid_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_MultiUid_0001 start";
    sptr<IRemoteObject> proxyA = new (std::nothrow) MockIRemoteObject();
    sptr<IRemoteObject> proxyB = new (std::nothrow) MockIRemoteObject();

    EXPECT_EQ(ERR_OK, registry_.Register(UID_A, proxyA));
    EXPECT_EQ(ERR_OK, registry_.Register(UID_B, proxyB));
    EXPECT_EQ(2u, registry_.Size());

    sptr<IRemoteObject> outA;
    sptr<IRemoteObject> outB;
    EXPECT_EQ(ERR_OK, registry_.Get(UID_A, outA));
    EXPECT_EQ(ERR_OK, registry_.Get(UID_B, outB));
    EXPECT_EQ(proxyA.GetRefPtr(), outA.GetRefPtr());
    EXPECT_EQ(proxyB.GetRefPtr(), outB.GetRefPtr());

    // Unregister A does not affect B
    EXPECT_EQ(ERR_OK, registry_.Unregister(UID_A));
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, registry_.Get(UID_A, outA));
    EXPECT_EQ(ERR_OK, registry_.Get(UID_B, outB));
    EXPECT_EQ(1u, registry_.Size());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_MultiUid_0001 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Register_0003
 * @tc.desc: test overwriting existing proxy for same UID.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Register_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Register_0003 start";
    sptr<IRemoteObject> proxy1 = new (std::nothrow) MockIRemoteObject();
    sptr<IRemoteObject> proxy2 = new (std::nothrow) MockIRemoteObject();

    EXPECT_EQ(ERR_OK, registry_.Register(UID_A, proxy1));
    EXPECT_EQ(1u, registry_.Size());
    EXPECT_EQ(ERR_OK, registry_.Register(UID_A, proxy2));
    EXPECT_EQ(1u, registry_.Size());

    sptr<IRemoteObject> outProxy;
    EXPECT_EQ(ERR_OK, registry_.Get(UID_A, outProxy));
    EXPECT_EQ(proxy2.GetRefPtr(), outProxy.GetRefPtr());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Register_0003 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Clear_0001
 * @tc.desc: test Clear removes all proxies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Clear_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Clear_0001 start";
    sptr<IRemoteObject> proxyA = new (std::nothrow) MockIRemoteObject();
    sptr<IRemoteObject> proxyB = new (std::nothrow) MockIRemoteObject();

    EXPECT_EQ(ERR_OK, registry_.Register(UID_A, proxyA));
    EXPECT_EQ(ERR_OK, registry_.Register(UID_B, proxyB));
    EXPECT_EQ(2u, registry_.Size());

    registry_.Clear();
    EXPECT_EQ(0u, registry_.Size());

    sptr<IRemoteObject> outProxy;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, registry_.Get(UID_A, outProxy));
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, registry_.Get(UID_B, outProxy));
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Clear_0001 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_Size_0001
 * @tc.desc: test Size returns correct count.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_Size_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Size_0001 start";
    EXPECT_EQ(0u, registry_.Size());

    sptr<IRemoteObject> proxyA = new (std::nothrow) MockIRemoteObject();
    sptr<IRemoteObject> proxyB = new (std::nothrow) MockIRemoteObject();
    sptr<IRemoteObject> proxyC = new (std::nothrow) MockIRemoteObject();

    registry_.Register(UID_A, proxyA);
    EXPECT_EQ(1u, registry_.Size());
    registry_.Register(UID_B, proxyB);
    EXPECT_EQ(2u, registry_.Size());
    registry_.Register(UID_C, proxyC);
    EXPECT_EQ(3u, registry_.Size());

    registry_.Unregister(UID_B);
    EXPECT_EQ(2u, registry_.Size());

    registry_.Clear();
    EXPECT_EQ(0u, registry_.Size());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_Size_0001 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_GetAll_0001
 * @tc.desc: test GetAll with no registered proxies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_GetAll_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetAll_0001 start";
    std::vector<sptr<IRemoteObject>> proxies;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, registry_.GetAll(proxies));
    EXPECT_TRUE(proxies.empty());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetAll_0001 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_GetAll_0002
 * @tc.desc: test GetAll with registered proxies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_GetAll_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetAll_0002 start";
    sptr<IRemoteObject> proxyA = new (std::nothrow) MockIRemoteObject();
    sptr<IRemoteObject> proxyB = new (std::nothrow) MockIRemoteObject();
    ASSERT_EQ(ERR_OK, registry_.Register(UID_A, proxyA));
    ASSERT_EQ(ERR_OK, registry_.Register(UID_B, proxyB));

    std::vector<sptr<IRemoteObject>> proxies;
    EXPECT_EQ(ERR_OK, registry_.GetAll(proxies));
    EXPECT_EQ(2u, proxies.size());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetAll_0002 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_GetByUserId_0001
 * @tc.desc: test GetByUserId with no registered proxies.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_GetByUserId_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetByUserId_0001 start";
    std::vector<sptr<IRemoteObject>> proxies;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, registry_.GetByUserId(100, proxies));
    EXPECT_TRUE(proxies.empty());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetByUserId_0001 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_GetByUserId_0002
 * @tc.desc: test GetByUserId with multiple UIDs mapping to same userId.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_GetByUserId_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetByUserId_0002 start";
    sptr<IRemoteObject> proxyA = new (std::nothrow) MockIRemoteObject();
    sptr<IRemoteObject> proxyB = new (std::nothrow) MockIRemoteObject();
    ASSERT_EQ(ERR_OK, registry_.Register(UID_A, proxyA));
    ASSERT_EQ(ERR_OK, registry_.Register(UID_B, proxyB));

    // UID_A=20000001 and UID_B=20000002 both map to userId=100
    std::vector<sptr<IRemoteObject>> proxies;
    EXPECT_EQ(ERR_OK, registry_.GetByUserId(100, proxies));
    EXPECT_EQ(2u, proxies.size());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetByUserId_0002 end";
}

/**
 * @tc.name: FmsFormProxyRegistryTest_GetByUserId_0003
 * @tc.desc: test GetByUserId with non-matching userId.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormProxyRegistryTest, FmsFormProxyRegistryTest_GetByUserId_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetByUserId_0003 start";
    sptr<IRemoteObject> proxyA = new (std::nothrow) MockIRemoteObject();
    ASSERT_EQ(ERR_OK, registry_.Register(UID_A, proxyA));

    // UID_A=20000001 maps to userId=100, not 999
    std::vector<sptr<IRemoteObject>> proxies;
    EXPECT_EQ(ERR_APPEXECFWK_FORM_GET_HOST_FAILED, registry_.GetByUserId(999, proxies));
    EXPECT_TRUE(proxies.empty());
    GTEST_LOG_(INFO) << "FmsFormProxyRegistryTest_GetByUserId_0003 end";
}
