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
#include <gmock/gmock.h>

#include "fms_log_wrapper.h"
#define private public
#include "form_observer/net_conn_callback_impl.h.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

class NetConnCallbackImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetConnCallbackImplTest::SetUpTestCase()
{
    HILOG_INFO("NetConnCallbackImplTest::SetUpTestCase");
}

void NetConnCallbackImplTest::TearDownTestCase()
{
    HILOG_INFO("NetConnCallbackImplTest::TearDownTestCase");
}

void NetConnCallbackImplTest::SetUp()
{
    HILOG_INFO("NetConnCallbackImplTest::SetUp");
}

void NetConnCallbackImplTest::TearDown()
{
    HILOG_INFO("NetConnCallbackImplTest::TearDown");
}

/**
 * @tc.name: NetConnCallbackImpl_001
 * @tc.desc: Test constructor and destructor
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackImplTest, NetConnCallbackImpl_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackImpl_001 start";

    auto callback = new (std::nothrow) NetConnCallbackImpl();
    ASSERT_NE(callback, nullptr);
    
    // Verify lastNetLostTime_ is initialized
    EXPECT_NE(callback->lastNetLostTime_.load(), 0);

    delete callback;

    GTEST_LOG_(INFO) << "NetConnCallbackImpl_001 end";
}

/**
 * @tc.name: NetConnCallbackImpl_002
 * @tc.desc: Test NetAvailable callback
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackImplTest, NetConnCallbackImpl_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackImpl_002 start";

    auto callback = new (std::nothrow) NetConnCallbackImpl();
    ASSERT_NE(callback, nullptr);

    sptr<NetManagerStandard::NetHandle> netHandle = new (std::nothrow) NetManagerStandard::NetHandle();
    ASSERT_NE(netHandle, nullptr);

    // Test NetAvailable returns ERR_OK
    int32_t result = callback->NetAvailable(netHandle);
    EXPECT_EQ(result, ERR_OK);

    delete callback;

    GTEST_LOG_(INFO) << "NetConnCallbackImpl_002 end";
}

/**
 * @tc.name: NetConnCallbackImpl_003
 * @tc.desc: Test NetLost callback
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackImplTest, NetConnCallbackImpl_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackImpl_003 start";

    auto callback = new (std::nothrow) NetConnCallbackImpl();
    ASSERT_NE(callback, nullptr);

    sptr<NetManagerStandard::NetHandle> netHandle = new (std::nothrow) NetManagerStandard::NetHandle();
    ASSERT_NE(netHandle, nullptr);

    int64_t beforeTime = callback->lastNetLostTime_.load();

    // Test NetLost updates lastNetLostTime_
    int32_t result = callback->NetLost(netHandle);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(callback->lastNetLostTime_.load(), beforeTime);

    delete callback;

    GTEST_LOG_(INFO) << "NetConnCallbackImpl_003 end";
}

/**
 * @tc.name: NetConnCallbackImpl_004
 * @tc.desc: Test NetUnavailable callback
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackImplTest, NetConnCallbackImpl_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackImpl_004 start";

    auto callback = new (std::nothrow) NetConnCallbackImpl();
    ASSERT_NE(callback, nullptr);

    int32_t result = callback->NetUnavailable();
    EXPECT_EQ(result, ERR_OK);

    delete callback;

    GTEST_LOG_(INFO) << "NetConnCallbackImpl_004 end";
}

/**
 * @tc.name: NetConnCallbackImpl_005
 * @tc.desc: Test NetCapabilitiesChange callback
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackImplTest, NetConnCallbackImpl_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackImpl_005 start";

    auto callback = new (std::nothrow) NetConnCallbackImpl();
    ASSERT_NE(callback, nullptr);

    sptr<NetManagerStandard::NetHandle> netHandle = new (std::nothrow) NetManagerStandard::NetHandle();
    ASSERT_NE(netHandle, nullptr);
    sptr<NetManagerStandard::NetAllCapabilities> netAllCap = new (std::nothrow) NetManagerStandard::NetAllCapabilities();
    ASSERT_NE(netAllCap, nullptr);

    int32_t result = callback->NetCapabilitiesChange(netHandle, netAllCap);
    EXPECT_EQ(result, ERR_OK);

    delete callback;

    GTEST_LOG_(INFO) << "NetConnCallbackImpl_005 end";
}

/**
 * @tc.name: NetConnCallbackImpl_006
 * @tc.desc: Test NetConnectionPropertiesChange callback
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackImplTest, NetConnCallbackImpl_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackImpl_006 start";

    auto callback = new (std::nothrow) NetConnCallbackImpl();
    ASSERT_NE(callback, nullptr);

    sptr<NetManagerStandard::NetHandle> netHandle = new (std::nothrow) NetManagerStandard::NetHandle();
    ASSERT_NE(netHandle, nullptr);
    sptr<NetManagerStandard::NetLinkInfo> info = new (std::nothrow) NetManagerStandard::NetLinkInfo();
    ASSERT_NE(info, nullptr);

    int32_t result = callback->NetConnectionPropertiesChange(netHandle, info);
    EXPECT_EQ(result, ERR_OK);

    delete callback;

    GTEST_LOG_(INFO) << "NetConnCallbackImpl_006 end";
}

/**
 * @tc.name: NetConnCallbackImpl_007
 * @tc.desc: Test NetBlockStatusChange callback
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackImplTest, NetConnCallbackImpl_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackImpl_007 start";

    auto callback = new (std::nothrow) NetConnCallbackImpl();
    ASSERT_NE(callback, nullptr);

    sptr<NetManagerStandard::NetHandle> netHandle = new (std::nothrow) NetManagerStandard::NetHandle();
    ASSERT_NE(netHandle, nullptr);

    int32_t result = callback->NetBlockStatusChange(netHandle, true);
    EXPECT_EQ(result, ERR_OK);

    delete callback;

    GTEST_LOG_(INFO) << "NetConnCallbackImpl_007 end";
}
