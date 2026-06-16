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

#include "common/util/form_util.h"
#include "fms_log_wrapper.h"
#define private public
#include "form_observer/net_conn_callback_observer.h"
#undef private

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr long FORM_DISCON_NETWORK_CHECK_TIME = 600000; // ms
}

class NetConnCallbackObserverTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void NetConnCallbackObserverTest::SetUpTestCase()
{
    HILOG_INFO("NetConnCallbackObserverTest::SetUpTestCase");
}

void NetConnCallbackObserverTest::TearDownTestCase()
{
    HILOG_INFO("NetConnCallbackObserverTest::TearDownTestCase");
}

void NetConnCallbackObserverTest::SetUp()
{
    HILOG_INFO("NetConnCallbackObserverTest::SetUp");
}

void NetConnCallbackObserverTest::TearDown()
{
    HILOG_INFO("NetConnCallbackObserverTest::TearDown");
}

/**
 * @tc.name: NetConnCallbackObserver_001
 * @tc.desc: Test NetAvailable
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackObserverTest, NetConnCallbackObserver_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackObserver_001 start";

    auto observer = std::make_shared<NetConnCallbackObserver>();
    ASSERT_NE(observer, nullptr);
    EXPECT_NE(observer->lastNetLostTime_.load(), 0);

    observer->lastNetLostTime_.store(0);
    sptr<NetManagerStandard::NetHandle> netHandle = new (std::nothrow) NetManagerStandard::NetHandle();
    ASSERT_NE(netHandle, nullptr);
    int32_t result = observer->NetAvailable(netHandle);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(observer->lastNetLostTime_.load(), 0);

    GTEST_LOG_(INFO) << "NetConnCallbackObserver_001 end";
}

/**
 * @tc.name: NetConnCallbackObserver_002
 * @tc.desc: Test NetAvailable
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackObserverTest, NetConnCallbackObserver_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackObserver_002 start";

    auto observer = std::make_shared<NetConnCallbackObserver>();
    ASSERT_NE(observer, nullptr);

    observer->lastNetLostTime_.store(FormUtil::GetCurrentMillisecond());
    sptr<NetManagerStandard::NetHandle> netHandle = new (std::nothrow) NetManagerStandard::NetHandle();
    ASSERT_NE(netHandle, nullptr);
    int32_t result = observer->NetAvailable(netHandle);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(observer->lastNetLostTime_.load(), 0);

    GTEST_LOG_(INFO) << "NetConnCallbackObserver_002 end";
}

/**
 * @tc.name: NetConnCallbackObserver_003
 * @tc.desc: Test NetAvailable
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackObserverTest, NetConnCallbackObserver_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackObserver_003 start";

    auto observer = std::make_shared<NetConnCallbackObserver>();
    ASSERT_NE(observer, nullptr);

    observer->lastNetLostTime_.store(FormUtil::GetCurrentMillisecond() - FORM_DISCON_NETWORK_CHECK_TIME);
    sptr<NetManagerStandard::NetHandle> netHandle = new (std::nothrow) NetManagerStandard::NetHandle();
    ASSERT_NE(netHandle, nullptr);
    int32_t result = observer->NetAvailable(netHandle);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_EQ(observer->lastNetLostTime_.load(), 0);

    GTEST_LOG_(INFO) << "NetConnCallbackObserver_003 end";
}

/**
 * @tc.name: NetConnCallbackObserver_004
 * @tc.desc: Test NetLost
 * @tc.type: FUNC
 */
HWTEST_F(NetConnCallbackObserverTest, NetConnCallbackObserver_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NetConnCallbackObserver_004 start";

    auto observer = std::make_shared<NetConnCallbackObserver>();
    ASSERT_NE(observer, nullptr);

    observer->lastNetLostTime_.store(0);
    sptr<NetManagerStandard::NetHandle> netHandle = new (std::nothrow) NetManagerStandard::NetHandle();
    ASSERT_NE(netHandle, nullptr);
    int32_t result = observer->NetLost(netHandle);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(observer->lastNetLostTime_.load(), 0);

    GTEST_LOG_(INFO) << "NetConnCallbackObserver_004 end";
}