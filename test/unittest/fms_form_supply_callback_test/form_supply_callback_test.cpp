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
#define private public
#include "form_cache_mgr.h"
#include "form_supply_callback.h"
#undef private
#include "form_ability_connection.h"
#include "form_acquire_connection.h"
#include "form_host_caller.h"
#include "form_mgr.h"
#include "hilog_wrapper.h"
#include "mock_form_provider_client.h"
#include "gmock/gmock.h"
#include "mock_form_mgr_proxy.h"
#include "mock_form_token.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FmsFormSupplyCallbackTest : public testing::Test {
public:

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    FormCacheMgr formCacheMgr_;
};


void FmsFormSupplyCallbackTest::SetUpTestCase()
{}

void FmsFormSupplyCallbackTest::TearDownTestCase()
{}

void FmsFormSupplyCallbackTest::SetUp()
{}

void FmsFormSupplyCallbackTest::TearDown()
{}

/**
 * @tc.name: FormAcquireConnectionTest_0001
 * @tc.desc: test RemoveFormHostCaller function and GetHostToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSupplyCallbackTest, FormAcquireConnectionTest_0001, TestSize.Level0)
{
    HILOG_INFO("FormAcquireConnectionTest_0001 start");
    int64_t formId = 1;
    FormItemInfo info;
    WantParams wantParams;
    FormAcquireConnection formAcquireConnection(formId, info, wantParams, nullptr);
    AppExecFwk::ElementName element;
    int resultCode = ERR_OK;
    FormAbilityConnection formAbilityConnection;
    // set hostToken is nullptr
    formAbilityConnection.SetHostToken(nullptr);
    formAcquireConnection.OnAbilityConnectDone(element, nullptr, resultCode);
    GTEST_LOG_(INFO) << "FormAcquireConnectionTest_0001 end";
}

/**
 * @tc.name: FormAcquireConnectionTest_0002
 * @tc.desc: test IsRemoveConnection function and hostToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSupplyCallbackTest, FormAcquireConnectionTest_0002, TestSize.Level0)
{
    HILOG_INFO("FormAcquireConnectionTest_0002 start");
    int64_t formId = 1;
    FormSupplyCallback formSupplyCallback;
    EXPECT_EQ(formSupplyCallback.IsRemoveConnection(formId, nullptr), true);
    GTEST_LOG_(INFO) << "FormAcquireConnectionTest_0002 end";
}

/**
 * @tc.name: FormAcquireConnectionTest_0003
 * @tc.desc: test RemoveConnection function and hostToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSupplyCallbackTest, FormAcquireConnectionTest_0003, TestSize.Level0)
{
    HILOG_INFO("FormAcquireConnectionTest_0003 start");
    int64_t formId = 1;
    FormSupplyCallback formSupplyCallback;
    formSupplyCallback.RemoveConnection(formId, nullptr);
    GTEST_LOG_(INFO) << "FormAcquireConnectionTest_0003 end";
}

/**
 * @tc.name: FormAcquireConnectionTest_0004
 * @tc.desc: test RemoveConnection function and GetFormId is 2
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSupplyCallbackTest, FormAcquireConnectionTest_0004, TestSize.Level0)
{
    HILOG_INFO("FormAcquireConnectionTest_0004 start");
    int64_t formId = 1;
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    sptr<FormAbilityConnection> providerToken = new (std::nothrow) FormAbilityConnection();
    FormSupplyCallback formSupplyCallback;
    // add connection
    formSupplyCallback.AddConnection(providerToken);
    // test RemoveConnection function
    formSupplyCallback.RemoveConnection(formId, hostToken);
    GTEST_LOG_(INFO) << "FormAcquireConnectionTest_0004 end";
}

/**
 * @tc.name: FormAcquireConnectionTest_0005
 * @tc.desc: test IsRemoveConnection function and GetFormId is 2
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSupplyCallbackTest, FormAcquireConnectionTest_0005, TestSize.Level0)
{
    HILOG_INFO("FormAcquireConnectionTest_0005 start");
    int64_t formId = 1;
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    sptr<FormAbilityConnection> providerToken = new (std::nothrow) FormAbilityConnection();
    FormSupplyCallback formSupplyCallback;
    // add connection
    formSupplyCallback.AddConnection(providerToken);
    // test IsRemoveConnection function
    formSupplyCallback.IsRemoveConnection(formId, hostToken);
    GTEST_LOG_(INFO) << "FormAcquireConnectionTest_0005 end";
}

/**
 * @tc.name: FormAcquireConnectionTest_0006
 * @tc.desc: test HandleHostDied function and hostToken is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSupplyCallbackTest, FormAcquireConnectionTest_0006, TestSize.Level0)
{
    HILOG_INFO("FormAcquireConnectionTest_0006 start");
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    FormSupplyCallback formSupplyCallback;
    // test HandleHostDied function
    formSupplyCallback.HandleHostDied(hostToken);
    GTEST_LOG_(INFO) << "FormAcquireConnectionTest_0006 end";
}

/**
 * @tc.name: FormAcquireConnectionTest_0007
 * @tc.desc: test HandleHostDied function and hostToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSupplyCallbackTest, FormAcquireConnectionTest_0007, TestSize.Level0)
{
    HILOG_INFO("FormAcquireConnectionTest_0007 start");
    FormSupplyCallback formSupplyCallback;
    // test HandleHostDied function
    formSupplyCallback.HandleHostDied(nullptr);
    GTEST_LOG_(INFO) << "FormAcquireConnectionTest_0007 end";
}

/**
 * @tc.name: FormAcquireConnectionTest_0008
 * @tc.desc: test HandleHostDied function and hostToken is not nullptr GetHostToken is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSupplyCallbackTest, FormAcquireConnectionTest_0008, TestSize.Level0)
{
    HILOG_INFO("FormAcquireConnectionTest_0008 start");
    FormAbilityConnection formAbilityConnection;
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    sptr<FormAbilityConnection> providerToken = new (std::nothrow) FormAbilityConnection();
    FormSupplyCallback formSupplyCallback;
    // add connection
    formSupplyCallback.AddConnection(providerToken);
    // GetHostToken is not nullptr
    formAbilityConnection.SetHostToken(hostToken);
    // test HandleHostDied function
    formSupplyCallback.HandleHostDied(hostToken);
    GTEST_LOG_(INFO) << "FormAcquireConnectionTest_0008 end";
}

/**
 * @tc.name: FormAcquireConnectionTest_0009
 * @tc.desc: test HandleHostDied function and hostToken is not nullptr GetHostToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormSupplyCallbackTest, FormAcquireConnectionTest_0009, TestSize.Level0)
{
    HILOG_INFO("FormAcquireConnectionTest_0009 start");
    sptr<IRemoteObject> hostToken = new (std::nothrow) MockFormProviderClient();
    sptr<FormAbilityConnection> providerToken = new (std::nothrow) FormAbilityConnection();
    FormSupplyCallback formSupplyCallback;
    // add connection
    formSupplyCallback.AddConnection(providerToken);
    // GetHostToken is nullptr
    FormAbilityConnection formAbilityConnection;
    formAbilityConnection.SetHostToken(nullptr);
    // test HandleHostDied function
    formSupplyCallback.HandleHostDied(hostToken);
    GTEST_LOG_(INFO) << "FormAcquireConnectionTest_0009 end";
}
}