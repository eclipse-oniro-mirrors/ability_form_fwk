/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <chrono>
#include <dirent.h>
#include <fstream>
#include <gtest/gtest.h>
#include <string>
#include <thread>

#include "form_mgr_errors.h"
#define private public
#include "form_cache_mgr.h"
#include "form_refresh_connection.h"
#include "form_supply_callback.h"
#include "form_util.h"
#undef private
#include "hilog_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FmsFormRefreshConnectionTest : public testing::Test {
public:
    void SetUp();
    void TearDown();
};
void FmsFormRefreshConnectionTest::SetUp()
{}

void FmsFormRefreshConnectionTest::TearDown()
{}

/**
 * @tc.name: FormCacheMgr_001
 * @tc.desc: test GetData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_001 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "aa";
    formCacheMgr.cacheData_.emplace(formId, data);
    EXPECT_EQ(true, formCacheMgr.GetData(formId, data));
    GTEST_LOG_(INFO) << "FormCacheMgr_001 end";
}

/**
 * @tc.name: FormCacheMgr_002
 * @tc.desc: test GetData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_002 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "";
    int64_t formIds = 2;
    formCacheMgr.cacheData_.emplace(formIds, data);
    EXPECT_EQ(false, formCacheMgr.GetData(formId, data));
    GTEST_LOG_(INFO) << "FormCacheMgr_002 end";
}

/**
 * @tc.name: FormCacheMgr_003
 * @tc.desc: test DeleteData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_003 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "aa";
    formCacheMgr.cacheData_.emplace(formId, data);
    EXPECT_EQ(true, formCacheMgr.DeleteData(formId));
    GTEST_LOG_(INFO) << "FormCacheMgr_003 end";
}

/**
 * @tc.name: FormCacheMgr_004
 * @tc.desc: test UpdateData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_004 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "aa";
    EXPECT_EQ(false, formCacheMgr.UpdateData(formId, data));
    GTEST_LOG_(INFO) << "FormCacheMgr_004 end";
}

/**
 * @tc.name: FormCacheMgr_005
 * @tc.desc: test UpdateData function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_005 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    std::string data = "aa";
    formCacheMgr.cacheData_.emplace(formId, data);
    EXPECT_EQ(true, formCacheMgr.UpdateData(formId, data));
    GTEST_LOG_(INFO) << "FormCacheMgr_005 end";
}

/**
 * @tc.name: FormCacheMgr_006
 * @tc.desc: test IsExist function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormCacheMgr_006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormCacheMgr_006 start";
    FormCacheMgr formCacheMgr;
    int64_t formId = 1;
    int64_t formIds = 2;
    std::string data = "aa";
    formCacheMgr.cacheData_.emplace(formIds, data);
    EXPECT_EQ(false, formCacheMgr.IsExist(formId));
    GTEST_LOG_(INFO) << "FormCacheMgr_006 end";
}

/**
 * @tc.name: FormRefreshConnection_001
 * @tc.desc: test IsExist function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormRefreshConnection_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRefreshConnection_001 start";
    int64_t formId = 1;
    Want want;
    std::string bundleName = "aa";
    std::string abilityName = "bb";
    bool isFreeInstall = false;
    FormRefreshConnection formRefreshConnection(formId, want, bundleName, abilityName, isFreeInstall);
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject = nullptr;
    int resultCode = 100;
    formRefreshConnection.OnAbilityConnectDone(element, remoteObject, resultCode);
    GTEST_LOG_(INFO) << "FormRefreshConnection_001 end";
}

/**
 * @tc.name: FormUtil_001
 * @tc.desc: test PaddingUdidHash function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormUtil_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormUtil_001 start";
    FormUtil formUtil;
    uint64_t formId = 0;
    uint64_t udidHash = 3;
    EXPECT_EQ(3, formUtil.PaddingUdidHash(formId, udidHash));
    GTEST_LOG_(INFO) << "FormUtil_001 end";
}

/**
 * @tc.name: FormUtil_002
 * @tc.desc: test GenerateUdidHash function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormUtil_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormUtil_002 start";
    FormUtil formUtil;
    int64_t udidHash = 100;
    EXPECT_EQ(true, formUtil.GenerateUdidHash(udidHash));
    GTEST_LOG_(INFO) << "FormUtil_002 end";
}

/**
 * @tc.name: FormSupplyCallback_001
 * @tc.desc: test AddConnection function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormSupplyCallback_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormSupplyCallback_001 start";
    FormSupplyCallback formSupplyCallback;
    sptr<FormAbilityConnection> connection = nullptr;
    formSupplyCallback.AddConnection(connection);
    GTEST_LOG_(INFO) << "FormSupplyCallback_001 end";
}

/**
 * @tc.name: FormSupplyCallback_002
 * @tc.desc: test CanDisconnect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormSupplyCallback_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormSupplyCallback_002 start";
    FormSupplyCallback formSupplyCallback;
    sptr<FormAbilityConnection> connection = nullptr;
    EXPECT_EQ(false, formSupplyCallback.CanDisconnect(connection));
    GTEST_LOG_(INFO) << "FormSupplyCallback_002 end";
}

/**
 * @tc.name: FormSupplyCallback_003
 * @tc.desc: test CanDisconnect function.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormRefreshConnectionTest, FormSupplyCallback_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormSupplyCallback_003 start";
    FormSupplyCallback formSupplyCallback;
    sptr<FormAbilityConnection> connection = new (std::nothrow) FormAbilityConnection();
    EXPECT_EQ(false, formSupplyCallback.CanDisconnect(connection));
    GTEST_LOG_(INFO) << "FormSupplyCallback_003 end";
}
}