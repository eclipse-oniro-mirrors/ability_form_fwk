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
#include <iremote_stub.h>

#define private public
#include "feature/form_share/form_distributed_client.h"
#undef private
#include "form_mgr_errors.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "mock_distributed_sched.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormDistributedClientTestClass : public FormDistributedClient {
public:
    FormDistributedClientTestClass() = default;
    virtual ~FormDistributedClientTestClass() = default;
};

class FmsFormDistributedClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormDistributedClientTest::SetUpTestCase()
{}

void FmsFormDistributedClientTest::TearDownTestCase()
{}

void FmsFormDistributedClientTest::SetUp()
{}

void FmsFormDistributedClientTest::TearDown()
{}

/**
 * @tc.name: ShareForm_0100
 * @tc.desc: Mobile that can run ohos test framework
 * @tc.type: ShareForm
 * @tc.require: issueI581YL
 */
HWTEST_F(FmsFormDistributedClientTest, ShareForm_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDistributedClientTest ShareForm_0100 start";
    std::string remoteDeviceId = "15010038475446345206751dbcda572b";
    FormShareInfo formShareInfo;
    FormDistributedClientTestClass formDmsClient;
    formDmsClient.dmsProxy_ = new OHOS::DistributedSchedule::DistributedSchedService();
    EXPECT_TRUE(ERR_OK == formDmsClient.ShareForm(remoteDeviceId, formShareInfo));
    GTEST_LOG_(INFO) << "FmsFormDistributedClientTest ShareForm_0100 end";
}

/**
 * @tc.name: ShareForm_0200
 * @tc.desc: Mobile that can run ohos test framework
 * @tc.type: ShareForm
 * @tc.require: issueI581YL
 */
HWTEST_F(FmsFormDistributedClientTest, ShareForm_0200, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDistributedClientTest ShareForm_0200 start";
    std::string remoteDeviceId = "";
    FormShareInfo formShareInfo;
    FormDistributedClientTestClass formDmsClient;
    EXPECT_TRUE(ERR_OK != formDmsClient.ShareForm(remoteDeviceId, formShareInfo));
    GTEST_LOG_(INFO) << "FmsFormDistributedClientTest ShareForm_0200 end";
}

/**
 * @tc.name: GetDmsServiceProxy_0100
 * @tc.desc: Mobile that can run ohos test framework
 * @tc.type: GetDmsServiceProxy
 * @tc.require: issueI581YL
 */
HWTEST_F(FmsFormDistributedClientTest, GetDmsServiceProxy_0100, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FmsFormDistributedClientTest GetDmsServiceProxy_0100 start";
    FormDistributedClientTestClass formDmsClient;
    EXPECT_TRUE((formDmsClient.dmsProxy_ == nullptr));
    formDmsClient.GetDmsServiceProxy();
    GTEST_LOG_(INFO) << "FmsFormDistributedClientTest GetDmsServiceProxy_0100 end";
}
}