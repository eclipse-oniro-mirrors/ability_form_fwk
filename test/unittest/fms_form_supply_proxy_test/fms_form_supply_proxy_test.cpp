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
#include <chrono>
#include <gtest/gtest.h>
#define private public
#define protected public
#include "appexecfwk_errors.h"
#include "form_supply_proxy.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "message_parcel.h"
#include "mock_i_remote_object.h"
#undef private
#undef protected
using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace AppExecFwk {
const std::int32_t ERROR_NUM = -1;
class FormSupplyProxyTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void FormSupplyProxyTest::SetUpTestCase()
{}

void FormSupplyProxyTest::TearDownTestCase()
{}

void FormSupplyProxyTest::SetUp()
{}

void FormSupplyProxyTest::TearDown()
{}

/*
* @tc.name: FormSupplyProxyTest_001
* @tc.name: OnAcquire
* @tc.desc: Verify function OnAcquire return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_001, TestSize.Level1";
    FormProviderInfo formInfo;
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERR_OK, proxy->OnAcquire(formInfo, want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_001, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_002
* @tc.name: OnAcquire
* @tc.desc: Verify function OnAcquire return value is ERROR_NUM
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_002, TestSize.Level1";
    FormProviderInfo formInfo;
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERROR_NUM)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERROR_NUM, proxy->OnAcquire(formInfo, want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_002, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_003
* @tc.name: OnEventHandle
* @tc.desc: Verify function OnEventHandle return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_003, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_003, TestSize.Level1";
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERR_OK, proxy->OnEventHandle(want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_003, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_004
* @tc.name: OnEventHandle
* @tc.desc: Verify function OnEventHandle return value is ERROR_NUM
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_004, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_004, TestSize.Level1";
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERROR_NUM)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERROR_NUM, proxy->OnEventHandle(want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_004, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_005
* @tc.name: OnAcquireStateResult
* @tc.desc: Verify function OnAcquireStateResult return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_005, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_005, TestSize.Level1";
    FormState state = FormState::DEFAULT;
    std::string provider;
    Want wantArg;
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERR_OK, proxy->OnAcquireStateResult(state, provider, wantArg, want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_005, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_006
* @tc.name: OnAcquireStateResult
* @tc.desc: Verify function OnAcquireStateResult return value is ERROR_NUM
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_006, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_006, TestSize.Level1";
    FormState state = FormState::DEFAULT;
    std::string provider;
    Want wantArg;
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERROR_NUM)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERROR_NUM, proxy->OnAcquireStateResult(state, provider, wantArg, want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_006, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_007
* @tc.name: OnShareAcquire
* @tc.desc: Verify function OnShareAcquire is called, function SendRequest ruturn value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_007, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_007, TestSize.Level1";
    int64_t formId = 1;
    std::string remoteDeviceId;
    const AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    bool result = true;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnShareAcquire(formId, remoteDeviceId, wantParams, requestCode, result);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_007, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_008
* @tc.name: OnShareAcquire
* @tc.desc: Verify function OnShareAcquire is called, function SendRequest ruturn value is ERROR_NUM
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_008, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_008, TestSize.Level1";
    int64_t formId = 1;
    std::string remoteDeviceId;
    const AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    bool result = true;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERROR_NUM)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnShareAcquire(formId, remoteDeviceId, wantParams, requestCode, result);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_008, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_009
* @tc.name: OnRenderTaskDone
* @tc.desc: Verify function OnRenderTaskDone return value is ERROR_NUM
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_009, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_009, TestSize.Level1";
    int64_t formId = 1;
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERROR_NUM)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERROR_NUM, proxy->OnRenderTaskDone(formId, want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_009, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_010
* @tc.name: OnRenderTaskDone
* @tc.desc: Verify function OnRenderTaskDone return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_010, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_010, TestSize.Level1";
    int64_t formId = 1;
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERR_OK, proxy->OnRenderTaskDone(formId, want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_010, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_011
* @tc.name: OnStopRenderingTaskDone
* @tc.desc: Verify function OnStopRenderingTaskDone return value is ERROR_NUM
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_011, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_011, TestSize.Level1";
    int64_t formId = 1;
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERROR_NUM)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERROR_NUM, proxy->OnStopRenderingTaskDone(formId, want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_011, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_012
* @tc.name: OnStopRenderingTaskDone
* @tc.desc: Verify function OnStopRenderingTaskDone return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_012, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_012, TestSize.Level1";
    int64_t formId = 1;
    Want want;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERR_OK, proxy->OnStopRenderingTaskDone(formId, want));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_012, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_013
* @tc.name: OnRenderTaskDone
* @tc.desc: Verify function OnRenderTaskDone return value is ERROR_NUM
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_013, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_013, TestSize.Level1";
    int64_t requestCode = 1;
    AAFwk::WantParams wantParams;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERROR_NUM)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERROR_NUM, proxy->OnAcquireDataResult(wantParams, requestCode));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_013, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_014
* @tc.name: OnRenderTaskDone
* @tc.desc: Verify function OnRenderTaskDone return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_014, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_014, TestSize.Level1";
    int64_t requestCode = 1;
    AAFwk::WantParams wantParams;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    EXPECT_EQ(ERR_OK, proxy->OnAcquireDataResult(wantParams, requestCode));
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_014, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_015
* @tc.name: OnRecoverFormsByConfigUpdate
* @tc.desc: Verify function OnRecoverFormsByConfigUpdate return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_015, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_015, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(iremoteObject, nullptr);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(proxy, nullptr);
    std::vector<int64_t> formIds;
    EXPECT_EQ(proxy->OnRecoverFormsByConfigUpdate(formIds), ERR_OK);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_015, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_016
* @tc.name: OnRecoverFormsByConfigUpdate
* @tc.desc: Verify function OnRecoverFormsByConfigUpdate return value is ERROR_NUM
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_016, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_016, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(iremoteObject, nullptr);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERROR_NUM)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(proxy, nullptr);
    std::vector<int64_t> formIds;
    EXPECT_EQ(proxy->OnRecoverFormsByConfigUpdate(formIds), ERROR_NUM);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_016, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_017
* @tc.name: OnRenderingBlock
* @tc.desc: Verify function OnRenderingBlock return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_017, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_017, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(iremoteObject, nullptr);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(proxy, nullptr);
    std::string bundleName = "bundleName";
    EXPECT_EQ(proxy->OnRenderingBlock(bundleName), ERR_OK);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_017, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_018
* @tc.name: OnRecycleForm
* @tc.desc: Verify function OnRecycleForm return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_018, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_018, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(iremoteObject, nullptr);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(proxy, nullptr);
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(proxy->OnRecycleForm(formId, want), ERR_OK);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_018, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_019
* @tc.name: OnNotifyRefreshForm
* @tc.desc: Verify function OnNotifyRefreshForm return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_019, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_019, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(iremoteObject, nullptr);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(proxy, nullptr);
    int64_t formId = 1;
    EXPECT_EQ(proxy->OnNotifyRefreshForm(formId), ERR_OK);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_019, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_020
* @tc.name: OnRenderFormDone
* @tc.desc: Verify function OnRenderFormDone return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_020, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_020, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(iremoteObject, nullptr);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(proxy, nullptr);
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(proxy->OnRenderFormDone(formId, want), ERR_OK);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_020, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_021
* @tc.name: OnRecoverFormDone
* @tc.desc: Verify function OnRecoverFormDone return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_021, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_021, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(iremoteObject, nullptr);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(proxy, nullptr);
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(proxy->OnRecoverFormDone(formId, want), ERR_OK);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_021, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_022
* @tc.name: OnRecycleFormDone
* @tc.desc: Verify function OnRecycleFormDone return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_022, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_022, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(iremoteObject, nullptr);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(proxy, nullptr);
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(proxy->OnRecycleFormDone(formId, want), ERR_OK);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_022, TestSize.Level1";
}

/*
* @tc.name: FormSupplyProxyTest_023
* @tc.name: OnDeleteFormDone
* @tc.desc: Verify function OnDeleteFormDone return value is ERR_OK
*/
HWTEST_F(FormSupplyProxyTest, FormSupplyProxyTest_023, TestSize.Level1)
{
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_023, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(iremoteObject, nullptr);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1).WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormSupplyProxy> proxy = std::make_shared<FormSupplyProxy>(iremoteObject);
    ASSERT_NE(proxy, nullptr);
    int64_t formId = 1;
    Want want;
    EXPECT_EQ(proxy->OnDeleteFormDone(formId, want), ERR_OK);
    GTEST_LOG_(INFO)<< "FormSupplyProxyTest, FormSupplyProxyTest_023, TestSize.Level1";
}
}  // namespace AppExecFwk
}  // namespace OHOS