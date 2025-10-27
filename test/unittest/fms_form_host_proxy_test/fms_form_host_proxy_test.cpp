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
#include <gtest/gtest.h>

#include "appexecfwk_errors.h"
#define private public
#define protected public
#include "form_host_proxy.h"
#undef private
#undef protected
#include "form_constants.h"
#include "message_parcel.h"
#include "mock_i_remote_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockWriteInterfaceToken(bool mockRet);

namespace {
class FmsFormHostProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
};

void FmsFormHostProxyTest::SetUpTestCase() {}
void FmsFormHostProxyTest::TearDownTestCase() {}
void FmsFormHostProxyTest::SetUp()
{
    MockWriteInterfaceToken(true);
}
void FmsFormHostProxyTest::TearDown() {}

/*
 * @tc.name: OnAcquiredTest_0100
 * @tc.desc: test OnAcquired function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnAcquiredTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnAcquiredTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormJsInfo formInfo;
    sptr<IRemoteObject> token = nullptr;
    proxy->OnAcquired(formInfo, token);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnAcquiredTest_0200
 * @tc.desc: test OnAcquired function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnAcquiredTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnAcquiredTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormJsInfo formInfo;
    sptr<IRemoteObject> token = nullptr;
    proxy->OnAcquired(formInfo, token);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnAcquiredTest_0300
 * @tc.desc: test OnAcquired function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnAcquiredTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnAcquiredTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormJsInfo formInfo;
    sptr<IRemoteObject> token = nullptr;
    proxy->OnAcquired(formInfo, token);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnUpdateTest_0100
 * @tc.desc: test OnUpdate function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnUpdateTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnUpdateTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormJsInfo formInfo;
    proxy->OnUpdate(formInfo);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnUpdateTest_0200
 * @tc.desc: test OnUpdate function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnUpdateTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnUpdateTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormJsInfo formInfo;
    proxy->OnUpdate(formInfo);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnUninstallTest_0100
 * @tc.desc: test OnUninstall function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnUninstallTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnUninstallTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    proxy->OnUninstall(formIds);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnUninstallTest_0200
 * @tc.desc: test OnUninstall function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnUninstallTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnUninstallTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    proxy->OnUninstall(formIds);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnAcquireStateTest_0100
 * @tc.desc: test OnAcquireState function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnAcquireStateTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnAcquireStateTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormState state = FormState::DEFAULT;
    AAFwk::Want want;
    proxy->OnAcquireState(state, want);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnAcquireStateTest_0200
 * @tc.desc: test OnAcquireState function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnAcquireStateTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnAcquireStateTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormState state = FormState::DEFAULT;
    AAFwk::Want want;
    proxy->OnAcquireState(state, want);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnAcquireStateTest_0300
 * @tc.desc: test OnAcquireState function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnAcquireStateTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnAcquireStateTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    FormState state = FormState::DEFAULT;
    AAFwk::Want want;
    proxy->OnAcquireState(state, want);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnShareFormResponseTest_0100
 * @tc.desc: test OnShareFormResponse function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnShareFormResponseTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnShareFormResponseTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnShareFormResponse(0, 0);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnShareFormResponseTest_0200
 * @tc.desc: test OnShareFormResponse function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnShareFormResponseTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnShareFormResponseTest_0100, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnShareFormResponse(0, 0);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnShareFormResponseTest_0300
 * @tc.desc: test OnShareFormResponse function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnShareFormResponseTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnShareFormResponseTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    proxy->OnShareFormResponse(0, 0);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnAcquireDataResponseTest_0100
 * @tc.desc: test OnAcquireDataResponse function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnAcquireDataResponseTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnAcquireDataResponseTest_0100, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    AAFwk::WantParams wantParams;
    proxy->OnAcquireDataResponse(wantParams, 0);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnAcquireDataResponseTest_0200
 * @tc.desc: test OnAcquireDataResponse function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnAcquireDataResponseTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnAcquireDataResponseTest_0200, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(ERR_OK)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    AAFwk::WantParams wantParams;
    proxy->OnAcquireDataResponse(wantParams, 0);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnAcquireDataResponseTest_0300
 * @tc.desc: test OnAcquireDataResponse function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnAcquireDataResponseTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnAcquireDataResponseTest_0300, TestSize.Level1";
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    EXPECT_CALL(*iremoteObject, SendRequest(_, _, _, _)).Times(1)
        .WillRepeatedly(DoAll(Return(-1)));
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    AAFwk::WantParams wantParams;
    proxy->OnAcquireDataResponse(wantParams, 0);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: OnEnableFormTest_0301
 * @tc.desc: test OnEnableForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, OnEnableFormTest_0301, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, OnEnableFormTest_0301, TestSize.Level1";
    MockWriteInterfaceToken(false);
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    ASSERT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    ASSERT_NE(nullptr, proxy);
    std::vector<int64_t> formIds{0};
    proxy->OnEnableForm(formIds, true);
    proxy->OnEnableForm(formIds, false);
    EXPECT_NE(proxy, nullptr);
}

/*
 * @tc.name: FormHostProxyTest_001
 * @tc.desc: test OnError function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, FormHostProxyTest_001, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, FormHostProxyTest_001, TestSize.Level1";
    MockWriteInterfaceToken(false);
    int32_t errorCode = 1;
    std::string errorMsg = "errorMsg";
    std::vector<int64_t> formIds{0};
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    EXPECT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    EXPECT_NE(nullptr, proxy);
    proxy->OnError(errorCode, errorMsg);
    proxy->OnError(errorCode, errorMsg, formIds);
    MockWriteInterfaceToken(true);
    proxy->OnError(errorCode, errorMsg);
    proxy->OnError(errorCode, errorMsg, formIds);
}

/*
 * @tc.name: FormHostProxyTest_002
 * @tc.desc: test OnRecycleForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, FormHostProxyTest_002, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, FormHostProxyTest_002, TestSize.Level1";
    MockWriteInterfaceToken(false);
    int64_t formId = 1;
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    EXPECT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    EXPECT_NE(nullptr, proxy);
    proxy->OnRecycleForm(formId);
    MockWriteInterfaceToken(true);
    proxy->OnRecycleForm(formId);
}

/*
 * @tc.name: FormHostProxyTest_003
 * @tc.desc: test OnLockForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, FormHostProxyTest_003, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, FormHostProxyTest_003, TestSize.Level1";
    MockWriteInterfaceToken(false);
    std::vector<int64_t> formIds{0};
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    EXPECT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    EXPECT_NE(nullptr, proxy);
    proxy->OnLockForm(formIds, true);
    proxy->OnLockForm(formIds, false);
    MockWriteInterfaceToken(true);
    proxy->OnLockForm(formIds, true);
    proxy->OnLockForm(formIds, false);
}

/*
 * @tc.name: FormHostProxyTest_004
 * @tc.desc: test OnDueControlForm function
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostProxyTest, FormHostProxyTest_004, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "FmsFormHostProxyTest, FormHostProxyTest_004, TestSize.Level1";
    MockWriteInterfaceToken(false);
    std::vector<int64_t> formIds{0};
    sptr<MockIRemoteObject> iremoteObject = new (std::nothrow) MockIRemoteObject();
    EXPECT_NE(nullptr, iremoteObject);
    std::shared_ptr<FormHostProxy> proxy = std::make_shared<FormHostProxy>(iremoteObject);
    EXPECT_NE(nullptr, proxy);
    proxy->OnDueControlForm(formIds, true, true);
    proxy->OnDueControlForm(formIds, true, false);
    proxy->OnDueControlForm(formIds, false, true);
    proxy->OnDueControlForm(formIds, false, false);
    MockWriteInterfaceToken(true);
    proxy->OnDueControlForm(formIds, true, true);
    proxy->OnDueControlForm(formIds, true, false);
    proxy->OnDueControlForm(formIds, false, true);
    proxy->OnDueControlForm(formIds, false, false);
}
}
