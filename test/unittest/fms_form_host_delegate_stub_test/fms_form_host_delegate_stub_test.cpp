/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <map>
#include <string>
#include <thread>

#include "appexecfwk_errors.h"
#include "data_proxy_observer_stub.h"
#include "datashare_log.h"
#include "datashare_helper.h"
#include "form_constants.h"
#define private public
#include "form_host_delegate_stub.h"
#include "data_center/form_info/form_item_info.h"
#undef private
#include "form_mgr_errors.h"
#include "data_center/form_record/form_record.h"
#include "common/util/form_util.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"


using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int64_t TEST_FORM_ID = 1001LL;

class FmsFormHostDelegateStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormHostDelegateStubTest::SetUpTestCase()
{}

void FmsFormHostDelegateStubTest::TearDownTestCase()
{}

void FmsFormHostDelegateStubTest::SetUp()
{}

void FmsFormHostDelegateStubTest::TearDown()
{}

class MockFormHostDelegateCallback : public FormHostDelegateStub {
public:
    MockFormHostDelegateCallback() {};
    virtual ~MockFormHostDelegateCallback() {};

    sptr<IRemoteObject> AsObject() override
    {
        if (!asObject_) {
            return nullptr;
        }
        return this;
    };

    int32_t RouterEvent(const int64_t formId, const Want &want) override
    {
        return ERR_OK;
    };

    bool asObject_ = true;
};

/**
 * @tc.name: FormHostDelegateStubTest_001
 * @tc.desc: Verify OnRemoteRequest function and remoteDescriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_001, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_ROUTER_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_TRANSACTION_FAILED);
}

/**
 * @tc.name: FormHostDelegateStubTest_002
 * @tc.desc: Verify OnRemoteRequest function and memberFunc is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_002, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_ROUTER_EVENT) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormHostDelegateStubTest_003
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRouterEvent interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.want is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_003, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_ROUTER_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    data.WriteInt64(TEST_FORM_ID);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: FormHostDelegateStubTest_004
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRouterEvent interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_004, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    data.WriteInt64(TEST_FORM_ID);
    Want want = {};
    data.WriteParcelable(&want);
    constexpr uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_ROUTER_EVENT);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}
}