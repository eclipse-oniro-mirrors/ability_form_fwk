/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#define private public
#include "form_publish_interceptor_stub.h"
#include "form_item_info.h"
#undef private
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_record.h"
#include "form_util.h"
#include "fms_log_wrapper.h"
#include "ipc_skeleton.h"


using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormPublishInterceptorStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormPublishInterceptorStubTest::SetUpTestCase()
{}

void FormPublishInterceptorStubTest::TearDownTestCase()
{}

void FormPublishInterceptorStubTest::SetUp()
{}

void FormPublishInterceptorStubTest::TearDown()
{}

class MockFormPublishInterceptorCallback : public FormPublishInterceptorStub {
public:
    MockFormPublishInterceptorCallback() {};
    virtual ~MockFormPublishInterceptorCallback() {};

    sptr<IRemoteObject> AsObject() override
    {
        if (!asObject_) {
            return nullptr;
        }
        return this;
    };

    bool asObject_ = true;
};

/**
 * @tc.name: FormPublishInterceptorStubTest_001
 * @tc.desc: VVerify OnRemoteRequest function and remoteDescriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(FormPublishInterceptorStubTest, FormPublishInterceptorStubTest_001, TestSize.Level0)
{
    FormPublishInterceptorStub formPublishInterceptorStub;
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    int ret = formPublishInterceptorStub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormPublishInterceptorStubTest_002
 * @tc.desc: Verify OnRemoteRequest function and memberFunc is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormPublishInterceptorStubTest, FormPublishInterceptorStubTest_002, TestSize.Level0)
{
    sptr<MockFormPublishInterceptorCallback> callback = new (std::nothrow) MockFormPublishInterceptorCallback();
    uint32_t code = static_cast<uint32_t>(IFormPublishInterceptor::Message::FORM_PROCESS_PUBLISH_FORM) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormPublishInterceptorCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormPublishInterceptorStubTest_003
 * @tc.desc: 1.Verify OnRemoteRequest and HandleProcessPublishForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.want is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormPublishInterceptorStubTest, FormPublishInterceptorStubTest_003, TestSize.Level0)
{
    sptr<MockFormPublishInterceptorCallback> callback = new (std::nothrow) MockFormPublishInterceptorCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormPublishInterceptor::Message::FORM_PROCESS_PUBLISH_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormPublishInterceptorCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormPublishInterceptorStubTest_004
 * @tc.desc: 1.Verify OnRemoteRequest and HandleProcessPublishForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormPublishInterceptorStubTest, FormPublishInterceptorStubTest_004, TestSize.Level0)
{
    Want want = {};
    sptr<MockFormPublishInterceptorCallback> callback = new (std::nothrow) MockFormPublishInterceptorCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormPublishInterceptor::Message::FORM_PROCESS_PUBLISH_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormPublishInterceptorCallback::GetDescriptor());
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}
}