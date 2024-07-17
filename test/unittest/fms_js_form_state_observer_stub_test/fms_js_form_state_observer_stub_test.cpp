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
#include <gmock/gmock.h>

#include "appexecfwk_errors.h"
#include "form_mgr_errors.h"
#include "form_constants.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "js_form_state_observer_stub.h"
#include "message_parcel.h"
using namespace testing::ext;

namespace {
static constexpr int32_t MAX_ALLOW_SIZE = 8 * 1024;
static constexpr int32_t TEST_VEC_SIZE = 1;
}
namespace OHOS {
namespace AppExecFwk {
using namespace AbilityRuntime;

class JSFormStateObserverStubTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void JSFormStateObserverStubTest::SetUpTestCase()
{}

void JSFormStateObserverStubTest::TearDownTestCase()
{}

void JSFormStateObserverStubTest::SetUp()
{}

void JSFormStateObserverStubTest::TearDown()
{}

class MockJsFormStateObserverCallback : public JsFormStateObserverStub {
public:
    MockJsFormStateObserverCallback() {};
    virtual ~MockJsFormStateObserverCallback() {};

    int32_t OnAddForm(const std::string &bundleName,
        const RunningFormInfo &runningFormInfo) override
    {
        return ERR_OK;
    };

    int32_t OnRemoveForm(const std::string &bundleName,
        const RunningFormInfo &runningFormInfo) override
    {
        return ERR_OK;
    };

    int32_t OnFormClickEvent(const std::string &bundleName,
        const std::string &formEventType,
        const RunningFormInfo &runningFormInfo) override
    {
        return ERR_OK;
    };

    int32_t NotifyWhetherFormsVisible(const FormVisibilityType visibleType,
        const std::string &bundleName,
        std::vector<FormInstance> &runningFormInfos) override
    {
        return ERR_OK;
    };
};

/**
 * @tc.name: JSFormStateObserverStubTest_001
 * @tc.desc: Verify OnRemoteRequest function and remoteDescriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_001, TestSize.Level0)
{
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback->OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: JSFormStateObserverStubTest_002
 * @tc.desc: Verify OnRemoteRequest function and memberFuncMap_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_002, TestSize.Level0)
{
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code = static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_ADD_FORM) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: JSFormStateObserverStubTest_003
 * @tc.desc: 1.Verify OnRemoteRequest and HandleOnAddForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.RunningFormInfo is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_003, TestSize.Level0)
{
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code = static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_ADD_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteString("bundleName");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: JSFormStateObserverStubTest_004
 * @tc.desc: 1.Verify OnRemoteRequest and HandleOnAddForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_004, TestSize.Level0)
{
    RunningFormInfo runningFormInfo = {};
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code = static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_ADD_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteString("bundleName");
    data.WriteParcelable(&runningFormInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: JSFormStateObserverStubTest_005
 * @tc.desc: 1.Verify OnRemoteRequest and HandleOnRemoveForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.RunningFormInfo is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_005, TestSize.Level0)
{
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code = static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_REMOVE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteString("bundleName");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: JSFormStateObserverStubTest_006
 * @tc.desc: 1.Verify OnRemoteRequest and HandleOnRemoveForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_006, TestSize.Level0)
{
    RunningFormInfo runningFormInfo = {};
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code = static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_REMOVE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteString("bundleName");
    data.WriteParcelable(&runningFormInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: JSFormStateObserverStubTest_007
 * @tc.desc: 1.Verify OnRemoteRequest and HandleNotifyWhetherFormsVisible interface executes as expected.
 *           2.Size < 0
 *           3.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_007, TestSize.Level0)
{
    int32_t size = -1;
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code =
        static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(FormVisibilityType::UNKNOWN));
    data.WriteString("bundleName");
    data.WriteInt32(size);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: JSFormStateObserverStubTest_008
 * @tc.desc: 1.Verify OnRemoteRequest and HandleNotifyWhetherFormsVisible interface executes as expected.
 *           2.Size > MAX_ALLOW_SIZE
 *           3.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_008, TestSize.Level0)
{
    int32_t size = MAX_ALLOW_SIZE + 1;
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code =
        static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(FormVisibilityType::UNKNOWN));
    data.WriteString("bundleName");
    data.WriteInt32(size);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: JSFormStateObserverStubTest_009
 * @tc.desc: 1.Verify OnRemoteRequest and HandleReloadForm interface executes as expected.
 *           2.RunningFormInfo is nullptr
 *           3.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_009, TestSize.Level0)
{
    int32_t size = 1;
    RunningFormInfo runningFormInfo = {};
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code =
        static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(FormVisibilityType::UNKNOWN));
    data.WriteString("bundleName");
    data.WriteInt32(size);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: JSFormStateObserverStubTest_010
 * @tc.desc: 1.Verify OnRemoteRequest and HandleReloadForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_010, TestSize.Level0)
{
    RunningFormInfo runningFormInfo = {};
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code =
        static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_NOTIFY_WHETHER_FORMS_VISIBLE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(FormVisibilityType::UNKNOWN));
    data.WriteString("bundleName");
    data.WriteInt32(TEST_VEC_SIZE);
    data.WriteParcelable(&runningFormInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: JSFormStateObserverStubTest_011
 * @tc.desc: 1.Verify OnRemoteRequest and HandleOnFormClick interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_INSTALLD_PARAM_ERROR.
 *           3.callType is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_011, TestSize.Level0)
{
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code = static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_FORM_CLICK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteString("bundleName");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_INSTALLD_PARAM_ERROR);
}

/**
 * @tc.name: JSFormStateObserverStubTest_012
 * @tc.desc: 1.Verify OnRemoteRequest and HandleOnFormClick interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.RunningFormInfo is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_012, TestSize.Level0)
{
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code = static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_FORM_CLICK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteString("bundleName");
    data.WriteString("callType");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: JSFormStateObserverStubTest_013
 * @tc.desc: 1.Verify OnRemoteRequest and HandleOnFormClick interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(JSFormStateObserverStubTest, JSFormStateObserverStubTest_013, TestSize.Level0)
{
    RunningFormInfo runningFormInfo = {};
    sptr<MockJsFormStateObserverCallback> callback = new (std::nothrow) MockJsFormStateObserverCallback();
    ASSERT_NE(callback, nullptr);
    uint32_t code = static_cast<uint32_t>(IJsFormStateObserver::Message::FORM_STATE_OBSERVER_ON_FORM_CLICK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(JsFormStateObserverStub::GetDescriptor());
    data.WriteString("bundleName");
    data.WriteString("callType");
    data.WriteParcelable(&runningFormInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace AppExecFwk
}  // namespace OHOS
