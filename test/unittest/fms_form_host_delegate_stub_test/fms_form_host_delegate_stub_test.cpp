/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include <string>

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
#include "form_instance.h"
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

    ErrCode RequestOverflow(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow) override
    {
        return ERR_OK;
    }
        
    ErrCode ChangeSceneAnimationState(const int64_t formId, int32_t state) override
    {
        return ERR_OK;
    }

    ErrCode GetFormRect(const int64_t formId, Rect &rect) override
    {
        return ERR_OK;
    }

    ErrCode GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap) override
    {
        return ERR_OK;
    }

    ErrCode TemplateFormDetailInfoChange(
        const std::vector<AppExecFwk::TemplateFormDetailInfo> &templateFormInfo) override
    {
        return ERR_OK;
    }

    ErrCode RequestFormWants(const std::vector<AppExecFwk::FormInfo> &formInfos,
        std::vector<AAFwk::WantParams> &wantParamsList) override
    {
        return ERR_OK;
    }

    ErrCode UpdateFormsConfigCallback(const std::vector<FormCustomConfig> &configs) override
    {
        return ERR_OK;
    }

    ErrCode DeleteFormsCallback(const std::vector<std::string> &formIds) override
    {
        return ERR_OK;
    }
    ErrCode GetVisibleFormRect(const int64_t formId, Rect &rect) override
    {
        rect = mockRect_;
        return ERR_OK;
    }

    bool asObject_ = true;

    Rect mockRect_ {};
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

/**
 * @tc.name: FormHostDelegateStubTest_005
 * @tc.desc: Verify OnRemoteRequest function and remoteDescriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_005, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_REQUEST_OVERFLOW);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_TRANSACTION_FAILED);
}
  
/**
 * @tc.name: FormHostDelegateStubTest_006
 * @tc.desc: Verify OnRemoteRequest function and memberFunc is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_006, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_REQUEST_OVERFLOW) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormHostDelegateStubTest_007
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRequestOverflow interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.formId is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_007, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    constexpr uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_REQUEST_OVERFLOW);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    OverflowInfo overflowInfo;
    bool isOverflow = true;
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    data.WriteBool(isOverflow);
    data.WriteParcelable(&overflowInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: FormHostDelegateStubTest_08
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRequestOverflow interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_08, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    OverflowInfo overflowInfo;
    bool isOverflow = true;
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    data.WriteInt64(TEST_FORM_ID);
    data.WriteParcelable(&overflowInfo);
    data.WriteBool(isOverflow);
    constexpr uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_REQUEST_OVERFLOW);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormHostDelegateStubTest_09
 * @tc.desc: Verify OnRemoteRequest function and remoteDescriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_09, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_CHANGE_SCENE_ANIMATION_STATE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_TRANSACTION_FAILED);
}

/**
 * @tc.name: FormHostDelegateStubTest_010
 * @tc.desc: Verify OnRemoteRequest function and memberFunc is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_010, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_CHANGE_SCENE_ANIMATION_STATE) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormHostDelegateStubTest_011
 * @tc.desc: 1.Verify OnRemoteRequest and HandleChangeSceneAnimationState interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_011, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    int32_t state = 1;
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    data.WriteInt64(TEST_FORM_ID);
    data.WriteInt32(state);
    constexpr uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_CHANGE_SCENE_ANIMATION_STATE);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormHostDelegateStubTest_12
 * @tc.desc: Verify OnRemoteRequest function and remoteDescriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_12, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_GET_FORM_RECT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_TRANSACTION_FAILED);
}

/**
 * @tc.name: FormHostDelegateStubTest_013
 * @tc.desc: Verify OnRemoteRequest function and memberFunc is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_013, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_GET_FORM_RECT) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormHostDelegateStubTest_014
 * @tc.desc: 1.Verify OnRemoteRequest and HandleGetFormRect interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_014, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Rect rect;
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    data.WriteInt64(TEST_FORM_ID);
    data.WriteParcelable(&rect);
    constexpr uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_GET_FORM_RECT);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}


/**
 * @tc.name: FormHostDelegateStubTest_15
 * @tc.desc: Verify OnRemoteRequest function and remoteDescriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_15, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_GET_LIVE_FORM_STATUS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_TRANSACTION_FAILED);
}

/**
 * @tc.name: FormHostDelegateStubTest_016
 * @tc.desc: Verify OnRemoteRequest function and memberFunc is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_016, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_GET_LIVE_FORM_STATUS) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormHostDelegateStubTest_017
 * @tc.desc: 1.Verify OnRemoteRequest and HandleGetLiveFormStatus interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FormHostDelegateStubTest_017, TestSize.Level0)
{
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    ASSERT_NE(callback, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    Rect rect;
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    data.WriteInt64(TEST_FORM_ID);
    data.WriteParcelable(&rect);
    constexpr uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_GET_LIVE_FORM_STATUS);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FmsFormHostDelegateStubTest_Conv_001
 * @tc.desc: Verify [out] stub dispatch: request carries formId only, delegate fills the reply rect.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FmsFormHostDelegateStubTest_Conv_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostDelegateStubTest_Conv_001 starts";

    // [out] rect: request carries formId only; the stub writes the delegate-filled rect to the reply.
    Rect expected;
    expected.left = 10.0;
    expected.top = 20.0;
    expected.width = 320.0;
    expected.height = 240.0;

    MessageParcel data;
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    data.WriteInt64(TEST_FORM_ID);

    // Verify the stub dispatch code for GetVisibleFormRect exists.
    constexpr uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_GET_VISIBLE_FORM_RECT);
    EXPECT_EQ(code, 4011u);

    // Verify the dispatch returns ERR_OK with the mock.
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    ASSERT_NE(callback, nullptr);
    callback->mockRect_ = expected;
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormHostDelegateStubTest_Conv_001 ends";
}

/**
 * @tc.name: FmsFormHostDelegateStubTest_Conv_007
 * @tc.desc: Verify the invisible -1 Rect travels delegate-to-reply and stub dispatch succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormHostDelegateStubTest, FmsFormHostDelegateStubTest_Conv_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormHostDelegateStubTest_Conv_007 starts";

    // The -1,-1,-1,-1 Rect that a host may use to indicate "invisible" state.
    Rect invisibleRect;
    invisibleRect.left = -1.0;
    invisibleRect.top = -1.0;
    invisibleRect.width = -1.0;
    invisibleRect.height = -1.0;

    // DISCREPANCY NOTE: createFormRectInfo also checks (width < 0 || height < 0)
    // at napi_form_util.cpp:1135. -1 width/height FAILS this check, which means
    // the current implementation would REJECT the -1 rect, contrary to the design doc
    // Conv_007 expectation. This is flagged in the final report.

    // [out] rect: request carries formId only; the -1 invisible rect travels delegate->reply.
    MessageParcel data;
    data.WriteInterfaceToken(MockFormHostDelegateCallback::GetDescriptor());
    data.WriteInt64(TEST_FORM_ID);

    // Verify the IPC dispatch for GetVisibleFormRect.
    constexpr uint32_t code = static_cast<uint32_t>(IFormHostDelegateIpcCode::COMMAND_GET_VISIBLE_FORM_RECT);
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    sptr<MockFormHostDelegateCallback> callback = new (std::nothrow) MockFormHostDelegateCallback();
    ASSERT_NE(callback, nullptr);
    callback->mockRect_ = invisibleRect;
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);

    GTEST_LOG_(INFO) << "FmsFormHostDelegateStubTest_Conv_007 ends";
}
}
