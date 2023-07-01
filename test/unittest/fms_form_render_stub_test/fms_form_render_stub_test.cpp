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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#define private public
#define protected public
#include "appexecfwk_errors.h"
#include "element_name.h"
#include "form_mgr_errors.h"
#include "form_constants.h"
#include "form_render_stub.h"
#include "form_supply_stub.h"
#include "ipc_types.h"
#include "iremote_broker.h"
#include "message_parcel.h"
#undef public
#undef protected
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FormRenderStubTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormRenderStubTest::SetUpTestCase()
{}

void FormRenderStubTest::TearDownTestCase()
{}

void FormRenderStubTest::SetUp()
{}

void FormRenderStubTest::TearDown()
{}

class MockFormRenderImpl : public FormRenderStub {
public:
    MockFormRenderImpl() {};
    virtual ~MockFormRenderImpl() {};

    int32_t RenderForm(const FormJsInfo &formJsInfo, const Want &want,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    };

    int32_t StopRenderingForm(
        const FormJsInfo &formJsInfo, const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    };

    int32_t CleanFormHost(const sptr<IRemoteObject> &hostToken) override
    {
        return ERR_OK;
    };

    int32_t ReloadForm(const std::vector<FormJsInfo> &&formJsInfos, const Want &want) override
    {
        return ERR_OK;
    };
};

class MockFormSupplyStub : public FormSupplyStub {
public:
    MockFormSupplyStub() {};
    virtual ~MockFormSupplyStub() {};
    int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return number_;
    };
    int HandleOnAcquire(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int HandleOnEventHandle(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int HandleOnAcquireStateResult(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int32_t HandleOnShareAcquire(MessageParcel &data, MessageParcel &reply)
    {
        return number_;
    };
    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override
    {
        return number_;
    };
    int OnEventHandle(const Want &want) override
    {
        return number_;
    };
    int OnAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg,
        const Want &want) override
    {
        return number_;
    };
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode)
    {
        return ERR_OK;
    };
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    };
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    const int number_ = 1;
};

/**
 * @tc.name: FormRenderStubTest_001
 * @tc.desc: Verify OnRemoteRequest function and remoteDescriptor is empty
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_001, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = 1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    auto result = callback->OnRemoteRequest(code, data, reply, option);

    EXPECT_EQ(result, ERR_APPEXECFWK_FORM_INVALID_PARAM);
}

/**
 * @tc.name: FormRenderStubTest_002
 * @tc.desc: Verify OnRemoteRequest function and memberFuncMap_ is empty
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_002, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RENDER_FORM) + 100;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormRenderStubTest_003
 * @tc.desc: Verify OnRemoteRequest function and memberFunc is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_003, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RENDER_FORM) + 100;
    callback->memberFuncMap_[code] = nullptr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, IPC_STUB_UNKNOW_TRANS_ERR);
}

/**
 * @tc.name: FormRenderStubTest_004
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRenderForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.FormJsInfo is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_004, TestSize.Level0)
{
    Want want = {};
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RENDER_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_005
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRenderForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.Want is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_005, TestSize.Level0)
{
    FormJsInfo formJsInfo = {};
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RENDER_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&formJsInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_006
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRenderForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.Client is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_006, TestSize.Level0)
{
    FormJsInfo formJsInfo = {};
    Want want = {};
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RENDER_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&formJsInfo);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_007
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRenderForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_007, TestSize.Level0)
{
    FormJsInfo formJsInfo = {};
    Want want = {};
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RENDER_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&formJsInfo);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormRenderStubTest_008
 * @tc.desc: 1.Verify OnRemoteRequest and HandleStopRenderingForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.FormJsInfo is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_008, TestSize.Level0)
{
    Want want = {};
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_STOP_RENDERING_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_009
 * @tc.desc: 1.Verify OnRemoteRequest and HandleStopRenderingForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.want is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_009, TestSize.Level0)
{
    FormJsInfo formJsInfo = {};
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_STOP_RENDERING_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&formJsInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_010
 * @tc.desc: 1.Verify OnRemoteRequest and HandleStopRenderingForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.client is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_010, TestSize.Level0)
{
    FormJsInfo formJsInfo = {};
    Want want = {};
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_STOP_RENDERING_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&formJsInfo);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_011
 * @tc.desc: 1.Verify OnRemoteRequest and HandleStopRenderingForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_011, TestSize.Level0)
{
    FormJsInfo formJsInfo = {};
    Want want = {};
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_STOP_RENDERING_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&formJsInfo);
    data.WriteParcelable(&want);
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormRenderStubTest_012
 * @tc.desc: 1.Verify OnRemoteRequest and HandleCleanFormHost interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_012, TestSize.Level0)
{
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_FORM_HOST_DIED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_013
 * @tc.desc: 1.Verify OnRemoteRequest and HandleCleanFormHost interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_013, TestSize.Level0)
{
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_FORM_HOST_DIED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteRemoteObject(callerToken);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormRenderStubTest_014
 * @tc.desc: 1.Verify OnRemoteRequest and HandleReloadForm interface executes as expected.
 *           2.Size < 0
 *           3.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_014, TestSize.Level0)
{
    int32_t size = -1;
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RELOAD_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteInt32(size);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_015
 * @tc.desc: 1.Verify OnRemoteRequest and HandleReloadForm interface executes as expected.
 *           2.Want is nullptr
 *           3.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_015, TestSize.Level0)
{
    int32_t size = 1;
    Want want = {};
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RELOAD_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteInt32(size);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_016
 * @tc.desc: 1.Verify OnRemoteRequest and HandleReloadForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_016, TestSize.Level0)
{
    int32_t size = 1;
    FormJsInfo formJsInfo;
    Want want = {};
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RELOAD_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteInt32(size);
    data.WriteParcelable(&formJsInfo);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}
}  // namespace AppExecFwk
}  // namespace OHOS
