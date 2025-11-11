/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "form_mgr_interface.h"
#include "form_constants.h"
#include "form_render_stub.h"
#include "form_supply_interface.h"
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
        sptr<IRemoteObject> callerToken) override
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
    int32_t UpdateFormSize(const int64_t &formId, const FormSurfaceInfo &formSurfaceInfo,
        const std::string &uid) override
    {
        return ERR_OK;
    };
    int32_t CheckPermission() override
    {
        return ERR_OK;
    }
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

class IFormSupplyTest : public IFormSupply {
public:
    IFormSupplyTest() {};
    virtual ~IFormSupplyTest() {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override
    {
        return number_;
    }
    int OnEventHandle(const Want &want) override
    {
        return number_;
    }
    int OnAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg,
        const Want &want) override
    {
        return number_;
    }
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override
    {}
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode) override
    {
        return number_;
    }
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

class IFormMgrTest : public IFormMgr {
public:
    IFormMgrTest() {};
    virtual ~IFormMgrTest() {};
    sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
    int AddForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken,
    FormJsInfo &formInfo) override
    {
        return number_;
    }
    int DeleteForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override
    {
        return number_;
    }
    int ReleaseForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const bool delCache) override
    {
        return number_;
    }
    int UpdateForm(const int64_t formId, const FormProviderData &formProviderData) override
    {
        return number_;
    }
    int SetNextRefreshTime(const int64_t formId, const int64_t nextTime) override
    {
        return number_;
    }
    ErrCode RequestPublishForm(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) override
    {
        return ERR_OK;
    }
    int LifecycleUpdate(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        bool updateType) override
    {
        return number_;
    }
    int RequestForm(const int64_t formId, const sptr<IRemoteObject> &callerToken, const Want &want) override
    {
        return number_;
    }
    int NotifyWhetherVisibleForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        const int32_t formVisibleType) override
    {
        return number_;
    }
    bool HasFormVisible(const uint32_t tokenId) override
    {
        return false;
    }
    int CastTempForm(const int64_t formId, const sptr<IRemoteObject> &callerToken) override
    {
        return number_;
    }
    int DumpStorageFormInfos(std::string &formInfos) override
    {
        return number_;
    }
    int DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos) override
    {
        return number_;
    }
    int DumpFormInfoByFormId(const std::int64_t formId, std::string &formInfo) override
    {
        return number_;
    }
    int DumpFormTimerByFormId(const std::int64_t formId, std::string &isTimingService) override
    {
        return number_;
    }
    int MessageEvent(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return number_;
    }
    int BackgroundEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return number_;
    }
    int RouterEvent(const int64_t formId, Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return number_;
    }
    int DeleteInvalidForms(const std::vector<int64_t> &formIds, const sptr<IRemoteObject> &callerToken,
        int32_t &numFormsDeleted) override
    {
        return number_;
    }
    int AcquireFormState(const Want &want, const sptr<IRemoteObject> &callerToken,
        FormStateInfo &stateInfo) override
    {
        return number_;
    }
    int NotifyFormsVisible(const std::vector<int64_t> &formIds, bool isVisible,
        const sptr<IRemoteObject> &callerToken) override
    {
        return number_;
    }
    int NotifyFormsPrivacyProtected(const std::vector<int64_t> &formIds, bool isProtected,
        const sptr<IRemoteObject> &callerToken) override
    {
        return number_;
    }
    int NotifyFormsEnableUpdate(const std::vector<int64_t> &formIds, bool isEnableUpdate,
        const sptr<IRemoteObject> &callerToken) override
    {
        return number_;
    }
    int GetAllFormsInfo(std::vector<FormInfo> &formInfos) override
    {
        return number_;
    }
    int GetFormsInfoByApp(std::string &bundleName, std::vector<FormInfo> &formInfos) override
    {
        return number_;
    }
    int GetFormsInfoByModule(std::string &bundleName, std::string &moduleName,
        std::vector<FormInfo> &formInfos) override
    {
        return number_;
    }
    int32_t GetFormsInfo(const FormInfoFilter &filter, std::vector<FormInfo> &formInfos) override
    {
        return ERR_OK;
    }
    bool IsRequestPublishFormSupported() override
    {
        return true;
    }
    int32_t StartAbility(const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    int32_t ShareForm(int64_t formId, const std::string &deviceId, const sptr<IRemoteObject> &callerToken,
        int64_t requestCode) override
    {
        return ERR_OK;
    }
    int32_t AcquireFormData(int64_t formId, int64_t requestCode, const sptr<IRemoteObject> &callerToken,
        AAFwk::WantParams &formData) override
    {
        return ERR_OK;
    }
    int32_t RecvFormShareInfoFromRemote(const FormShareInfo &info) override
    {
        return ERR_OK;
    }
    int32_t CheckFMSReady() override
    {
        return ERR_OK;
    }
    ErrCode RegisterFormAddObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode RegisterFormRemoveObserverByBundle(const std::string bundleName,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    int32_t SetBackgroundFunction(const std::string funcName, const std::string params) override
    {
        return ERR_OK;
    }
    int32_t GetFormsCount(bool isTempFormFlag, int32_t &formCount) override
    {
        return ERR_OK;
    }
    int32_t GetHostFormsCount(std::string &bundleName, int32_t &formCount) override
    {
        return ERR_OK;
    }
    ErrCode GetRunningFormInfos(bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) override
    {
        return ERR_OK;
    }
    ErrCode GetRunningFormInfosByBundleName(
        const std::string &bundleName, bool isUnusedIncluded, std::vector<RunningFormInfo> &runningFormInfos) override
    {
        return ERR_OK;
    }
    int32_t GetFormInstancesByFilter(const FormInstancesFilter &formInstancesFilter,
        std::vector<FormInstance> &formInstances) override
    {
        return ERR_OK;
    }
    int32_t GetFormInstanceById(const int64_t formId, FormInstance &formInstance) override
    {
        return ERR_OK;
    }
    ErrCode RegisterAddObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }
    ErrCode RegisterRemoveObserver(const std::string &bundleName, const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }

    ErrCode RegisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer) override
    {
        return ERR_OK;
    }

    ErrCode UnregisterClickEventObserver(
        const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &observer) override
    {
        return ERR_OK;
    }

    ErrCode RegisterFormRouterProxy(const std::vector<int64_t> &formIds,
        const sptr<IRemoteObject> &callerToken) override
    {
        return ERR_OK;
    }

    ErrCode UnregisterFormRouterProxy(const std::vector<int64_t> &formIds) override
    {
        return ERR_OK;
    }

    ErrCode RequestPublishFormWithSnapshot(Want &want, bool withFormBindingData,
        std::unique_ptr<FormProviderData> &formBindingData, int64_t &formId) override
    {
        return ERR_OK;
    }

    int32_t LockForms(const std::vector<FormLockInfo> &formLockInfos,
        OHOS::AppExecFwk::LockChangeType type) override
    {
        return ERR_OK;
    }

    bool IsFormBundleProtected(const std::string &bundleName, int64_t formId) override
    {
        return true;
    }

    bool IsFormBundleExempt(int64_t formId) override
    {
        return true;
    }
	
    int32_t GetPublishedFormInfoById(const int64_t formId, RunningFormInfo &formInfo) override
    {
        return ERR_OK;
    }

    int32_t GetPublishedFormInfos(std::vector<RunningFormInfo> &formInfos) override
    {
        return ERR_OK;
    }

    ErrCode OpenFormEditAbility(const std::string &abilityName, const int64_t &formId, bool isMainPage) override
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

/**
 * @tc.name: FormRenderStubTest_017
 * @tc.desc: 1.Verify OnRemoteRequest and HandleReleaseRenderer interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_017, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RELEASE_RENDERER);
    Want want = {};
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteInt64(1);
    data.WriteString("<compId>");
    data.WriteString("<uid>");
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormRenderStubTest_018
 * @tc.desc: 1.Verify OnRemoteRequest and HandleOnUnlock interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_018, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_UNLOCKED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormRenderStubTest_019
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRecycleForm interface executes as expected.
 *           2.Want is nullptr
 *           3.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_019, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RECYCLE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteInt64(1);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_020
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRecycleForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_020, TestSize.Level0)
{
    Want want = {};
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RECYCLE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteInt64(1);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormRenderStubTest_021
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRecoverForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.FormJsInfo is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_021, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RECOVER_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_022
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRecoverForm interface executes as expected.
 *           2.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
 *           3.want is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_022, TestSize.Level0)
{
    FormJsInfo formJsInfo = {};
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RECOVER_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&formJsInfo);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: FormRenderStubTest_023
 * @tc.desc: 1.Verify OnRemoteRequest and HandleRecycleForm interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_023, TestSize.Level0)
{
    FormJsInfo formJsInfo = {};
    Want want = {};
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RECOVER_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteParcelable(&formJsInfo);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormRenderStubTest_024
 * @tc.desc: 1.Verify OnRemoteRequest and RunCachedConfigurationUpdated interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_024, TestSize.Level0)
{
    sptr<MockFormRenderImpl> formRenderStub = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RUN_CACHED_CONFIG);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    auto result = formRenderStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
* @tc.name: FormRenderStubTest_025
* @tc.desc: 1.Verify OnRemoteRequest and HandleSetVisibleChange interface executes as expected.
* 2.Want is nullptr
* 3.The interface return value ERR_APPEXECFWK_PARCEL_ERROR.
* @tc.type: FUNC
*/
HWTEST_F(FormRenderStubTest, FormRenderStubTest_025, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_SET_VISIBLE_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteInt64(1);
    data.WriteBool(true);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
* @tc.name: FormRenderStubTest_026
* @tc.desc: 1.Verify OnRemoteRequest and HandleSetVisibleChange interface executes as expected.
* 2.The interface return value ERR_OK.
* @tc.type: FUNC
*/
HWTEST_F(FormRenderStubTest, FormRenderStubTest_026, TestSize.Level0)
{
    Want want = {};
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_SET_VISIBLE_CHANGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteInt64(1);
    data.WriteBool(true);
    data.WriteParcelable(&want);
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
* @tc.name: FormRenderStubTest_027
* @tc.desc: 1.Verify OnRemoteRequest and HandleUpdateFormSize interface executes as expected.
* 2.The interface return value ERR_OK.
* @tc.type: FUNC
*/
HWTEST_F(FormRenderStubTest, FormRenderStubTest_027, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_UPDATE_FORM_SIZE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    int64_t formId = 1;
    data.WriteInt64(formId);
    float width = 1.1;
    float height = 1.1;
    float borderWidth = 1.1;
    data.WriteFloat(width);
    data.WriteFloat(height);
    data.WriteFloat(borderWidth);
    data.WriteString("<uid>");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: FormRenderStubTest_028
 * @tc.desc: 1.Verify OnRemoteRequest and HandleReleaseRenderer interface executes as expected.
 *           2.The interface return value ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, FormRenderStubTest_028, TestSize.Level0)
{
    sptr<MockFormRenderImpl> callback = new (std::nothrow) MockFormRenderImpl();
    uint32_t code = static_cast<uint32_t>(IFormRender::Message::FORM_RENDER_RELEASE_RENDERER);
    Want want = {};
    MessageParcel data;
    MessageParcel reply;
    MessageOption option{MessageOption::TF_ASYNC};
    data.WriteInterfaceToken(u"ohos.appexecfwk.FormRender");
    data.WriteInt64(1);
    data.WriteString("<compId>");
    data.WriteString("<uid>");
    auto result = callback->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.name: IFormSupplyTest_001
 * @tc.desc: Test OnRenderingBlock function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormSupplyTest_001, TestSize.Level0)
{
    std::string bundleName = "<bundleName>";
    IFormSupplyTest iFormSupplyTest;
    EXPECT_EQ(iFormSupplyTest.OnRenderingBlock(bundleName), ERR_OK);
}

/**
 * @tc.name: IFormMgrTest_001
 * @tc.desc: Test StopRenderingForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_001, TestSize.Level0)
{
    int64_t formId = 1;
    std::string compId = "<compId>";
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.StopRenderingForm(formId, compId), ERR_OK);
}

/**
 * @tc.name: IFormMgrTest_002
 * @tc.desc: Test ReleaseRenderer function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_002, TestSize.Level0)
{
    int64_t formId = 1;
    std::string compId = "<compId>";
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.ReleaseRenderer(formId, compId), ERR_OK);
}

/**
 * @tc.name: IFormMgrTest_003
 * @tc.desc: Test RequestPublishProxyForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_003, TestSize.Level0)
{
    Want want;
    bool withFormBindingData = true;
    std::unique_ptr<FormProviderData> formBindingData;
    int64_t formId = 1;
    std::vector<FormDataProxy> formDataProxies;
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.RequestPublishProxyForm(
        want, withFormBindingData, formBindingData, formId, formDataProxies), ERR_OK);
}

/**
 * @tc.name: IFormMgrTest_004
 * @tc.desc: Test UpdateProxyForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_004, TestSize.Level0)
{
    int64_t formId = 1;
    FormProviderData formProviderData;
    std::vector<FormDataProxy> formDataProxies;
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.UpdateProxyForm(formId, formProviderData, formDataProxies), ERR_OK);
}

/**
 * @tc.name: IFormMgrTest_005
 * @tc.desc: Test LockForms function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_005, TestSize.Level0)
{
    std::vector<FormLockInfo> formLockInfos;
    OHOS::AppExecFwk::LockChangeType type = LockChangeType::SWITCH_CHANGE;
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.LockForms(formLockInfos, type), ERR_OK);
}

/**
 * @tc.name: IFormMgrTest_006
 * @tc.desc: Test IsFormBundleProtected function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_006, TestSize.Level0)
{
    std::string bundleName = "com.ohos.example.bundleName";
    int64_t formId = 1;
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.IsFormBundleProtected(bundleName, formId), true);
}

/**
 * @tc.name: IFormMgrTest_007
 * @tc.desc: Test IsFormBundleExempt function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_007, TestSize.Level0)
{
    int64_t formId = 1;
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.IsFormBundleExempt(formId), true);
}

/**
 * @tc.name: IFormMgrTest_008
 * @tc.desc: Test GetPublishedFormInfoById function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_008, TestSize.Level0)
{
    int64_t formId = 1;
    RunningFormInfo formInfo;
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.GetPublishedFormInfoById(formId, formInfo), ERR_OK);
}

/**
 * @tc.name: IFormMgrTest_009
 * @tc.desc: Test GetPublishedFormInfos function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_009, TestSize.Level0)
{
    std::vector<RunningFormInfo> formInfos;
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.GetPublishedFormInfos(formInfos), ERR_OK);
}

/**
 * @tc.name: IFormMgrTest_010
 * @tc.desc: Test OpenFormEditAbility function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStubTest, IFormMgrTest_010, TestSize.Level0)
{
    std::string abilityName = "123";
    int64_t formId = 1;
    bool isMainPage = true;
    IFormMgrTest iFormMgrTest;
    EXPECT_EQ(iFormMgrTest.OpenFormEditAbility(abilityName, formId, isMainPage), ERR_OK);
}
}  // namespace AppExecFwk
}  // namespace OHOS
