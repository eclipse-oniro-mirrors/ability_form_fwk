/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <memory>
#include "status_mgr_center/form_render_status_task_mgr.h"
#include "status_mgr_center/form_render_status_mgr.h"
#include "form_supply_stub.h"
#include "form_constants.h"
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace {
const int64_t FORM_ID = 123;
class FormRenderStatusTaskMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormRenderStatusTaskMgrTest::SetUpTestCase()
{}

void FormRenderStatusTaskMgrTest::TearDownTestCase()
{}

void FormRenderStatusTaskMgrTest::SetUp()
{}

void FormRenderStatusTaskMgrTest::TearDown()
{}

class MockFormSupplyStub : public FormSupplyStub {
public:
    MockFormSupplyStub(){};
    virtual ~MockFormSupplyStub(){};
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
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
    int OnAcquireStateResult(
        FormState state, const std::string &provider, const Want &wantArg, const Want &want) override
    {
        return number_;
    };
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode)
    {
        return ERR_OK;
    };
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId, const AAFwk::WantParams &wantParams,
        int64_t requestCode, const bool &result) override{};
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
 * @tc.name: FormRenderStatusTaskMgrTest_OnRenderFormDone
 * @tc.desc: Verify PostFormEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusTaskMgrTest, FormRenderStatusTaskMgrTest_OnRenderFormDone, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnRenderFormDone start";

    Want want;
    int64_t formId = FORM_ID;
    FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(formId, FormFsmEvent::RENDER_FORM_DONE, "", nullptr);

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(
        formId, FormFsmEvent::RENDER_FORM_DONE, "", formSupplyClient);

    std::string eventId = std::to_string(formId);
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    eventId = FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRenderFormDone(
        formId, FormFsmEvent::RENDER_FORM_DONE, eventId, formSupplyClient);

    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnRenderFormDone end";
}

/**
 * @tc.name: FormRenderStatusTaskMgrTest_OnRecoverFormDone
 * @tc.desc: Verify PostFormEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusTaskMgrTest, FormRenderStatusTaskMgrTest_OnRecoverFormDone, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnRecoverFormDone start";

    Want want;
    int64_t formId = FORM_ID;
    FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(formId, FormFsmEvent::RECOVER_FORM_DONE, "", nullptr);

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(
        formId, FormFsmEvent::RECOVER_FORM_DONE, "", formSupplyClient);

    std::string eventId = std::to_string(formId);
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    eventId = FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRecoverFormDone(
        formId, FormFsmEvent::RECOVER_FORM_DONE, eventId, formSupplyClient);

    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnRecoverFormDone end";
}

/**
 * @tc.name: FormRenderStatusTaskMgrTest_OnDeleteFormDone
 * @tc.desc: Verify PostFormEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusTaskMgrTest, FormRenderStatusTaskMgrTest_OnDeleteFormDone, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnDeleteFormDone start";

    Want want;
    int64_t formId = FORM_ID;
    FormRenderStatusTaskMgr::GetInstance().OnDeleteFormDone(formId, FormFsmEvent::DELETE_FORM_DONE, "", nullptr);

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnDeleteFormDone(
        formId, FormFsmEvent::DELETE_FORM_DONE, "", formSupplyClient);

    std::string eventId = std::to_string(formId);
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    eventId = FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnDeleteFormDone(
        formId, FormFsmEvent::DELETE_FORM_DONE, eventId, formSupplyClient);

    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnDeleteFormDone end";
}

/**
 * @tc.name: FormRenderStatusTaskMgrTest_OnRecycleFormDone
 * @tc.desc: Verify PostFormEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusTaskMgrTest, FormRenderStatusTaskMgrTest_OnRecycleFormDone, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnRecycleFormDone start";

    Want want;
    int64_t formId = FORM_ID;
    FormRenderStatusTaskMgr::GetInstance().OnRecycleFormDone(formId, FormFsmEvent::RECYCLE_FORM_DONE, "", nullptr);

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleFormDone(
        formId, FormFsmEvent::RECYCLE_FORM_DONE, "", formSupplyClient);

    std::string eventId = std::to_string(formId);
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    eventId = FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleFormDone(
        formId, FormFsmEvent::RECYCLE_FORM_DONE, eventId, formSupplyClient);

    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnRecycleFormDone end";
}

/**
 * @tc.name: FormRenderStatusTaskMgrTest_OnRecycleForm
 * @tc.desc: Verify PostFormEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusTaskMgrTest, FormRenderStatusTaskMgrTest_OnRecycleForm, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnRecycleForm start";

    int64_t formId = FORM_ID;
    Want want;
    std::string statusData = std::to_string(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleForm(
        formId, FormFsmEvent::RECYCLE_DATA_DONE, statusData, want, nullptr);

    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormSupplyStub();
    sptr<IFormSupply> formSupplyClient = iface_cast<IFormSupply>(callerToken);
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleForm(
        formId, FormFsmEvent::RECYCLE_DATA_DONE, statusData, want, formSupplyClient);

    std::string eventId = std::to_string(formId);
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    eventId = FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    FormRenderStatusTaskMgr::GetInstance().OnRecycleForm(
        formId, FormFsmEvent::RECYCLE_DATA_DONE, statusData, want, formSupplyClient);

    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_OnRecycleForm end";
}

/**
 * @tc.name: FormRenderStatusTaskMgrTest_RecycleTimeout
 * @tc.desc: Verify ScheduleRecycleTimeout and CancelRecycleTimeout
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusTaskMgrTest, FormRenderStatusTaskMgrTest_RecycleTimeout, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_RecycleTimeout start";

    int64_t formId = FORM_ID;
    FormRenderStatusTaskMgr::GetInstance().SetSerialQueue(nullptr);
    EXPECT_EQ(false, FormRenderStatusTaskMgr::GetInstance().ScheduleRecycleTimeout(formId));
    EXPECT_EQ(false, FormRenderStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId));

    std::string queueStr = "FormRenderSerialQueue";
    std::shared_ptr<FormRenderSerialQueue> serialQueue = std::make_unique<FormRenderSerialQueue>(queueStr);
    FormRenderStatusTaskMgr::GetInstance().SetSerialQueue(serialQueue);
    EXPECT_EQ(false, FormRenderStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId));
    EXPECT_EQ(true, FormRenderStatusTaskMgr::GetInstance().ScheduleRecycleTimeout(formId));
    EXPECT_EQ(true, FormRenderStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId));

    GTEST_LOG_(INFO) << "FormRenderStatusTaskMgrTest_RecycleTimeout end";
}
}  // namespace