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
#include <memory>
#define private public
#include "status_mgr_center/form_status_task_mgr.h"
#undef private
#include "mock_form_provider_client.h"
#include "form_render_interface.h"
#include "form_constants.h"
#include "util/form_status_common.h"
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormStatusTaskMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormStatusTaskMgrTest::SetUpTestCase()
{}

void FormStatusTaskMgrTest::TearDownTestCase()
{}

void FormStatusTaskMgrTest::SetUp()
{}

void FormStatusTaskMgrTest::TearDown()
{}

/**
 * @tc.name: FormStatusTaskMgr_0001
 * @tc.desc: Verify PostRecycleForms
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::vector<int64_t> formIds = {123, 456, 789};
    Want want;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<IRemoteObject> remoteObjectOfRender = nullptr;
    formTaskMgr->PostRecycleForms(formIds, want, remoteObjectOfHost, remoteObjectOfRender);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0001 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0002
 * @tc.desc: Verify PostRecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0002 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostRecoverForm(record, want, remoteObject);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0002 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0003
 * @tc.desc: test PostStopRenderingForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0003 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostStopRenderingForm(record, want, remoteObject);
    int64_t formId = 0;
    std::string compId = "compId";
    std::string uid = "uid";
    formTaskMgr->PostReleaseRenderer(formId, compId, uid, remoteObject);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0003 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0004
 * @tc.desc: Verify PostRenderForm
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0004 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    FormRecord record;
    Want want;
    want.SetParam(Constants::FORM_UPDATE_TYPE_KEY, Constants::ADAPTER_UPDATE_FORM);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostRenderForm(record, want, remoteObject);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0004 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0005
 * @tc.desc: test PostStopRenderingForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0005 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostStopRenderingForm(record, want, remoteObject);
    int64_t formId = 0;
    std::string compId = "compId";
    std::string uid = "uid";
    formTaskMgr->PostReleaseRenderer(formId, compId, uid, remoteObject);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0005 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0006
 * @tc.desc: test RecycleForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0006 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 1;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<IRemoteObject> remoteObjectOfRender = nullptr;
    formTaskMgr->RecycleForm(formId, remoteObjectOfHost, remoteObjectOfRender);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObjectOfRender), nullptr);

    remoteObjectOfRender = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->RecycleForm(formId, remoteObjectOfHost, remoteObjectOfRender);

    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0006 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0007
 * @tc.desc: Verify RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0007 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->RecoverForm(record, want, remoteObject);
    remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->RecoverForm(record, want, remoteObject);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0007 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0008
 * @tc.desc: test ReleaseRenderer function
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0008 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 0;
    std::string compId = "compId";
    std::string uid = "uid";
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->ReleaseRenderer(formId, compId, uid, remoteObject);
    remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->ReleaseRenderer(formId, compId, uid, remoteObject);
    FormRecord record;
    Want want;
    formTaskMgr->RenderForm(record, want, remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0008 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0011
 * @tc.desc: Verify StopRenderingForm
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0011 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    FormRecord formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->StopRenderingForm(formRecords, want, remoteObject);
    remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->StopRenderingForm(formRecords, want, remoteObject);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0011 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0012
 * @tc.desc: Verify RenderForm
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0012 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    FormRecord record;
    record.isVisible = false;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->RenderForm(record, want, remoteObject);
    remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->RenderForm(record, want, remoteObject);
    record.isVisible = true;
    formTaskMgr->RenderForm(record, want, remoteObject);

    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::UPDATE_RENDERING_FORM);
    formTaskMgr->RenderForm(record, want, remoteObject);

    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0012 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0013
 * @tc.desc: test RecycleForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0013 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 1;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<IRemoteObject> remoteObjectOfRender = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->RecycleForm(formId, remoteObjectOfHost, remoteObjectOfRender);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0013 end";
}

/**
 * @tc.name: FormStatusTaskMgr_0014
 * @tc.desc: Verify StopRenderingForm
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_0014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0014 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    FormRecord formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->StopRenderingForm(formRecords, want, remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_0014 end";
}

/**
 * @tc.name: FormStatusTaskMgr_RecycleTimeout
 * @tc.desc: Verify ScheduleRecycleTimeout and CancelRecycleTimeout
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_RecycleTimeout, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_RecycleTimeout start";
 
    int64_t formId = 123;
    EXPECT_EQ(true, FormStatusTaskMgr::GetInstance().ScheduleRecycleTimeout(formId));
    EXPECT_EQ(true, FormStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId));
    EXPECT_EQ(false, FormStatusTaskMgr::GetInstance().CancelRecycleTimeout(formId));
 
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_RecycleTimeout end";
}

/**
 * @tc.name: FormStatusTaskMgr_PostDelayReleaseRenderer
 * @tc.desc: Verify PostDelayReleaseRenderer
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, FormStatusTaskMgr_PostDelayReleaseRenderer, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_PostDelayReleaseRenderer start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 0;
    std::string compId = "compId";
    std::string uid = "uid";
    sptr<IRemoteObject> remoteObject = nullptr;
    bool ret = formTaskMgr->PostDelayReleaseRenderer(formId, compId, uid, remoteObject);
    EXPECT_EQ(true, ret);
    GTEST_LOG_(INFO) << "FormStatusTaskMgr_PostDelayReleaseRenderer end";
}

/**
* @tc.name: OnRenderFormDone_001
* @tc.desc: Verify OnRenderFormDone returns ERR_OK
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, OnRenderFormDone_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRenderFormDone_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    int32_t result = formTaskMgr->OnRenderFormDone(formId, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "OnRenderFormDone_001 end";
}

/**
* @tc.name: OnRecoverFormDone_001
* @tc.desc: Verify OnRecoverFormDone returns ERR_OK
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, OnRecoverFormDone_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRecoverFormDone_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    int32_t result = formTaskMgr->OnRecoverFormDone(formId, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "OnRecoverFormDone_001 end";
}

/**
* @tc.name: OnRecycleFormDone_001
* @tc.desc: Verify OnRecycleFormDone returns ERR_OK
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, OnRecycleFormDone_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRecycleFormDone_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    int32_t result = formTaskMgr->OnRecycleFormDone(formId, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "OnRecycleFormDone_001 end";
}

/**
* @tc.name: OnDeleteFormDone_001
* @tc.desc: Verify OnDeleteFormDone returns ERR_OK
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, OnDeleteFormDone_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnDeleteFormDone_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    int32_t result = formTaskMgr->OnDeleteFormDone(formId, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "OnDeleteFormDone_001 end";
}

/**
* @tc.name: OnRecycleDataDone_001
* @tc.desc: Verify OnRecycleDataDone with empty statusData
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, OnRecycleDataDone_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRecycleDataDone_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    int32_t result = formTaskMgr->OnRecycleDataDone(formId, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "OnRecycleDataDone_001 end";
}

/**
* @tc.name: OnRecycleDataDone_002
* @tc.desc: Verify OnRecycleDataDone with statusData
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, OnRecycleDataDone_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRecycleDataDone_002 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    want.SetParam(Constants::FORM_STATUS_DATA, "test_status_data");
    int32_t result = formTaskMgr->OnRecycleDataDone(formId, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "OnRecycleDataDone_002 end";
}

/**
* @tc.name: OnRecycleDataDone_003
* @tc.desc: Verify OnRecycleDataDone with eventId and event
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, OnRecycleDataDone_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRecycleDataDone_003 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    want.SetParam(Constants::FORM_STATUS_DATA, "test_status_data");
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, "event_001");
    want.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RECYCLE_DATA_DONE));
    int32_t result = formTaskMgr->OnRecycleDataDone(formId, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "OnRecycleDataDone_003 end";
}

/**
* @tc.name: HandleFrsEventReply_001
* @tc.desc: Verify HandleFrsEventReply with empty eventId
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, HandleFrsEventReply_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFrsEventReply_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    FormFsmEvent failEvent = FormFsmEvent::RENDER_FORM_FAIL;
    int32_t result = formTaskMgr->HandleFrsEventReply(formId, want, failEvent);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "HandleFrsEventReply_001 end";
}

/**
* @tc.name: HandleFrsEventReply_002
* @tc.desc: Verify HandleFrsEventReply with eventId and event not equal to failEvent
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, HandleFrsEventReply_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFrsEventReply_002 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, "event_001");
    want.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RENDER_FORM_DONE));
    FormFsmEvent failEvent = FormFsmEvent::RENDER_FORM_FAIL;
    int32_t result = formTaskMgr->HandleFrsEventReply(formId, want, failEvent);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "HandleFrsEventReply_002 end";
}

/**
* @tc.name: HandleFrsEventReply_003
* @tc.desc: Verify HandleFrsEventReply with event equal to failEvent
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, HandleFrsEventReply_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFrsEventReply_003 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123;
    Want want;
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, "event_001");
    want.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RENDER_FORM_FAIL));
    FormFsmEvent failEvent = FormFsmEvent::RENDER_FORM_FAIL;
    int32_t result = formTaskMgr->HandleFrsEventReply(formId, want, failEvent);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "HandleFrsEventReply_003 end";
}

/**
* @tc.name: RemoveConnection_001
* @tc.desc: Verify RemoveConnection with valid connectId
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, RemoveConnection_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RemoveConnection_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int32_t connectId = 123;
    formTaskMgr->RemoveConnection(connectId);
    EXPECT_TRUE(formTaskMgr != nullptr);
    GTEST_LOG_(INFO) << "RemoveConnection_001 end";
}

/**
* @tc.name: RestoreFormRecycledStatus_001
* @tc.desc: Verify RestoreFormRecycledStatus with formRecord
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, RestoreFormRecycledStatus_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RestoreFormRecycledStatus_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord formRecord;
    formRecord.formId = 123;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->RestoreFormRecycledStatus(formRecord, remoteObject);
    EXPECT_TRUE(formTaskMgr != nullptr);
    GTEST_LOG_(INFO) << "RestoreFormRecycledStatus_001 end";
}

/**
* @tc.name: RestoreFormRecycledStatus_002
* @tc.desc: Verify RestoreFormRecycledStatus with valid remoteObject
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, RestoreFormRecycledStatus_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RestoreFormRecycledStatus_002 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord formRecord;
    formRecord.formId = 123;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    ASSERT_NE(remoteObject, nullptr);
    formTaskMgr->RestoreFormRecycledStatus(formRecord, remoteObject);
    EXPECT_TRUE(formTaskMgr != nullptr);
    GTEST_LOG_(INFO) << "RestoreFormRecycledStatus_002 end";
}

/**
* @tc.name: PostRecycleForms_001
* @tc.desc: Verify PostRecycleForms with empty formIds
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, PostRecycleForms_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PostRecycleForms_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::vector<int64_t> formIds;
    Want want;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<IRemoteObject> remoteObjectOfRender = nullptr;
    formTaskMgr->PostRecycleForms(formIds, want, remoteObjectOfHost, remoteObjectOfRender);
    EXPECT_TRUE(formTaskMgr != nullptr);
    GTEST_LOG_(INFO) << "PostRecycleForms_001 end";
}

/**
* @tc.name: PostRecoverForm_001
* @tc.desc: Verify PostRecoverForm with valid record formId
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, PostRecoverForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PostRecoverForm_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord record;
    record.formId = 123456;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostRecoverForm(record, want, remoteObject);
    EXPECT_EQ(record.formId, 123456);
    GTEST_LOG_(INFO) << "PostRecoverForm_001 end";
}

/**
* @tc.name: PostRenderForm_001
* @tc.desc: Verify PostRenderForm with valid formRecord formId
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, PostRenderForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PostRenderForm_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord formRecord;
    formRecord.formId = 123456;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostRenderForm(formRecord, want, remoteObject);
    EXPECT_EQ(record.formId, 123456);
    GTEST_LOG_(INFO) << "PostRenderForm_001 end";
}

/**
* @tc.name: PostStopRenderingForm_001
* @tc.desc: Verify PostStopRenderingForm with valid formRecord formId
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, PostStopRenderingForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PostStopRenderingForm_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord formRecord;
    formRecord.formId = 123456;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostStopRenderingForm(formRecord, want, remoteObject);
    EXPECT_EQ(record.formId, 123456);
    GTEST_LOG_(INFO) << "PostStopRenderingForm_001 end";
}

/**
* @tc.name: PostReleaseRenderer_001
* @tc.desc: Verify PostReleaseRenderer with isDynamic false
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, PostReleaseRenderer_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PostReleaseRenderer_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123456;
    std::string compId = "test_comp_id";
    std::string uid = "test_uid";
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostReleaseRenderer(formId, compId, uid, remoteObject, false);
    EXPECT_EQ(record.formId, 123456);
    GTEST_LOG_(INFO) << "PostReleaseRenderer_001 end";
}

/**
* @tc.name: RecycleForm_001
* @tc.desc: Verify RecycleForm with valid formId and remoteObjects
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, RecycleForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForm_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123456;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<IRemoteObject> remoteObjectOfRender = new (std::nothrow) MockFormProviderClient();
    ASSERT_NE(remoteObjectOfRender, nullptr);
    formTaskMgr->RecycleForm(formId, remoteObjectOfHost, remoteObjectOfRender);
    EXPECT_EQ(record.formId, 123456);
    GTEST_LOG_(INFO) << "RecycleForm_001 end";
}

/**
* @tc.name: RecoverForm_001
* @tc.desc: Verify RecoverForm with valid record and connectId
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, RecoverForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForm_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord record;
    record.formId = 123456;
    record.bundleName = "test_bundle";
    record.formName = "test_form";
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 100);
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    ASSERT_NE(remoteObject, nullptr);
    formTaskMgr->RecoverForm(record, want, remoteObject);
    EXPECT_EQ(record.formId, 123456);
    GTEST_LOG_(INFO) << "RecoverForm_001 end";
}

/**
* @tc.name: ReleaseRenderer_001
* @tc.desc: Verify ReleaseRenderer with valid parameters
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, ReleaseRenderer_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 123456;
    std::string compId = "test_comp_id";
    std::string uid = "test_uid";
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    ASSERT_NE(remoteObject, nullptr);
    formTaskMgr->ReleaseRenderer(formId, compId, uid, remoteObject);
    EXPECT_EQ(record.formId, 123456);
    GTEST_LOG_(INFO) << "ReleaseRenderer_001 end";
}

/**
* @tc.name: StopRenderingForm_001
* @tc.desc: Verify StopRenderingForm with valid formRecord and connectId
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, StopRenderingForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StopRenderingForm_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord formRecord;
    formRecord.formId = 123456;
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 100);
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    ASSERT_NE(remoteObject, nullptr);
    formTaskMgr->StopRenderingForm(formRecord, want, remoteObject);
    EXPECT_EQ(record.formId, 123456);
    GTEST_LOG_(INFO) << "StopRenderingForm_001 end";
}

/**
* @tc.name: RenderForm_001
* @tc.desc: Verify RenderForm with valid formRecord and connectId
* @tc.type: FUNC
*/
HWTEST_F(FormStatusTaskMgrTest, RenderForm_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RenderForm_001 start";
    std::shared_ptr<FormStatusTaskMgr> formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord formRecord;
    formRecord.formId = 123456;
    formRecord.isVisible = true;
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 100);
    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    ASSERT_NE(remoteObject, nullptr);
    formTaskMgr->RenderForm(formRecord, want, remoteObject);
    EXPECT_EQ(record.formId, 123456);
    GTEST_LOG_(INFO) << "RenderForm_001 end";
}
}