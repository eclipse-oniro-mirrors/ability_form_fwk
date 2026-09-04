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
#include "data_center/form_data_mgr.h"
#include "status_mgr_center/form_status_mgr.h"
#undef private
#include "mock_form_provider_client.h"
#include "mock_i_form_render.h"
#include "form_render_interface.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "util/form_status_common.h"
#include "fms_log_wrapper.h"
#include "status_mgr_center/form_status.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using testing::_;
using testing::Return;
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
{
    for (auto id : {999001, 999002, 999003, 999004, 999005, 999006, 999007, 999008, 999009, 999010}) {
        FormStatus::GetInstance().DeleteFormStatus(id);
        FormStatusMgr::GetInstance().DeleteFormEventId(id);
        FormDataMgr::GetInstance().DeleteFormRecord(id);
    }
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
 * @tc.name: RecycleForm_002
 * @tc.desc: Verify RecycleForm with valid IFormRender but no form record (GetFormRecord fails).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RecycleForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForm_002 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999001;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    auto render = iface_cast<IFormRender>(mockRender);
    ASSERT_NE(render, nullptr);
    // no record -> GetFormRecord returns false -> early return before IPC
    FormRecord checkRecord;
    EXPECT_FALSE(FormDataMgr::GetInstance().GetFormRecord(formId, checkRecord));
    EXPECT_CALL(*mockRender, RecycleForm(_, _)).Times(0);
    formTaskMgr->RecycleForm(formId, remoteObjectOfHost, mockRender);
    GTEST_LOG_(INFO) << "RecycleForm_002 end";
}

/**
 * @tc.name: RecycleForm_003
 * @tc.desc: Verify RecycleForm when RecycleForm IPC returns error (error != ERR_OK).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RecycleForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForm_003 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999002;
    FormRecord record;
    record.formId = formId;
    record.providerUserId = 100;
    record.bundleName = "com.test.bundle";
    record.formName = "test_form";
    FormDataMgr::GetInstance().formRecords_[formId] = record;
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RecycleForm(_, _)).WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    formTaskMgr->RecycleForm(formId, remoteObjectOfHost, mockRender);
    GTEST_LOG_(INFO) << "RecycleForm_003 end";
}

/**
 * @tc.name: RecycleForm_004
 * @tc.desc: Verify RecycleForm when RecycleForm IPC returns ERR_OK (success path).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RecycleForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForm_004 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999003;
    FormRecord record;
    record.formId = formId;
    record.providerUserId = 100;
    record.bundleName = "com.test.bundle";
    record.formName = "test_form";
    FormDataMgr::GetInstance().formRecords_[formId] = record;
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RecycleForm(_, _)).WillOnce(Return(ERR_OK));
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    formTaskMgr->RecycleForm(formId, remoteObjectOfHost, mockRender);
    GTEST_LOG_(INFO) << "RecycleForm_004 end";
}

/**
 * @tc.name: RecycleForm_005
 * @tc.desc: Verify MockIFormRender can be cast to IFormRender via iface_cast.
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RecycleForm_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecycleForm_005 start";
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    sptr<IFormRender> render = iface_cast<IFormRender>(mockRender);
    EXPECT_NE(render, nullptr);
    GTEST_LOG_(INFO) << "RecycleForm_005 end";
}

/**
 * @tc.name: RecoverForm_002
 * @tc.desc: Verify RecoverForm with status != RENDERED triggers MergeFormData path.
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RecoverForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForm_002 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999001;
    // status != RENDERED -> MergeFormData branch
    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RECYCLED);
    EXPECT_NE(FormStatus::GetInstance().GetFormLastStatus(formId), FormFsmStatus::RENDERED);
    FormRecord record;
    record.formId = formId;
    Want want;
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    formTaskMgr->RecoverForm(record, want, mockRender);
    GTEST_LOG_(INFO) << "RecoverForm_002 end";
}

/**
 * @tc.name: RecoverForm_003
 * @tc.desc: Verify RecoverForm with status == RENDERED and no cached data.
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RecoverForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForm_003 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999002;
    // two SetFormStatus calls so lastStatus == RENDERED (L373 false)
    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RENDERED);
    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RECOVERING);
    EXPECT_EQ(FormStatus::GetInstance().GetFormLastStatus(formId), FormFsmStatus::RENDERED);
    FormRecord record;
    record.formId = formId;
    Want want;
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RecoverForm(_, _)).WillOnce(Return(ERR_OK));
    formTaskMgr->RecoverForm(record, want, mockRender);
    GTEST_LOG_(INFO) << "RecoverForm_003 end";
}

/**
 * @tc.name: RecoverForm_004
 * @tc.desc: Verify RecoverForm with cached formProviderData.
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RecoverForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForm_004 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999003;
    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RENDERED);
    FormRecord record;
    record.formId = formId;
    // HasData() true
    FormProviderData data("{\"key\":\"value\"}");
    record.formProviderInfo.SetFormData(data);
    EXPECT_TRUE(record.formProviderInfo.GetFormData().HasData());
    Want want;
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    formTaskMgr->RecoverForm(record, want, mockRender);
    GTEST_LOG_(INFO) << "RecoverForm_004 end";
}

/**
 * @tc.name: RecoverForm_005
 * @tc.desc: Verify RecoverForm when RecoverForm IPC returns error.
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RecoverForm_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForm_005 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999004;
    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RENDERED);
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    FormRecord record;
    record.formId = formId;
    record.bundleName = "com.test.bundle";
    record.formName = "test_form";
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 100);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RecoverForm(_, _)).WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    formTaskMgr->RecoverForm(record, want, mockRender);
    GTEST_LOG_(INFO) << "RecoverForm_005 end";
}

/**
 * @tc.name: RecoverForm_006
 * @tc.desc: Verify RecoverForm when RecoverForm IPC returns ERR_OK (success path).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RecoverForm_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RecoverForm_006 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999005;
    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RENDERED);
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    FormRecord record;
    record.formId = formId;
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 100);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RecoverForm(_, _)).WillOnce(Return(ERR_OK));
    formTaskMgr->RecoverForm(record, want, mockRender);
    GTEST_LOG_(INFO) << "RecoverForm_006 end";
}

/**
 * @tc.name: ReleaseRenderer_002
 * @tc.desc: Verify ReleaseRenderer when IPC returns error (error != ERR_OK).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, ReleaseRenderer_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_002 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999001;
    std::string compId = "test_comp";
    std::string uid = "test_uid";
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, ReleaseRenderer(_, _, _, _)).WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    formTaskMgr->ReleaseRenderer(formId, compId, uid, mockRender);
    GTEST_LOG_(INFO) << "ReleaseRenderer_002 end";
}

/**
 * @tc.name: ReleaseRenderer_003
 * @tc.desc: Verify ReleaseRenderer when IPC returns ERR_OK (success path).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, ReleaseRenderer_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ReleaseRenderer_003 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999002;
    std::string compId = "test_comp";
    std::string uid = "test_uid";
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, ReleaseRenderer(_, _, _, _)).WillOnce(Return(ERR_OK));
    formTaskMgr->ReleaseRenderer(formId, compId, uid, mockRender);
    GTEST_LOG_(INFO) << "ReleaseRenderer_003 end";
}

/**
 * @tc.name: StopRenderingForm_002
 * @tc.desc: Verify StopRenderingForm when IPC returns error (error != ERR_OK).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, StopRenderingForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StopRenderingForm_002 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999001;
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    FormRecord formRecord;
    formRecord.formId = formId;
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 100);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, StopRenderingForm(_, _, _)).WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    formTaskMgr->StopRenderingForm(formRecord, want, mockRender);
    GTEST_LOG_(INFO) << "StopRenderingForm_002 end";
}

/**
 * @tc.name: StopRenderingForm_003
 * @tc.desc: Verify StopRenderingForm when IPC returns ERR_OK (success path).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, StopRenderingForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "StopRenderingForm_003 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999002;
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    FormRecord formRecord;
    formRecord.formId = formId;
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 100);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, StopRenderingForm(_, _, _)).WillOnce(Return(ERR_OK));
    formTaskMgr->StopRenderingForm(formRecord, want, mockRender);
    GTEST_LOG_(INFO) << "StopRenderingForm_003 end";
}

/**
 * @tc.name: RenderForm_002
 * @tc.desc: Verify RenderForm with valid IFormRender, success, default renderType.
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RenderForm_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RenderForm_002 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999001;
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isVisible = true;
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 100);
    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::RENDER_FORM);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RenderForm(_, _, _)).WillOnce(Return(ERR_OK));
    formTaskMgr->RenderForm(formRecord, want, mockRender);
    GTEST_LOG_(INFO) << "RenderForm_002 end";
}

/**
 * @tc.name: RenderForm_003
 * @tc.desc: Verify RenderForm when IPC returns error (error != ERR_OK).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RenderForm_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RenderForm_003 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999002;
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isVisible = true;
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, 100);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RenderForm(_, _, _)).WillOnce(Return(ERR_APPEXECFWK_FORM_COMMON_CODE));
    formTaskMgr->RenderForm(formRecord, want, mockRender);
    GTEST_LOG_(INFO) << "RenderForm_003 end";
}

/**
 * @tc.name: RenderForm_004
 * @tc.desc: Verify RenderForm with UPDATE_RENDERING_FORM renderType (MarkUpdateRender path).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RenderForm_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RenderForm_004 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999003;
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isVisible = true;
    Want want;
    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::UPDATE_RENDERING_FORM);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RenderForm(_, _, _)).WillOnce(Return(ERR_OK));
    formTaskMgr->RenderForm(formRecord, want, mockRender);
    GTEST_LOG_(INFO) << "RenderForm_004 end";
}

/**
 * @tc.name: RenderForm_005
 * @tc.desc: Verify CreateRenderFormJsInfo with non-RENDER_FORM type and non-RENDERED status.
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RenderForm_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RenderForm_005 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999004;
    // non-RENDER_FORM + non-RENDERED -> MergeFormData
    FormStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RECYCLED);
    EXPECT_NE(FormStatus::GetInstance().GetFormLastStatus(formId), FormFsmStatus::RENDERED);
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isVisible = true;
    Want want;
    want.SetParam(Constants::FORM_RENDER_TYPE_KEY, Constants::UPDATE_RENDERING_FORM);
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RenderForm(_, _, _)).WillOnce(Return(ERR_OK));
    formTaskMgr->RenderForm(formRecord, want, mockRender);
    GTEST_LOG_(INFO) << "RenderForm_005 end";
}

/**
 * @tc.name: RenderForm_006
 * @tc.desc: Verify CreateRenderFormJsInfo with RENDER_FORM type and no cached data.
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, RenderForm_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "RenderForm_006 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999005;
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    FormRecord formRecord;
    formRecord.formId = formId;
    formRecord.isVisible = false;
    Want want;
    sptr<MockIFormRender> mockRender = new (std::nothrow) MockIFormRender();
    ASSERT_NE(mockRender, nullptr);
    EXPECT_CALL(*mockRender, RenderForm(_, _, _)).WillOnce(Return(ERR_OK));
    formTaskMgr->RenderForm(formRecord, want, mockRender);
    GTEST_LOG_(INFO) << "RenderForm_006 end";
}

/**
 * @tc.name: OnRecycleDataDone_004
 * @tc.desc: Verify OnRecycleDataDone when eventId matches curTid (lambda posted).
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, OnRecycleDataDone_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "OnRecycleDataDone_004 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999001;
    // Set eventId via FormStatusMgr and read it back
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(formId);
    EXPECT_FALSE(eventId.empty());
    Want want;
    want.SetParam(Constants::FORM_STATUS_DATA, "test_status_data");
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
    want.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RECYCLE_DATA_DONE));
    int32_t result = formTaskMgr->OnRecycleDataDone(formId, want);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "OnRecycleDataDone_004 end";
}

/**
 * @tc.name: HandleFrsEventReply_004
 * @tc.desc: Verify HandleFrsEventReply when eventId matches curTid.
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTaskMgrTest, HandleFrsEventReply_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "HandleFrsEventReply_004 start";
    auto formTaskMgr = std::make_shared<FormStatusTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 999002;
    FormStatusMgr::GetInstance().SetFormEventId(formId);
    std::string eventId = FormStatusMgr::GetInstance().GetFormEventId(formId);
    EXPECT_FALSE(eventId.empty());
    Want want;
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
    want.SetParam(Constants::FORM_STATUS_EVENT, static_cast<int32_t>(FormFsmEvent::RENDER_FORM_DONE));
    FormFsmEvent failEvent = FormFsmEvent::RENDER_FORM_FAIL;
    int32_t result = formTaskMgr->HandleFrsEventReply(formId, want, failEvent);
    EXPECT_EQ(result, ERR_OK);
    GTEST_LOG_(INFO) << "HandleFrsEventReply_004 end";
}
}