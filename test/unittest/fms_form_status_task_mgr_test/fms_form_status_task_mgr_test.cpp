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
}