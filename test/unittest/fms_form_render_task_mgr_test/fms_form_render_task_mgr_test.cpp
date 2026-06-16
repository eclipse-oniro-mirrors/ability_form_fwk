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
#include "form_render/form_render_task_mgr.h"
#undef private
#include "mock_form_provider_client.h"
#include "form_render_interface.h"
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormRenderTaskMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormRenderTaskMgrTest::SetUpTestCase()
{}

void FormRenderTaskMgrTest::TearDownTestCase()
{}

void FormRenderTaskMgrTest::SetUp()
{}

void FormRenderTaskMgrTest::TearDown()
{}

/**
 * @tc.name: FormRenderTaskMgr_0001
 * @tc.desc: Verify PostUpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0001 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    int64_t formId = 123;
    FormSurfaceInfo formSurfaceInfo;
    formSurfaceInfo.width = 1;
    formSurfaceInfo.height = 1;
    formSurfaceInfo.borderWidth = 1;
    formSurfaceInfo.formViewScale = 1;
    std::string uid = "123";
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostUpdateFormSize(formId, formSurfaceInfo, uid, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0001 end";
}

/**
 * @tc.name: FormRenderTaskMgr_0002
 * @tc.desc: Verify PostOnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0002 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostOnUnlock(remoteObject);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0002 end";
}

/**
 * @tc.name: FormRenderTaskMgr_0003
 * @tc.desc: Verify PostOnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0003 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostSetVisibleChange(0, true, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0003 end";
}

/**
 * @tc.name: FormRenderTaskMgr_0004
 * @tc.desc: Verify PostReloadForm
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0004 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::vector<FormRecord> formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostReloadForm(std::move(formRecords), want, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0004 end";
}

/**
 * @tc.name: FormRenderTaskMgr_0005
 * @tc.desc: Verify UpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0005 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    int64_t formId = 123;
    FormSurfaceInfo formSurfaceInfo;
    formSurfaceInfo.width = 1;
    formSurfaceInfo.height = 1;
    formSurfaceInfo.borderWidth = 1;
    formSurfaceInfo.formViewScale = 1;
    std::string uid = "123";
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->UpdateFormSize(formId, formSurfaceInfo, uid, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0005 end";
}

/**
 * @tc.name: FormRenderTaskMgr_0006
 * @tc.desc: Verify OnUnlock
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0006 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->OnUnlock(remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0006 end";
}

/**
 * @tc.name: FormRenderTaskMgr_0007
 * @tc.desc: Verify SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0007 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    int64_t formId = 123;
    bool isVisible = true;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->SetVisibleChange(formId, isVisible, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0007 end";
}

/**
 * @tc.name: FormRenderTaskMgr_0008
 * @tc.desc: test ReloadForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0008 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::vector<FormRecord> formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->ReloadForm(std::move(formRecords), want, remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0008 end";
}

/**
 * @tc.name: FormRenderTaskMgr_0009
 * @tc.desc: Verify UpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0009 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    int64_t formId = 123;
    FormSurfaceInfo formSurfaceInfo;
    formSurfaceInfo.width = 1;
    formSurfaceInfo.height = 1;
    formSurfaceInfo.borderWidth = 1;
    formSurfaceInfo.formViewScale = 1;
    std::string uid = "123";
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->UpdateFormSize(formId, formSurfaceInfo, uid, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0009 end";
}

/**
 * @tc.name: FormRenderTaskMgr_0010
 * @tc.desc: test ReloadForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_0010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0010 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::vector<FormRecord> formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->ReloadForm(std::move(formRecords), want, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_0010 end";
}

/**
 * @tc.name: FormRenderTaskMgr_PostSetRenderGroupParams_0001
 * @tc.desc: test PostSetRenderGroupParams function
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderTaskMgrTest, FormRenderTaskMgr_PostSetRenderGroupParams_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_PostSetRenderGroupParams_0001 start";
    std::shared_ptr<FormRenderTaskMgr> formTaskMgr = std::make_shared<FormRenderTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostSetRenderGroupParams(1, want, remoteObject);
    GTEST_LOG_(INFO) << "FormRenderTaskMgr_PostSetRenderGroupParams_0001 end";
}
}