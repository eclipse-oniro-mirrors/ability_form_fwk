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
#include "form_observer/form_observer_task_mgr.h"
#undef private
#include "js_form_state_observer_interface.h"
#include "mock_form_provider_client.h"
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormObserverTaskMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormObserverTaskMgrTest::SetUpTestCase()
{}

void FormObserverTaskMgrTest::TearDownTestCase()
{}

void FormObserverTaskMgrTest::SetUp()
{}

void FormObserverTaskMgrTest::TearDown()
{}

/**
 * @tc.name: FormObserverTaskMgr_0001
 * @tc.desc: Verify PostAddTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, FormObserverTaskMgr_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0001 start";
    std::shared_ptr<FormObserverTaskMgr> formTaskMgr = std::make_shared<FormObserverTaskMgr>();
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->PostAddTaskToHost(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0001 end";
}

/**
 * @tc.name: FormObserverTaskMgr_0002
 * @tc.desc: Verify PostRemoveTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, FormObserverTaskMgr_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0107 start";
    std::shared_ptr<FormObserverTaskMgr> formTaskMgr = std::make_shared<FormObserverTaskMgr>();
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->PostRemoveTaskToHost(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0107 end";
}

/**
 * @tc.name: FormObserverTaskMgr_0003
 * @tc.desc: Verify PostRemoveTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, FormObserverTaskMgr_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0003 start";
    std::shared_ptr<FormObserverTaskMgr> formTaskMgr = std::make_shared<FormObserverTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::string bundleName = "bundleName";
    std::string formEventType = "formEventType";
    sptr<IRemoteObject> remoteObject = nullptr;
    RunningFormInfo runningFormInfo;
    formTaskMgr->PostFormClickEventToHost(bundleName, formEventType, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0003 end";
}

/**
 * @tc.name: FormObserverTaskMgr_0004
 * @tc.desc: test PostBatchRefreshForms function
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, FormObserverTaskMgr_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0004 start";
    std::shared_ptr<FormObserverTaskMgr> formTaskMgr = std::make_shared<FormObserverTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int32_t formRefreshType = 1;
    formTaskMgr->PostBatchRefreshForms(formRefreshType);
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0004 end";
}

/**
 * @tc.name: FormObserverTaskMgr_0005
 * @tc.desc: Verify FormAdd
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, FormObserverTaskMgr_0005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0005 start";
    std::shared_ptr<FormObserverTaskMgr> formTaskMgr = std::make_shared<FormObserverTaskMgr>();
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->FormAdd(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0005 end";
}

/**
 * @tc.name: FormObserverTaskMgr_0006
 * @tc.desc: Verify FormRemove
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, FormObserverTaskMgr_0006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0006 start";
    std::shared_ptr<FormObserverTaskMgr> formTaskMgr = std::make_shared<FormObserverTaskMgr>();
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->FormRemove(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0006 end";
}

/**
 * @tc.name: FormObserverTaskMgr_0007
 * @tc.desc: Verify FormClickEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormObserverTaskMgrTest, FormObserverTaskMgr_0007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0007 start";
    std::shared_ptr<FormObserverTaskMgr> formTaskMgr = std::make_shared<FormObserverTaskMgr>();
    std::string bundleName = "bundleName";
    std::string formEventType = "formEventType";
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    RunningFormInfo runningFormInfo;
    formTaskMgr->FormClickEvent(bundleName, formEventType, remoteObject, runningFormInfo);
    EXPECT_EQ(iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormObserverTaskMgr_0007 end";
}
}