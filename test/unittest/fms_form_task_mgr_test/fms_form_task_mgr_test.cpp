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
#include "status_mgr_center/form_task_mgr.h"
#undef private
#include "fms_log_wrapper.h"
#include "mock_form_provider_client.h"
#include "gmock/gmock.h"
#include "form_render_interface.h"
#include "feature/form_share/form_share_mgr.h"
#include "js_form_state_observer_interface.h"
#include "form_host_interface.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormTaskMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};


void FormTaskMgrTest::SetUpTestCase()
{}

void FormTaskMgrTest::TearDownTestCase()
{}

void FormTaskMgrTest::SetUp()
{}

void FormTaskMgrTest::TearDown()
{}

/**
 * @tc.name: FormTaskMgr_0001
 * @tc.desc: test PostFrsDiedTaskToHost function
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0001 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostFrsDiedTaskToHost(remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0001 end";
}

/**
 * @tc.name: FormTaskMgr_0002
 * @tc.desc: test FrsDiedTaskToHost function
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0002 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->FrsDiedTaskToHost(remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0002 end";
}

/**
 * @tc.name: FormTaskMgr_0003
 * @tc.desc: test PostAcquireTaskToHost function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0003 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostAcquireTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0003 end";
}

/**
 * @tc.name: FormTaskMgr_0004
 * @tc.desc: test PostUpdateTaskToHost function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0004 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostUpdateTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0004 end";
}

/**
 * @tc.name: FormTaskMgr_0005
 * @tc.desc: test PostUpdateTaskToHost function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0005 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    formTaskMgr->SetSerialQueue(nullptr);
    int64_t formId = 2;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostUpdateTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0005 end";
}

/**
 * @tc.name: FormTaskMgr_0006
 * @tc.desc: test PostDeleteTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0006, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0006 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostDeleteTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0006 end";
}

/**
 * @tc.name: FormTaskMgr_0007
 * @tc.desc: test PostRefreshTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0007, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0007 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostRefreshTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0007 end";
}

/**
 * @tc.name: FormTaskMgr_0008
 * @tc.desc: test PostRefreshTask function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0008 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    formTaskMgr->SetSerialQueue(nullptr);
    int64_t formId = 2;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostRefreshTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0008 end";
}

/**
 * @tc.name: FormTaskMgr_0009
 * @tc.desc: test PostHostDiedTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0009 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostHostDiedTask(remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0009 end";
}

/**
 * @tc.name: FormTaskMgr_0010
 * @tc.desc: test PostEventNotifyTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0010 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    std::vector<int64_t> formEvent;
    formEvent.emplace_back(formId);
    int32_t formVisibleType = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostEventNotifyTask(formEvent, formVisibleType, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0010 end";
}

/**
 * @tc.name: FormTaskMgr_0011
 * @tc.desc: test PostEventNotifyTask function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0011 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    formTaskMgr->SetSerialQueue(nullptr);
    int64_t formId = 2;
    std::vector<int64_t> formEvent;
    formEvent.emplace_back(formId);
    int32_t formVisibleType = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostEventNotifyTask(formEvent, formVisibleType, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0011 end";
}

/**
 * @tc.name: FormTaskMgr_0012
 * @tc.desc: test PostProviderBatchDeleteTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0012 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostProviderBatchDeleteTask(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0012 end";
}

/**
 * @tc.name: FormTaskMgr_0013
 * @tc.desc: test PostProviderBatchDeleteTask function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0013 start";
    FormTaskMgr formTaskMgr;
    formTaskMgr.SetSerialQueue(nullptr);
    int64_t formId = 2;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.PostProviderBatchDeleteTask(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0013 end";
}

/**
 * @tc.name: FormTaskMgr_0014
 * @tc.desc: test PostFormEventTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0014 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    std::string message = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostFormEventTask(formId, message, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0014 end";
}

/**
 * @tc.name: FormTaskMgr_0015
 * @tc.desc: test PostFormEventTask function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0015 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    formTaskMgr->SetSerialQueue(nullptr);
    int64_t formId = 2;
    std::string message = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostFormEventTask(formId, message, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0015 end";
}

/**
 * @tc.name: FormTaskMgr_0016
 * @tc.desc: test PostAcquireStateTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0016 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    Want wantArg;
    std::string state = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostAcquireStateTask(wantArg, state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0016 end";
}

/**
 * @tc.name: FormTaskMgr_0017
 * @tc.desc: test PostAcquireStateTask function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0017 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    formTaskMgr->SetSerialQueue(nullptr);
    Want wantArg;
    std::string state = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostAcquireStateTask(wantArg, state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0017 end";
}

/**
 * @tc.name: FormTaskMgr_0018
 * @tc.desc: test PostUninstallTaskToHost function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0018 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 3;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostUninstallTaskToHost(formIds, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0018 end";
}

/**
 * @tc.name: FormTaskMgr_0019
 * @tc.desc: test PostAcquireStateTaskToHost function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0019 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireStateTaskToHost(state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0019 end";
}

/**
 * @tc.name: FormTaskMgr_0020
 * @tc.desc: test PostAcquireStateTaskToHost function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0020 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    formTaskMgr->SetSerialQueue(nullptr);
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireStateTaskToHost(state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0020 end";
}

/**
 * @tc.name: FormTaskMgr_0021
 * @tc.desc: test PostFormShareSendResponse function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0021 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formShareRequestCode = 1;
    int32_t result = 2;
    formTaskMgr->PostFormShareSendResponse(formShareRequestCode, result);
    GTEST_LOG_(INFO) << "FormTaskMgr_0021 end";
}

/**
 * @tc.name: FormTaskMgr_0022
 * @tc.desc: test PostFormShareSendResponse function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0022 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    formTaskMgr->SetSerialQueue(nullptr);
    int64_t formShareRequestCode = 1;
    int32_t result = 2;
    formTaskMgr->PostFormShareSendResponse(formShareRequestCode, result);
    GTEST_LOG_(INFO) << "FormTaskMgr_0022 end";
}

/**
 * @tc.name: FormTaskMgr_0023
 * @tc.desc: test NotifyFormUpdate function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0023 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->NotifyFormUpdate(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0023 end";
}

/**
 * @tc.name: FormTaskMgr_0024
 * @tc.desc: test NotifyFormUpdate function and formProviderProxy is not nullptr and error == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0024 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->NotifyFormUpdate(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0024 end";
}

/**
 * @tc.name: FormTaskMgr_0025
 * @tc.desc: test EventNotify function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0025, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0025 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.EventNotify(formEvents, formVisibleType, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0025 end";
}

/**
 * @tc.name: FormTaskMgr_0026
 * @tc.desc: test EventNotify function and formProviderProxy is not nullptr and error == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0026, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0026 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.EventNotify(formEvents, formVisibleType, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0026 end";
}

/**
 * @tc.name: FormTaskMgr_0027
 * @tc.desc: test NotifyCastTemp function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0027, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0027 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.NotifyCastTemp(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0027 end";
}

/**
 * @tc.name: FormTaskMgr_0028
 * @tc.desc: test AcquireTaskToHost function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0028, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0027 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0027 end";
}

/**
 * @tc.name: FormTaskMgr_0029
 * @tc.desc: test UpdateTaskToHost function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0029, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0029 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.UpdateTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0029 end";
}

/**
 * @tc.name: FormTaskMgr_0030
 * @tc.desc: test UpdateTaskToHost function and remoteFormHost is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0030, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0030 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.UpdateTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0030 end";
}

/**
 * @tc.name: FormTaskMgr_0031
 * @tc.desc: test HostDied function and remoteHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0031, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0031 start";
    FormTaskMgr formTaskMgr;
    sptr<IRemoteObject> remoteHost = nullptr;
    formTaskMgr.HostDied(remoteHost);
    GTEST_LOG_(INFO) << "FormTaskMgr_0031 end";
}

/**
 * @tc.name: FormTaskMgr_0033
 * @tc.desc: test ProviderBatchDelete function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0033, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0033 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.ProviderBatchDelete(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0033 end";
}

/**
 * @tc.name: FormTaskMgr_0034
 * @tc.desc: test ProviderBatchDelete function and formProviderProxy is not nullptr error == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0034, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0034 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.ProviderBatchDelete(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0034 end";
}

/**
 * @tc.name: FormTaskMgr_0035
 * @tc.desc: test FireFormEvent function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0035, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0035 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::string message = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.FireFormEvent(formId, message, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0035 end";
}

/**
 * @tc.name: FormTaskMgr_0036
 * @tc.desc: test FireFormEvent function and formProviderProxy is not nullptr and error == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0036, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0036 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::string message = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.FireFormEvent(formId, message, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0036 end";
}

/**
 * @tc.name: FormTaskMgr_0037
 * @tc.desc: test AcquireState function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0037, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0037 start";
    FormTaskMgr formTaskMgr;
    Want wantArg;
    std::string provider = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireState(wantArg, provider, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0037 end";
}

/**
 * @tc.name: FormTaskMgr_0038
 * @tc.desc: test AcquireState function and formProviderProxy is not nullptr and error == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0038, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0038 start";
    FormTaskMgr formTaskMgr;
    Want wantArg;
    std::string provider = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.AcquireState(wantArg, provider, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0038 end";
}

/**
 * @tc.name: FormTaskMgr_0039
 * @tc.desc: test FormUninstall function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0039, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0039 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.FormUninstall(formIds, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0039 end";
}

/**
 * @tc.name: FormTaskMgr_0040
 * @tc.desc: test FormUninstall function and remoteFormHost is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0040, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0040 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.FormUninstall(formIds, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0040 end";
}

/**
 * @tc.name: FormTaskMgr_0041
 * @tc.desc: test AcquireStateBack function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0041, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0041 start";
    FormTaskMgr formTaskMgr;
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireStateBack(state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0041 end";
}

/**
 * @tc.name: FormTaskMgr_0042
 * @tc.desc: test AcquireStateBack function and remoteFormHost is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0042, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0042 start";
    FormTaskMgr formTaskMgr;
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.AcquireStateBack(state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0042 end";
}

/**
 * @tc.name: FormTaskMgr_0043
 * @tc.desc: test PostAcquireDataTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0043, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0043 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostAcquireDataTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0043 end";
}

/**
 * @tc.name: FormTaskMgr_0044
 * @tc.desc: test PostAcquireDataTask function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0044, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0044 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    formTaskMgr->SetSerialQueue(nullptr);
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostAcquireDataTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0044 end";
}

/**
 * @tc.name: FormTaskMgr_0045
 * @tc.desc: test AcquireFormData function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0045, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0045 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireFormData(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0045 end";
}

/**
 * @tc.name: FormTaskMgr_0046
 * @tc.desc: test AcquireFormData function and formProviderProxy is not nullptr and error == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0046, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0046 start";
    FormTaskMgr formTaskMgr;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.AcquireFormData(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0046 end";
}

/**
 * @tc.name: FormTaskMgr_0047
 * @tc.desc: test PostAcquireDataTaskToHost function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0047, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0047 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostAcquireDataTaskToHost(wantParams, requestCode, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0047 end";
}

/**
 * @tc.name: FormTaskMgr_0048
 * @tc.desc: test PostAcquireDataTaskToHost function and eventHandler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0048, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0048 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    formTaskMgr->SetSerialQueue(nullptr);
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostAcquireDataTaskToHost(wantParams, requestCode, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0048 end";
}

/**
 * @tc.name: FormTaskMgr_0049
 * @tc.desc: test AcquireFormDataBack function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0049, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0049 start";
    FormTaskMgr formTaskMgr;
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireFormDataBack(wantParams, requestCode, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0049 end";
}

/**
 * @tc.name: FormTaskMgr_0050
 * @tc.desc: test AcquireFormDataBack function and formProviderProxy is not nullptr and error == ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0050, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0050 start";
    FormTaskMgr formTaskMgr;
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.AcquireFormDataBack(wantParams, requestCode, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0050 end";
}

/**
 * @tc.name: FormTaskMgr_0051
 * @tc.desc: test PostRenderForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0051, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0051 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostRenderForm(record, want, remoteObject);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0051 end";
}

/**
 * @tc.name: FormTaskMgr_0052
 * @tc.desc: test PostStopRenderingForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0052, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0052 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostStopRenderingForm(record, want, remoteObject);
    int64_t formId = 0;
    std::string compId = "compId";
    std::string uid = "uid";
    formTaskMgr->PostReleaseRenderer(formId, compId, uid, remoteObject);
    EXPECT_EQ(formTaskMgr->serialQueue_, nullptr);
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostStopRenderingForm(record, want, remoteObject);
    formTaskMgr->PostReleaseRenderer(formId, compId, uid, remoteObject);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0052 end";
}

/**
 * @tc.name: FormTaskMgr_0053
 * @tc.desc: test ReleaseRenderer function
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0053, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0053 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 0;
    std::string compId = "compId";
    std::string uid = "uid";
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->ReleaseRenderer(formId, compId, uid, remoteObject);
    FormRecord record;
    Want want;
    formTaskMgr->RenderForm(record, want, remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0053 end";
}

/**
 * @tc.name: FormTaskMgr_0054
 * @tc.desc: test ReloadForm function
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0054, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0054 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::vector<FormRecord> formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->ReloadForm(std::move(formRecords), want, remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0054 end";
}

/**
 * @tc.name: FormTaskMgr_0054
 * @tc.desc: test FormShareSendResponse function
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0055, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0055 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formShareRequestCode = 0;
    int32_t result = 0;
    formTaskMgr->FormShareSendResponse(formShareRequestCode, result);
    EXPECT_NE(DelayedSingleton<FormShareMgr>::GetInstance(), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0055 end";
}

/*
 * Feature: FormCacheMgr
 * Function: StopRenderingForm
 * FunctionPoints: FormCacheMgr StopRenderingForm interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0056, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0056 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->StopRenderingForm(formRecords, want, remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0056 end";
}

/*
 * Feature: FormCacheMgr
 * Function: PostReloadForm
 * FunctionPoints: FormCacheMgr PostReloadForm interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0057, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0057 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::vector<FormRecord> formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostReloadForm(std::move(formRecords), want, remoteObject);
    EXPECT_EQ(formTaskMgr->serialQueue_, nullptr);
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostReloadForm(std::move(formRecords), want, remoteObject);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0057 end";
}

/*
 * Feature: FormCacheMgr
 * Function: OnUnlock
 * FunctionPoints: FormCacheMgr OnUnlock interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0058, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0058 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->OnUnlock(remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0058 end";
}

/*
 * Feature: FormCacheMgr
 * Function: PostOnUnlock
 * FunctionPoints: FormCacheMgr PostOnUnlock interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0059, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0059 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostOnUnlock(remoteObject);
    EXPECT_EQ(formTaskMgr->serialQueue_, nullptr);
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostOnUnlock(remoteObject);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0059 end";
}

/*
 * Feature: FormCacheMgr
 * Function: FormRouterEventProxy
 * FunctionPoints: FormCacheMgr FormRouterEventProxy interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0060, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0060 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 0;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->FormRouterEventProxy(formId, remoteObject, want);
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->PostOnUnlock(remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0060 end";
}

/*
 * Feature: FormCacheMgr
 * Function: PostRecycleForms
 * FunctionPoints: FormCacheMgr PostRecycleForms interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0061, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0061 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::vector<int64_t> formIds;
    Want want;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<IRemoteObject> remoteObjectOfRender = nullptr;
    formTaskMgr->PostRecycleForms(formIds, want, remoteObjectOfHost, remoteObjectOfRender);
    EXPECT_EQ(formTaskMgr->serialQueue_, nullptr);
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostRecycleForms(formIds, want, remoteObjectOfHost, remoteObjectOfRender);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0061 end";
}

/*
 * Feature: FormCacheMgr
 * Function: PostRecycleForms
 * FunctionPoints: FormCacheMgr PostRecycleForms interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0062, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0062 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formId = 1;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<IRemoteObject> remoteObjectOfRender = nullptr;
    formTaskMgr->RecycleForm(formId, remoteObjectOfHost, remoteObjectOfRender);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObjectOfRender), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0062 end";
}

/*
 * Feature: FormCacheMgr
 * Function: PostRecoverForm
 * FunctionPoints: FormCacheMgr PostRecoverForm interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0063, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0063 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostRecoverForm(record, want, remoteObject);
    EXPECT_EQ(formTaskMgr->serialQueue_, nullptr);
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostRecoverForm(record, want, remoteObject);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0063 end";
}

/*
 * Feature: FormCacheMgr
 * Function: RecoverForm
 * FunctionPoints: FormCacheMgr PostRecycleForms interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0064, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0064 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->RecoverForm(record, want, remoteObject);
    EXPECT_EQ(iface_cast<IFormRender>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0064 end";
}

/*
 * Feature: FormCacheMgr
 * Function: CancelDelayTask
 * FunctionPoints: FormCacheMgr CancelDelayTask interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0065, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0065 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::pair<int64_t, int64_t> eventMsg;
    formTaskMgr->CancelDelayTask(eventMsg);
    EXPECT_EQ(formTaskMgr->serialQueue_, nullptr);
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->CancelDelayTask(eventMsg);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0065 end";
}

/*
 * Feature: FormCacheMgr
 * Function: PostFormClickEventToHost
 * FunctionPoints: FormCacheMgr PostFormClickEventToHost interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0066, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0066 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::string bundleName = "bundleName";
    std::string formEventType = "formEventType";
    sptr<IRemoteObject> remoteObject = nullptr;
    RunningFormInfo runningFormInfo;
    formTaskMgr->PostFormClickEventToHost(bundleName, formEventType, remoteObject, runningFormInfo);
    EXPECT_EQ(formTaskMgr->serialQueue_, nullptr);
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostFormClickEventToHost(bundleName, formEventType, remoteObject, runningFormInfo);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0066 end";
}

/*
 * Feature: FormCacheMgr
 * Function: FormClickEvent
 * FunctionPoints: FormCacheMgr FormClickEvent interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0067, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0067 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    std::string bundleName = "bundleName";
    std::string formEventType = "formEventType";
    sptr<IRemoteObject> remoteObject = nullptr;
    RunningFormInfo runningFormInfo;
    formTaskMgr->FormClickEvent(bundleName, formEventType, remoteObject, runningFormInfo);
    EXPECT_EQ(iface_cast<AbilityRuntime::IJsFormStateObserver>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0067 end";
}

/*
 * Feature: FormCacheMgr
 * Function: PostBatchRefreshForms
 * FunctionPoints: FormCacheMgr PostBatchRefreshForms interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0068, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0068 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int32_t formRefreshType = 1;
    formTaskMgr->PostBatchRefreshForms(formRefreshType);
    EXPECT_EQ(formTaskMgr->serialQueue_, nullptr);
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostBatchRefreshForms(formRefreshType);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0068 end";
}

/*
 * Feature: FormCacheMgr
 * Function: EnableFormsTaskToHost
 * FunctionPoints: FormCacheMgr EnableFormsTaskToHost interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0069, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0069 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    vector<int64_t> formIds;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->EnableFormsTaskToHost(formIds, false, remoteObject);
    EXPECT_EQ(iface_cast<IFormHost>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0069 end";
}

/*
 * Feature: FormCacheMgr
 * Function: PostTask
 * FunctionPoints: FormCacheMgr PostTask interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0070, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0070 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    uint64_t delayMs = 1;
    std::function<void()> func = nullptr;
    formTaskMgr->PostTask(func, delayMs);
    vector<int64_t> formIds;
    sptr<IRemoteObject> remoteObject = nullptr;
    bool enable = false;
    auto enableFormsTaskToHostFunc = [formIds, enable, remoteObject]()
    {
        FormTaskMgr::GetInstance().EnableFormsTaskToHost(formIds, enable, remoteObject);
    };
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostFrsDiedTaskToHost(remoteObject);
    formTaskMgr->PostTask(enableFormsTaskToHostFunc, delayMs);
    EXPECT_NE(formTaskMgr->serialQueue_, nullptr);
    GTEST_LOG_(INFO) << "FormTaskMgr_0070 end";
}


/**
 * @tc.name: FormTaskMgr_0071
 * @tc.desc: Verify PostAcquireTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0071, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0071 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostAcquireTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0071 end";
}

/**
 * @tc.name: FormTaskMgr_0072
 * @tc.desc: Verify PostAcquireTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0072, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0072 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    Want want;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostAcquireTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0072 end";
}

/**
 * @tc.name: FormTaskMgr_0073
 * @tc.desc: Verify PostShareAcquireTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0073, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0073 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    std::string remoteDeviceId = "123";
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostShareAcquireTask(formId, remoteDeviceId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0073 end";
}

/**
 * @tc.name: FormTaskMgr_0074
 * @tc.desc: Verify PostShareAcquireTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0074, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0074 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    std::string remoteDeviceId = "456";
    Want want;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostShareAcquireTask(formId, remoteDeviceId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0074 end";
}

/**
 * @tc.name: FormTaskMgr_0075
 * @tc.desc: Verify PostDeleteTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0075, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0075 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostDeleteTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0075 end";
}

/**
 * @tc.name: FormTaskMgr_0076
 * @tc.desc: Verify PostDeleteTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0076, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0076 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    Want want;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostDeleteTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0076 end";
}

/**
 * @tc.name: FormTaskMgr_0077
 * @tc.desc: Verify PostRefreshTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0077, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0077 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostRefreshTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0077 end";
}

/**
 * @tc.name: FormTaskMgr_0078
 * @tc.desc: Verify PostRefreshTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0078, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0078 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    Want want;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostRefreshTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0078 end";
}

/**
 * @tc.name: FormTaskMgr_0079
 * @tc.desc: Verify PostCastTempTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0079, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0079 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostCastTempTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0079 end";
}

/**
 * @tc.name: FormTaskMgr_0080
 * @tc.desc: Verify PostCastTempTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0080, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0080 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    Want want;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostCastTempTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0080 end";
}

/**
 * @tc.name: FormTaskMgr_0081
 * @tc.desc: Verify PostAcquireTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0081, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0081 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    FormRecord record;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostAcquireTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0081 end";
}

/**
 * @tc.name: FormTaskMgr_0082
 * @tc.desc: Verify PostAcquireTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0082, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0082 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    FormRecord record;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostAcquireTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0082 end";
}

/**
 * @tc.name: FormTaskMgr_0083
 * @tc.desc: Verify PostAcquireDataTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0083, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0083 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    AAFwk::WantParams wantParams;
    int64_t requestCode = 123;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostAcquireDataTaskToHost(wantParams, requestCode, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0083 end";
}

/**
 * @tc.name: FormTaskMgr_0084
 * @tc.desc: Verify PostAcquireDataTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0084, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0084 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    AAFwk::WantParams wantParams;
    int64_t requestCode = 456;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostAcquireDataTaskToHost(wantParams, requestCode, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0084 end";
}

/**
 * @tc.name: FormTaskMgr_0085
 * @tc.desc: Verify PostUpdateTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0085, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0085 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    FormRecord record;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostUpdateTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0085 end";
}

/**
 * @tc.name: FormTaskMgr_0086
 * @tc.desc: Verify PostUpdateTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0086, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0086 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    FormRecord record;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostUpdateTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0086 end";
}

/**
 * @tc.name: FormTaskMgr_0087
 * @tc.desc: Verify PostHostDiedTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0087, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0087 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostHostDiedTask(remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0087 end";
}

/**
 * @tc.name: FormTaskMgr_0088
 * @tc.desc: Verify PostHostDiedTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0088, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0088 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostHostDiedTask(remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0088 end";
}

/**
 * @tc.name: FormTaskMgr_0089
 * @tc.desc: Verify PostEventNotifyTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0089, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0089 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::vector<int64_t> formEvent;
    int32_t formVisibleType = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostEventNotifyTask(formEvent, formVisibleType, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0089 end";
}

/**
 * @tc.name: FormTaskMgr_0090
 * @tc.desc: Verify PostEventNotifyTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0090, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0090 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::vector<int64_t> formEvent;
    int32_t formVisibleType = 456;
    Want want;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostEventNotifyTask(formEvent, formVisibleType, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0090 end";
}

/**
 * @tc.name: FormTaskMgr_0091
 * @tc.desc: Verify PostProviderBatchDeleteTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0091, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0091 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::set<int64_t> formIds;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostProviderBatchDeleteTask(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0091 end";
}

/**
 * @tc.name: FormTaskMgr_0092
 * @tc.desc: Verify PostProviderBatchDeleteTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0092, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0092 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::set<int64_t> formIds;
    Want want;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostProviderBatchDeleteTask(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0092 end";
}

/**
 * @tc.name: FormTaskMgr_0093
 * @tc.desc: Verify PostFormEventTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0093, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0093 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    std::string message = "message";
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostFormEventTask(formId, message, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0093 end";
}

/**
 * @tc.name: FormTaskMgr_0094
 * @tc.desc: Verify PostFormEventTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0094, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0094 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    std::string message = "message";
    Want want;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostFormEventTask(formId, message, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0094 end";
}

/**
 * @tc.name: FormTaskMgr_0095
 * @tc.desc: Verify PostAcquireStateTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0095, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0095 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    Want wantArg;
    std::string provider;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireStateTask(wantArg, provider, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0095 end";
}

/**
 * @tc.name: FormTaskMgr_0096
 * @tc.desc: Verify PostAcquireStateTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0096, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0096 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    Want wantArg;
    std::string provider;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireStateTask(wantArg, provider, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0096 end";
}

/**
 * @tc.name: FormTaskMgr_0097
 * @tc.desc: Verify PostAcquireDataTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0097, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0097 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostAcquireDataTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0097 end";
}

/**
 * @tc.name: FormTaskMgr_0098
 * @tc.desc: Verify PostAcquireDataTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0098, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0098 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    Want want;
    sptr<IRemoteObject> remoteObject;
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostAcquireDataTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0098 end";
}

/**
 * @tc.name: FormTaskMgr_0099
 * @tc.desc: Verify PostUninstallTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0099, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0099 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostUninstallTaskToHost(formIds, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0099 end";
}

/**
 * @tc.name: FormTaskMgr_0100
 * @tc.desc: Verify PostUninstallTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0100 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostUninstallTaskToHost(formIds, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0100 end";
}

/**
 * @tc.name: FormTaskMgr_0101
 * @tc.desc: Verify PostAcquireStateTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0101, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0101 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireStateTaskToHost(state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0101 end";
}

/**
 * @tc.name: FormTaskMgr_0102
 * @tc.desc: Verify PostAcquireStateTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0102, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0102 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireStateTaskToHost(state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0102 end";
}

/**
 * @tc.name: FormTaskMgr_0103
 * @tc.desc: Verify PostFormShareSendResponse
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0103, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0103 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    int64_t formShareRequestCode = 123;
    int32_t result = 123;
    formTaskMgr->PostFormShareSendResponse(formShareRequestCode, result);
    GTEST_LOG_(INFO) << "FormTaskMgr_0103 end";
}

/**
 * @tc.name: FormTaskMgr_0104
 * @tc.desc: Verify PostFormShareSendResponse
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0104, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0104 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    int64_t formShareRequestCode = 456;
    int32_t result = 456;
    formTaskMgr->PostFormShareSendResponse(formShareRequestCode, result);
    GTEST_LOG_(INFO) << "FormTaskMgr_0104 end";
}

/**
 * @tc.name: FormTaskMgr_0105
 * @tc.desc: Verify PostAddTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0105, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0105 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->PostAddTaskToHost(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0105 end";
}

/**
 * @tc.name: FormTaskMgr_0106
 * @tc.desc: Verify PostAddTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0106, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0106 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->PostAddTaskToHost(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0106 end";
}

/**
 * @tc.name: FormTaskMgr_0107
 * @tc.desc: Verify PostRemoveTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0107, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0107 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->PostRemoveTaskToHost(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0107 end";
}

/**
 * @tc.name: FormTaskMgr_0108
 * @tc.desc: Verify PostRemoveTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0108, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0108 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->PostRemoveTaskToHost(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0108 end";
}

/**
 * @tc.name: FormTaskMgr_0109
 * @tc.desc: Verify PostEnterpriseAppInstallFailedRetryTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0109, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0109 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    int64_t formId = 123;
    Want want;
    bool isVisibleToFresh = true;
    formTaskMgr->PostEnterpriseAppInstallFailedRetryTask(formId, want, isVisibleToFresh);
    GTEST_LOG_(INFO) << "FormTaskMgr_0109 end";
}

/**
 * @tc.name: FormTaskMgr_0110
 * @tc.desc: Verify PostEnterpriseAppInstallFailedRetryTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0110, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0110 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    int64_t formId = 456;
    Want want;
    bool isVisibleToFresh = true;
    formTaskMgr->PostEnterpriseAppInstallFailedRetryTask(formId, want, isVisibleToFresh);
    GTEST_LOG_(INFO) << "FormTaskMgr_0110 end";
}

/**
 * @tc.name: FormTaskMgr_0111
 * @tc.desc: Verify FormAdd
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0111, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0111 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->FormAdd(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0111 end";
}

/**
 * @tc.name: FormTaskMgr_0112
 * @tc.desc: Verify FormAdd
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0112, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0112 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject = nullptr;
    RunningFormInfo runningFormInfo;
    formTaskMgr->FormAdd(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0112 end";
}

/**
 * @tc.name: FormTaskMgr_0113
 * @tc.desc: Verify FormRemove
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0113, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0113 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject;
    RunningFormInfo runningFormInfo;
    formTaskMgr->FormRemove(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0113 end";
}

/**
 * @tc.name: FormTaskMgr_0114
 * @tc.desc: Verify FormRemove
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0114, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0114 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string bundleName = "bundleName";
    sptr<IRemoteObject> remoteObject = nullptr;
    RunningFormInfo runningFormInfo;
    formTaskMgr->FormRemove(bundleName, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0114 end";
}

/**
 * @tc.name: FormTaskMgr_0115
 * @tc.desc: Verify AcquireProviderFormInfo
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0115, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0115 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->AcquireProviderFormInfo(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0115 end";
}

/**
 * @tc.name: FormTaskMgr_0116
 * @tc.desc: Verify AcquireShareFormData
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0116, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0116 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    std::string remoteDeviceId = "remoteDeviceId";
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->AcquireShareFormData(formId, remoteDeviceId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0116 end";
}

/**
 * @tc.name: FormTaskMgr_0117
 * @tc.desc: Verify NotifyFormDelete
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0117, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0117 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->NotifyFormDelete(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0117 end";
}

/**
 * @tc.name: FormTaskMgr_0118
 * @tc.desc: Verify NotifyCastTemp
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0118, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0118 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->NotifyCastTemp(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0118 end";
}

/**
 * @tc.name: FormTaskMgr_0119
 * @tc.desc: Verify PostAcquireTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0119, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0119 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 2;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->PostAcquireTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0119 end";
}

/**
 * @tc.name: FormTaskMgr_0120
 * @tc.desc: Verify HostDied
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0120, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0120 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    sptr<IRemoteObject> remoteHost = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->HostDied(remoteHost);
    GTEST_LOG_(INFO) << "FormTaskMgr_0120 end";
}

/**
 * @tc.name: FormTaskMgr_0121
 * @tc.desc: Verify ProviderBatchDelete
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0121, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0121 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::set<int64_t> formIds;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->ProviderBatchDelete(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0121 end";
}

/**
 * @tc.name: FormTaskMgr_0122
 * @tc.desc: Verify CreateFormJsInfo
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0122, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0122 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    FormRecord record;
    formTaskMgr->CreateFormJsInfo(formId, record);
    GTEST_LOG_(INFO) << "FormTaskMgr_0122 end";
}

/**
 * @tc.name: FormTaskMgr_0123
 * @tc.desc: Verify PostRenderForm
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0123, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0123 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    FormRecord record;
    Want want;
    want.SetParam(Constants::FORM_UPDATE_TYPE_KEY, Constants::ADAPTER_UPDATE_FORM);
    sptr<IRemoteObject> remoteObject = nullptr;
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostRenderForm(record, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0123 end";
}

/**
 * @tc.name: FormTaskMgr_0124
 * @tc.desc: Verify InnerPostRenderForm
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0124, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0124 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    FormRecord formRecord;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->InnerPostRenderForm(formRecord, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0124 end";
}

/**
 * @tc.name: FormTaskMgr_0125
 * @tc.desc: Verify InnerPostRenderForm
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0125, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0125 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->formLastRecoverTimes.clear();
    formTaskMgr->formLastRecoverTimes.insert({123, 123});
    FormRecord formRecord;
    formRecord.formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->InnerPostRenderForm(formRecord, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0125 end";
}

/**
 * @tc.name: FormTaskMgr_0126
 * @tc.desc: Verify InnerPostRenderForm
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0126, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0126 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->formLastRecoverTimes.clear();
    formTaskMgr->formLastRecoverTimes.insert({123, 0});
    FormRecord formRecord;
    formRecord.formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->InnerPostRenderForm(formRecord, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0126 end";
}

/**
 * @tc.name: FormTaskMgr_0127
 * @tc.desc: Verify RenderForm
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0127, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0127 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->RenderForm(record, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0127 end";
}

/**
 * @tc.name: FormTaskMgr_0128
 * @tc.desc: Verify StopRenderingForm
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0128, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0128 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    FormRecord formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->StopRenderingForm(formRecords, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0128 end";
}

/**
 * @tc.name: FormTaskMgr_0129
 * @tc.desc: Verify ReloadForm
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0129, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0129 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::vector<FormRecord> formRecords;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->ReloadForm(std::move(formRecords), want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0129 end";
}

/**
 * @tc.name: FormTaskMgr_0130
 * @tc.desc: Verify SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0130, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0130 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    bool isVisible = true;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->SetVisibleChange(formId, isVisible, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0130 end";
}

/**
 * @tc.name: FormTaskMgr_0131
 * @tc.desc: Verify SetVisibleChange
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0131, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0131 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 456;
    bool isVisible = true;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->SetVisibleChange(formId, isVisible, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0131 end";
}

/**
 * @tc.name: FormTaskMgr_0132
 * @tc.desc: Verify PostRouterProxyToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0132, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0132 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    int64_t formId = 123;
    sptr<IRemoteObject> remoteObject;
    Want want;
    formTaskMgr->PostRouterProxyToHost(formId, remoteObject, want);
    GTEST_LOG_(INFO) << "FormTaskMgr_0132 end";
}

/**
 * @tc.name: FormTaskMgr_0133
 * @tc.desc: Verify PostRouterProxyToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0133, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0133 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    int64_t formId = 456;
    sptr<IRemoteObject> remoteObject;
    Want want;
    formTaskMgr->PostRouterProxyToHost(formId, remoteObject, want);
    GTEST_LOG_(INFO) << "FormTaskMgr_0133 end";
}

/**
 * @tc.name: FormTaskMgr_0134
 * @tc.desc: Verify FormRouterEventProxy
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0134, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0134 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 0;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    Want want;
    formTaskMgr->FormRouterEventProxy(formId, remoteObject, want);
    GTEST_LOG_(INFO) << "FormTaskMgr_0134 end";
}

/**
 * @tc.name: FormTaskMgr_0135
 * @tc.desc: Verify PostVisibleNotify
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0135, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0135 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    std::vector<int64_t> formIds;
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::map<std::string, std::vector<int64_t>> eventMaps;
    int32_t formVisibleType = 123;
    int32_t visibleNotifyDelay = 123;
    sptr<IRemoteObject> callerToken;
    formTaskMgr->PostVisibleNotify(formIds, formInstanceMaps, eventMaps,
        formVisibleType, visibleNotifyDelay, callerToken);
    GTEST_LOG_(INFO) << "FormTaskMgr_0135 end";
}

/**
 * @tc.name: FormTaskMgr_0136
 * @tc.desc: Verify PostVisibleNotify
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0136, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0136 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    std::vector<int64_t> formIds;
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::map<std::string, std::vector<int64_t>> eventMaps;
    int32_t formVisibleType = 456;
    int32_t visibleNotifyDelay = 456;
    sptr<IRemoteObject> callerToken;
    formTaskMgr->PostVisibleNotify(formIds, formInstanceMaps, eventMaps,
        formVisibleType, visibleNotifyDelay, callerToken);
    GTEST_LOG_(INFO) << "FormTaskMgr_0136 end";
}

/**
 * @tc.name: FormTaskMgr_0137
 * @tc.desc: Verify NotifyVisible
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0137, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0137 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::vector<int64_t> formIds;
    std::map<std::string, std::vector<FormInstance>> formInstanceMaps;
    std::map<std::string, std::vector<int64_t>> eventMaps;
    int32_t formVisibleType = 456;
    sptr<IRemoteObject> callerToken;
    formTaskMgr->NotifyVisible(formIds, formInstanceMaps, eventMaps, formVisibleType, callerToken);
    GTEST_LOG_(INFO) << "FormTaskMgr_0137 end";
}

/**
 * @tc.name: FormTaskMgr_0138
 * @tc.desc: Verify PostRecycleForms
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0138, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0138 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    std::vector<int64_t> formIds = {123, 456, 789};
    Want want;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<IRemoteObject> remoteObjectOfRender = nullptr;
    formTaskMgr->PostRecycleForms(formIds, want, remoteObjectOfHost, remoteObjectOfRender);
    GTEST_LOG_(INFO) << "FormTaskMgr_0138 end";
}

/**
 * @tc.name: FormTaskMgr_0139
 * @tc.desc: Verify RecycleForm
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0139, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0139 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 1;
    sptr<IRemoteObject> remoteObjectOfHost = nullptr;
    sptr<IRemoteObject> remoteObjectOfRender = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->RecycleForm(formId, remoteObjectOfHost, remoteObjectOfRender);
    GTEST_LOG_(INFO) << "FormTaskMgr_0139 end";
}

/**
 * @tc.name: FormTaskMgr_0140
 * @tc.desc: Verify RecoverForm
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0140, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0140 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    FormRecord record;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->RecoverForm(record, want, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0140 end";
}

/**
 * @tc.name: FormTaskMgr_0141
 * @tc.desc: Verify PostDelayRecheckWhetherNeedCleanFormHostTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0141, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0141 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    int callerUid = 1;
    sptr<IRemoteObject> remoteObjectOfHost = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->PostDelayRecheckWhetherNeedCleanFormHostTask(callerUid, remoteObjectOfHost);
    GTEST_LOG_(INFO) << "FormTaskMgr_0141 end";
}

/**
 * @tc.name: FormTaskMgr_0142
 * @tc.desc: Verify PostDelayRecheckWhetherNeedCleanFormHostTask
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0142, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0142 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    int callerUid = 2;
    sptr<IRemoteObject> remoteObjectOfHost = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->PostDelayRecheckWhetherNeedCleanFormHostTask(callerUid, remoteObjectOfHost);
    GTEST_LOG_(INFO) << "FormTaskMgr_0142 end";
}

/**
 * @tc.name: FormTaskMgr_0143
 * @tc.desc: Verify FormClickEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0143, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0143 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    std::string bundleName = "bundleName";
    std::string formEventType = "formEventType";
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    RunningFormInfo runningFormInfo;
    formTaskMgr->FormClickEvent(bundleName, formEventType, remoteObject, runningFormInfo);
    GTEST_LOG_(INFO) << "FormTaskMgr_0143 end";
}

/**
 * @tc.name: FormTaskMgr_0144
 * @tc.desc: Verify PostEnableFormsTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0144, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0144 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    std::vector<int64_t> formIds;
    bool enable = true;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostEnableFormsTaskToHost(formIds, enable, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0144 end";
}

/**
 * @tc.name: FormTaskMgr_0145
 * @tc.desc: Verify EnableFormsTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0145, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0145 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    vector<int64_t> formIds;
    bool enable = false;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->EnableFormsTaskToHost(formIds, enable, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0145 end";
}

/**
 * @tc.name: FormTaskMgr_0146
 * @tc.desc: Verify PostLockFormsTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0146, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0146 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    std::vector<int64_t> formIds;
    bool lock = true;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostLockFormsTaskToHost(formIds, lock, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0146 end";
}

/**
 * @tc.name: FormTaskMgr_0147
 * @tc.desc: Verify PostLockFormsTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0147, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0147 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    std::vector<int64_t> formIds;
    bool lock = true;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostLockFormsTaskToHost(formIds, lock, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0147 end";
}

/**
 * @tc.name: FormTaskMgr_0148
 * @tc.desc: Verify PostUpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0148, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0148 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    int64_t formId = 123;
    float width = 1;
    float height = 1;
    float borderWidth = 1;
    std::string uid = "123";
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostUpdateFormSize(formId, width, height, borderWidth, uid, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0148 end";
}

/**
 * @tc.name: FormTaskMgr_0149
 * @tc.desc: Verify PostUpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0149, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0149 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    int64_t formId = 123;
    float width = 1;
    float height = 1;
    float borderWidth = 1;
    std::string uid = "123";
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostUpdateFormSize(formId, width, height, borderWidth, uid, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0149 end";
}

/**
 * @tc.name: FormTaskMgr_0150
 * @tc.desc: Verify UpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0150, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0150 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    float width = 1;
    float height = 1;
    float borderWidth = 1;
    std::string uid = "123";
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->UpdateFormSize(formId, width, height, borderWidth, uid, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0150 end";
}

/**
 * @tc.name: FormTaskMgr_0151
 * @tc.desc: Verify UpdateFormSize
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0151, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0151 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    int64_t formId = 123;
    float width = 1;
    float height = 1;
    float borderWidth = 1;
    std::string uid = "123";
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->UpdateFormSize(formId, width, height, borderWidth, uid, remoteObject);
    GTEST_LOG_(INFO) << "FormTaskMgr_0151 end";
}

/**
 * @tc.name: FormTaskMgr_0152
 * @tc.desc: Verify PostConnectNetWork
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0152, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0152 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    formTaskMgr->PostConnectNetWork();
    GTEST_LOG_(INFO) << "FormTaskMgr_0152 end";
}

/**
 * @tc.name: FormTaskMgr_0153
 * @tc.desc: Verify PostConnectNetWork
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0153, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0153 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    formTaskMgr->PostConnectNetWork();
    GTEST_LOG_(INFO) << "FormTaskMgr_0153 end";
}

/**
 * @tc.name: FormTaskMgr_0154
 * @tc.desc: Verify ConnectNetWork
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0154, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0154 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->ConnectNetWork();
    GTEST_LOG_(INFO) << "FormTaskMgr_0154 end";
}

/**
 * @tc.name: FormTaskMgr_0155
 * @tc.desc: Verify PostDelayRefreshForms
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0155, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0155 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    formTaskMgr->serialQueue_ = nullptr;
    std::vector<FormRecord> updatedForms;
    Want want;
    formTaskMgr->PostDelayRefreshForms(updatedForms, want);
    GTEST_LOG_(INFO) << "FormTaskMgr_0155 end";
}

/**
 * @tc.name: FormTaskMgr_0156
 * @tc.desc: Verify PostDelayRefreshForms
 * @tc.type: FUNC
 */
HWTEST_F(FormTaskMgrTest, FormTaskMgr_0156, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormTaskMgr_0156 start";
    std::shared_ptr<FormTaskMgr> formTaskMgr = std::make_shared<FormTaskMgr>();
    const std::string queueName = "queue";
    formTaskMgr->serialQueue_ = std::make_shared<FormSerialQueue>(queueName.c_str());
    FormRecord formRecord1;
    FormRecord formRecord2;
    std::vector<FormRecord> updatedForms = {formRecord1, formRecord2};
    Want want;
    formTaskMgr->PostDelayRefreshForms(updatedForms, want);
    GTEST_LOG_(INFO) << "FormTaskMgr_0156 end";
}
}