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
#include "form_host/form_host_task_mgr.h"
#undef private
#include "mock_form_provider_client.h"
#include "form_host_interface.h"
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormHostTaskMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormHostTaskMgrTest::SetUpTestCase()
{}

void FormHostTaskMgrTest::TearDownTestCase()
{}

void FormHostTaskMgrTest::SetUp()
{}

void FormHostTaskMgrTest::TearDown()
{}

/**
 * @tc.name: FormHostTaskMgr_0001
 * @tc.desc: test PostAcquireTaskToHost function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0001 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostAcquireTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0001 end";
}

/**
 * @tc.name: FormHostTaskMgr_0002
 * @tc.desc: Verify PostUpdateTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0002 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostUpdateTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0002 end";
}

/**
 * @tc.name: FormHostTaskMgr_0003
 * @tc.desc: Verify PostUninstallTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0003 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 3;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostUninstallTaskToHost(formIds, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0003 end";
}

/**
 * @tc.name: FormHostTaskMgr_0004
 * @tc.desc: test PostAcquireStateTaskToHost function
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0004 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireStateTaskToHost(state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0004 end";
}

/**
 * @tc.name: FormHostTaskMgr_0005
 * @tc.desc: test PostAcquireDataTaskToHost function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0005 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostAcquireDataTaskToHost(wantParams, requestCode, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0005 end";
}

/**
 * @tc.name: FormHostTaskMgr_0006
 * @tc.desc: Verify PostEnableFormsTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0006 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    std::vector<int64_t> formIds;
    bool enable = true;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostEnableFormsTaskToHost(formIds, enable, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0006 end";
}

/**
 * @tc.name: FormHostTaskMgr_0007
 * @tc.desc: Verify PostLockFormsTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0007 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    std::vector<int64_t> formIds;
    bool lock = true;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostLockFormsTaskToHost(formIds, lock, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0007 end";
}

/**
 * @tc.name: FormHostTaskMgr_0008
 * @tc.desc: test PostFrsDiedTaskToHost function
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0008 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostFrsDiedTaskToHost(remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0008 end";
}

/**
 * @tc.name: FormHostTaskMgr_0009
 * @tc.desc: test PostHostDiedTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0009 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostHostDiedTask(remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0009 end";
}

/**
 * @tc.name: FormHostTaskMgr_0010
 * @tc.desc: test AcquireTaskToHost function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0010, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0010 start";
    FormHostTaskMgr formTaskMgr;
    int64_t formId = 1;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0010 end";
}

/**
 * @tc.name: FormHostTaskMgr_0011
 * @tc.desc: test UpdateTaskToHost function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0011 start";
    FormHostTaskMgr formTaskMgr;
    int64_t formId = 1;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.UpdateTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0011 end";
}

/**
 * @tc.name: FormHostTaskMgr_0012
 * @tc.desc: test FormUninstall function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0012, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0012 start";
    FormHostTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.FormUninstall(formIds, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0012 end";
}

/**
 * @tc.name: FormHostTaskMgr_0013
 * @tc.desc: test AcquireStateBack function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0013, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0013 start";
    FormHostTaskMgr formTaskMgr;
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireStateBack(state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0013 end";
}

/**
 * @tc.name: FormHostTaskMgr_0014
 * @tc.desc: test AcquireFormDataBack function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0014 start";
    FormHostTaskMgr formTaskMgr;
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireFormDataBack(wantParams, requestCode, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0014 end";
}

/*
 * Feature: FormHostTaskMgr_0015
 * Function: EnableFormsTaskToHost
 * FunctionPoints: FormCacheMgr EnableFormsTaskToHost interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0015 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    vector<int64_t> formIds;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->EnableFormsTaskToHost(formIds, false, remoteObject);
    EXPECT_EQ(iface_cast<IFormHost>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0015 end";
}

/*
 * Feature: FormHostTaskMgr_0016
 * Function: LockFormsTaskToHost
 * FunctionPoints: FormCacheMgr LockFormsTaskToHost interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0016 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    vector<int64_t> formIds;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->LockFormsTaskToHost(formIds, false, remoteObject);
    EXPECT_EQ(iface_cast<IFormHost>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0016 end";
}

/**
 * @tc.name: FormHostTaskMgr_0017
 * @tc.desc: test FrsDiedTaskToHost function
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0017 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->FrsDiedTaskToHost(remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0017 end";
}

/**
 * @tc.name: FormHostTaskMgr_0018
 * @tc.desc: test HostDied function and remoteHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0018 start";
    FormHostTaskMgr formTaskMgr;
    sptr<IRemoteObject> remoteHost = nullptr;
    formTaskMgr.HostDied(remoteHost);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0018 end";
}

/**
 * @tc.name: FormHostTaskMgr_0019
 * @tc.desc: Verify PostAcquireTaskToHost
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0019 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    int64_t formId = 2;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->PostAcquireTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0019 end";
}

/**
 * @tc.name: FormHostTaskMgr_0020
 * @tc.desc: test UpdateTaskToHost function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0020 start";
    FormHostTaskMgr formTaskMgr;
    int64_t formId = 1;
    FormRecord record;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.UpdateTaskToHost(formId, record, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0020 end";
}

/**
 * @tc.name: FormHostTaskMgr_0021
 * @tc.desc: test FormUninstall function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0021 start";
    FormHostTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.FormUninstall(formIds, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0021 end";
}

/**
 * @tc.name: FormHostTaskMgr_0022
 * @tc.desc: test AcquireStateBack function and remoteFormHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0022 start";
    FormHostTaskMgr formTaskMgr;
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.AcquireStateBack(state, want, remoteObject);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0022 end";
}

/*
 * Feature: FormHostTaskMgr_0023
 * Function: EnableFormsTaskToHost
 * FunctionPoints: FormCacheMgr EnableFormsTaskToHost interface
 * EnvConditions: Mobile that can run ohos test framework
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0023 start";
    std::shared_ptr<FormHostTaskMgr> formTaskMgr = std::make_shared<FormHostTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    vector<int64_t> formIds;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->EnableFormsTaskToHost(formIds, false, remoteObject);
    EXPECT_EQ(iface_cast<IFormHost>(remoteObject), nullptr);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0023 end";
}

/**
 * @tc.name: FormHostTaskMgr_0024
 * @tc.desc: test HostDied function and remoteHost is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostTaskMgrTest, FormHostTaskMgr_0024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0024 start";
    FormHostTaskMgr formTaskMgr;
    sptr<IRemoteObject> remoteHost = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.HostDied(remoteHost);
    GTEST_LOG_(INFO) << "FormHostTaskMgr_0024 end";
}
}