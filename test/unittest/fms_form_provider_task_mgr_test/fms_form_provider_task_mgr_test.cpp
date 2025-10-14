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
#include "form_provider/form_provider_task_mgr.h"
#undef private
#include "mock_form_provider_client.h"
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormProviderTaskMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormProviderTaskMgrTest::SetUpTestCase()
{}

void FormProviderTaskMgrTest::TearDownTestCase()
{}

void FormProviderTaskMgrTest::SetUp()
{}

void FormProviderTaskMgrTest::TearDown()
{}

/**
 * @tc.name: FormProviderTaskMgr_0001
 * @tc.desc: Verify PostAcquireTask
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0001 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0001 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0002
 * @tc.desc: Verify PostRefreshTask
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0002 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostRefreshTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0002 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0003
 * @tc.desc: test PostDeleteTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0003 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostDeleteTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0003 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0004
 * @tc.desc: test PostProviderBatchDeleteTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0004 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    std::set<int64_t> formIds;
    formIds.insert(formId);
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostProviderBatchDeleteTask(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0004 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0005
 * @tc.desc: Verify PostCastTempTask
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0005 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostCastTempTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0005 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0006
 * @tc.desc: Verify PostAcquireStateTask
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0006 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    Want wantArg;
    std::string provider;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireStateTask(wantArg, provider, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0006 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0007
 * @tc.desc: Verify PostAcquireDataTask
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0007 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->PostAcquireDataTask(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0007 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0008
 * @tc.desc: test PostFormEventTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0008, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0008 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    std::string message = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostFormEventTask(formId, message, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0008 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0009
 * @tc.desc: test PostEventNotifyTask function and eventHandler_ is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0009, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0009 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 2;
    std::vector<int64_t> formEvent;
    formEvent.emplace_back(formId);
    int32_t formVisibleType = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->PostEventNotifyTask(formEvent, formVisibleType, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0009 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0010
 * @tc.desc: Verify AcquireProviderFormInfo
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0010 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->AcquireProviderFormInfo(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0010 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0011
 * @tc.desc: test NotifyFormUpdate function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0011, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0011 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr->NotifyFormUpdate(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0011 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0012
 * @tc.desc: Verify NotifyFormDelete
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0012 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    int64_t formId = 123;
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->NotifyFormDelete(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0012 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0013
 * @tc.desc: Verify ProviderBatchDelete
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0013 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    std::set<int64_t> formIds;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->ProviderBatchDelete(formIds, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0013 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0014
 * @tc.desc: test NotifyCastTemp function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0014, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0014 start";
    FormProviderTaskMgr formTaskMgr;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.NotifyCastTemp(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0014 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0015
 * @tc.desc: test AcquireState function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0015, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0015 start";
    FormProviderTaskMgr formTaskMgr;
    Want wantArg;
    std::string provider = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireState(wantArg, provider, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0015 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0016
 * @tc.desc: test AcquireFormData function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0016, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0016 start";
    FormProviderTaskMgr formTaskMgr;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.AcquireFormData(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0016 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0017
 * @tc.desc: test FireFormEvent function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0017, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0017 start";
    FormProviderTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::string message = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.FireFormEvent(formId, message, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0017 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0018
 * @tc.desc: test EventNotify function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0018, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0018 start";
    FormProviderTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    Want want;
    sptr<IRemoteObject> remoteObject = nullptr;
    formTaskMgr.EventNotify(formEvents, formVisibleType, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0018 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0019
 * @tc.desc: test NotifyFormUpdate function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0019, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0019 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr->NotifyFormUpdate(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0019 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0020
 * @tc.desc: test FireFormEvent function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0020, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0020 start";
    FormProviderTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::string message = "aa";
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.FireFormEvent(formId, message, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0020 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0021
 * @tc.desc: test EventNotify function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0021, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0021 start";
    FormProviderTaskMgr formTaskMgr;
    int64_t formId = 1;
    std::vector<int64_t> formEvents;
    formEvents.emplace_back(formId);
    int32_t formVisibleType = 2;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.EventNotify(formEvents, formVisibleType, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0021 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0022
 * @tc.desc: test NotifySizeChanged function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0022, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0022 start";
    FormProviderTaskMgr formTaskMgr;
    int64_t formId = 1;
    int32_t newDimension = 1;
    Rect rect;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.NotifySizeChanged(formId, newDimension, rect, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0022 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0023
 * @tc.desc: test NotifyFormLocationUpdate function and formProviderProxy is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0023, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0023 start";
    FormProviderTaskMgr formTaskMgr;
    int64_t formId = 1;
    Want want;
    sptr<IRemoteObject> remoteObject = new (std::nothrow) MockFormProviderClient();
    formTaskMgr.NotifyFormLocationUpdate(formId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0023 end";
}

/**
 * @tc.name: FormProviderTaskMgr_0024
 * @tc.desc: test DelayedFormExitDetect function
 * @tc.type: FUNC
 */
HWTEST_F(FormProviderTaskMgrTest, FormProviderTaskMgr_0024, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0024 start";
    std::shared_ptr<FormProviderTaskMgr> formTaskMgr = std::make_shared<FormProviderTaskMgr>();
    ASSERT_NE(nullptr, formTaskMgr);
    int32_t connectId = 1;
    formTaskMgr->DelayedFormExitDetect(connectId);
    GTEST_LOG_(INFO) << "FormProviderTaskMgr_0024 end";
}
}