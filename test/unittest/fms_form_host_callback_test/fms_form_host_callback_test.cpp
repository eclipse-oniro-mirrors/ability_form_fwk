/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "gmock/gmock.h"
#include "form_mgr_errors.h"
#include "fms_log_wrapper.h"
#include "mock_form_provider_client.h"
#include "mock_form_host_task_mgr.h"
#define private public
#include "bms_mgr/form_bms_helper.h"
#include "form_host/form_host_callback.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormHostCallbackTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};


void FormHostCallbackTest::SetUpTestCase()
{}

void FormHostCallbackTest::TearDownTestCase()
{}

void FormHostCallbackTest::SetUp()
{}

void FormHostCallbackTest::TearDown()
{}

/**
 * @tc.name: FormHostCallbackTest_0001
 * @tc.desc: test OnUpdate function and formId < 0
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0001, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0001 start");
    FormHostCallback formHostCallback;
    int64_t formId = -1;
    FormRecord record;
    sptr<IRemoteObject> callerToken = nullptr;
    formHostCallback.OnUpdate(formId, record, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0001 end";
}

/**
 * @tc.name: FormHostCallbackTest_0002
 * @tc.desc: test OnUpdate function and formId > 0 and callerToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0002, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0002 start");
    FormHostCallback formHostCallback;
    int64_t formId = 2;
    FormRecord record;
    sptr<IRemoteObject> callerToken = nullptr;
    formHostCallback.OnUpdate(formId, record, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0002 end";
}

/**
 * @tc.name: FormHostCallbackTest_0003
 * @tc.desc: test OnUpdate function and formId > 0 and callerToken is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0003, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0003 start");
    FormHostCallback formHostCallback;
    int64_t formId = 2;
    FormRecord record;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formHostCallback.OnUpdate(formId, record, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0003 end";
}

/**
 * @tc.name: FormHostCallbackTest_0004
 * @tc.desc: test OnUninstall function and formIds is empty
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0004, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0004 start");
    FormHostCallback formHostCallback;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = nullptr;
    formHostCallback.OnUninstall(formIds, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0004 end";
}

/**
 * @tc.name: FormHostCallbackTest_0005
 * @tc.desc: test OnUninstall function and formIds is not empty and callerToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0005, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0005 start");
    FormHostCallback formHostCallback;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = nullptr;
    formHostCallback.OnUninstall(formIds, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0005 end";
}

/**
 * @tc.name: FormHostCallbackTest_0006
 * @tc.desc: test OnAcquireState function callerToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0006, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0006 start");
    FormHostCallback formHostCallback;
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> callerToken = nullptr;
    formHostCallback.OnAcquireState(state, want, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0006 end";
}

/**
 * @tc.name: FormHostCallbackTest_0007
 * @tc.desc: test OnAcquireState function callerToken is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0007, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0007 start");
    FormHostCallback formHostCallback;
    AppExecFwk::FormState state = AppExecFwk::FormState::UNKNOWN;
    AAFwk::Want want;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formHostCallback.OnAcquireState(state, want, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0007 end";
}

/**
 * @tc.name: FormHostCallbackTest_0008
 * @tc.desc: test OnAcquireFormData function callerToken is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0008, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0008 start");
    FormHostCallback formHostCallback;
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    sptr<IRemoteObject> callerToken = nullptr;
    formHostCallback.OnAcquireFormData(wantParams, requestCode, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0008 end";
}

/**
 * @tc.name: FormHostCallbackTest_0009
 * @tc.desc: test OnAcquireFormData function callerToken is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0009, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0009 start");
    FormHostCallback formHostCallback;
    AAFwk::WantParams wantParams;
    int64_t requestCode = 1;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formHostCallback.OnAcquireFormData(wantParams, requestCode, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0009 end";
}

/**
 * @tc.name: FormHostCallbackTest_0010
 * @tc.desc: test OnEnableForms function
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_0010, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_0010 start");
    FormHostCallback formHostCallback;
    int64_t formId = 1;
    std::vector<int64_t> formIds;
    formIds.emplace_back(formId);
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formHostCallback.OnEnableForms(formIds, true, callerToken);
    formHostCallback.OnEnableForms(formIds, false, callerToken);
    GTEST_LOG_(INFO) << "FormHostCallbackTest_0010 end";
}


/**
 * @tc.name: FormHostCallbackTest_OnCheckForms_0001
 * @tc.desc: test OnEnableForms function
 * @tc.type: FUNC
 */
HWTEST_F(FormHostCallbackTest, FormHostCallbackTest_OnCheckForms_0001, TestSize.Level0)
{
    HILOG_INFO("FormHostCallbackTest_OnCheckForms_0001 start");
    MockFormHostTaskMgr::obj = std::make_shared<MockFormHostTaskMgr>();
    EXPECT_CALL(*MockFormHostTaskMgr::obj, PostCheckFormsTaskToHost(_, _)).Times(1);

    FormHostCallback formHostCallback;
    std::vector<int64_t> formIds;
    sptr<IRemoteObject> callerToken = new (std::nothrow) MockFormProviderClient();
    formHostCallback.OnCheckForms(formIds, callerToken);
    
    int64_t formId = 1;
    formIds.emplace_back(formId);
    formHostCallback.OnCheckForms(formIds, nullptr);

    formHostCallback.OnCheckForms(formIds, callerToken);

    MockFormHostTaskMgr::obj = nullptr;
    GTEST_LOG_(INFO) << "FormHostCallbackTest_OnCheckForms_0001 end";
}
}