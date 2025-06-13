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
#include "feature/form_share/form_share_task_mgr.h"
#undef private
#include "fms_log_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormShareTaskMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormShareTaskMgrTest::SetUpTestCase()
{}

void FormShareTaskMgrTest::TearDownTestCase()
{}

void FormShareTaskMgrTest::SetUp()
{}

void FormShareTaskMgrTest::TearDown()
{}

/**
 * @tc.name: FormShareTaskMgr_0001
 * @tc.desc: Verify PostShareAcquireTask
 * @tc.type: FUNC
 */
HWTEST_F(FormShareTaskMgrTest, FormShareTaskMgr_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormShareTaskMgr_0001 start";
    // std::shared_ptr<FormShareTaskMgr> formTaskMgr = std::make_shared<FormShareTaskMgr>();
    int64_t formId = 123;
    std::string remoteDeviceId = "123";
    Want want;
    sptr<IRemoteObject> remoteObject;
    // formTaskMgr->PostShareAcquireTask(formId, remoteDeviceId, want, remoteObject);
    FormShareTaskMgr::GetInstance().PostShareAcquireTask(formId, remoteDeviceId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormShareTaskMgr_0001 end";
}

/**
 * @tc.name: FormShareTaskMgr_0002
 * @tc.desc: Verify PostFormShareSendResponse
 * @tc.type: FUNC
 */
HWTEST_F(FormShareTaskMgrTest, FormShareTaskMgr_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormShareTaskMgr_0002 start";
    std::shared_ptr<FormShareTaskMgr> formTaskMgr = std::make_shared<FormShareTaskMgr>();
    int64_t formShareRequestCode = 123;
    int32_t result = 123;
    formTaskMgr->PostFormShareSendResponse(formShareRequestCode, result);
    GTEST_LOG_(INFO) << "FormShareTaskMgr_0002 end";
}

/**
 * @tc.name: FormShareTaskMgr_0003
 * @tc.desc: Verify AcquireShareFormData
 * @tc.type: FUNC
 */
HWTEST_F(FormShareTaskMgrTest, FormShareTaskMgr_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormShareTaskMgr_0003 start";
    std::shared_ptr<FormShareTaskMgr> formTaskMgr = std::make_shared<FormShareTaskMgr>();
    int64_t formId = 123;
    std::string remoteDeviceId = "remoteDeviceId";
    Want want;
    sptr<IRemoteObject> remoteObject;
    formTaskMgr->AcquireShareFormData(formId, remoteDeviceId, want, remoteObject);
    GTEST_LOG_(INFO) << "FormShareTaskMgr_0003 end";
}

/**
 * @tc.name: FormShareTaskMgr_0004
 * @tc.desc: test FormShareSendResponse function
 * @tc.type: FUNC
 */
HWTEST_F(FormShareTaskMgrTest, FormShareTaskMgr_0004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormShareTaskMgr_0004 start";
    std::shared_ptr<FormShareTaskMgr> formTaskMgr = std::make_shared<FormShareTaskMgr>();
    ASSERT_NE(formTaskMgr, nullptr);
    int64_t formShareRequestCode = 0;
    int32_t result = 0;
    formTaskMgr->FormShareSendResponse(formShareRequestCode, result);
    EXPECT_NE(DelayedSingleton<FormShareTaskMgr>::GetInstance(), nullptr);
    GTEST_LOG_(INFO) << "FormShareTaskMgr_0004 end";
}
}