/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "status_mgr_center/form_event_retry_mgr.h"
#include "status_mgr_center/form_event_queue.h"
#include "status_mgr_center/form_status_common.h"
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t FORM_ID = 123;
class FormEventRetryMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormEventRetryMgrTest::SetUpTestCase()
{}

void FormEventRetryMgrTest::TearDownTestCase()
{}

void FormEventRetryMgrTest::SetUp()
{}

void FormEventRetryMgrTest::TearDown()
{}

/**
 * @tc.name: FormEventRetryMgrTest_0001
 * @tc.desc: Verify GetLastFormEvent and SetLastFormEvent
 * @tc.type: FUNC
 */
HWTEST_F(FormEventRetryMgrTest, FormEventRetryMgrTest_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventRetryMgrTest_0001 start";

    int64_t formId = FORM_ID;
    FormEventTaskInfo formEventInfo;
    FormEventRetryMgr::GetInstance().DeleteLastFormEvent(formId);
    bool ret = FormEventRetryMgr::GetInstance().GetLastFormEvent(formId, formEventInfo);
    EXPECT_EQ(ret, false);

    auto task = []() { GTEST_LOG_(INFO) << "FmsFormHostQueueTest_001 Task called"; };
    FormEventTaskInfo taskInfo{formId, FormFsmEvent::RENDER_FORM, task};
    FormEventRetryMgr::GetInstance().SetLastFormEvent(formId, taskInfo);
    ret = FormEventRetryMgr::GetInstance().GetLastFormEvent(formId, formEventInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(formEventInfo.getFormEvent(), FormFsmEvent::RENDER_FORM);

    FormEventTaskInfo taskInfoNew{formId, FormFsmEvent::RECYCLE_FORM, task};
    FormEventRetryMgr::GetInstance().SetLastFormEvent(formId, taskInfoNew);
    ret = FormEventRetryMgr::GetInstance().GetLastFormEvent(formId, formEventInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(formEventInfo.getFormEvent(), FormFsmEvent::RECYCLE_FORM);
    EXPECT_EQ(formEventInfo.getFormId(), formId);

    FormEventRetryMgr::GetInstance().DeleteLastFormEvent(formId);
    ret = FormEventRetryMgr::GetInstance().GetLastFormEvent(formId, formEventInfo);
    EXPECT_EQ(ret, false);

    GTEST_LOG_(INFO) << "FormEventRetryMgrTest_0001 end";
}

/**
 * @tc.name: FormEventRetryMgrTest_0002
 * @tc.desc: Verify GetRetryCount and SetRetryCount
 * @tc.type: FUNC
 */
HWTEST_F(FormEventRetryMgrTest, FormEventRetryMgrTest_0002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormEventRetryMgrTest_0002 start";

    int64_t formId = FORM_ID;
    int32_t retryCount = 0;
    bool ret = FormEventRetryMgr::GetInstance().GetRetryCount(formId, retryCount);
    EXPECT_EQ(ret, false);

    FormEventRetryMgr::GetInstance().SetRetryCount(formId, 1);
    ret = FormEventRetryMgr::GetInstance().GetRetryCount(formId, retryCount);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(retryCount, 1);

    FormEventRetryMgr::GetInstance().SetRetryCount(formId, 2);
    ret = FormEventRetryMgr::GetInstance().GetRetryCount(formId, retryCount);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(retryCount, 2);

    FormEventRetryMgr::GetInstance().DeleteRetryCount(formId);
    ret = FormEventRetryMgr::GetInstance().GetRetryCount(formId, retryCount);
    EXPECT_EQ(ret, false);

    GTEST_LOG_(INFO) << "FormEventRetryMgrTest_0002 end";
}
}  // namespace