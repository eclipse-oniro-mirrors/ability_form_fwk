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
#define private public
#include "status_mgr_center/form_status_table.h"
#include "status_mgr_center/form_status_common.h"
#undef private
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FormStatusTableTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormStatusTableTest::SetUpTestCase()
{}

void FormStatusTableTest::TearDownTestCase()
{}

void FormStatusTableTest::SetUp()
{}

void FormStatusTableTest::TearDown()
{}

/**
 * @tc.name: GetFormStatusInfoTest
 * @tc.desc: Verify GetFormStatusInfo
 * @tc.type: FUNC
 */
HWTEST_F(FormStatusTableTest, GetFormStatusInfoTest, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "GetFormStatusInfoTest start";

    FormStatusMachineInfo info;
    bool ret =
        FormStatusTable::GetInstance().GetFormStatusInfo(FormFsmStatus::INIT, FormFsmEvent::RENDER_FORM_DONE, info);
    EXPECT_EQ(ret, false);

    ret = FormStatusTable::GetInstance().GetFormStatusInfo((FormFsmStatus)100, FormFsmEvent::RENDER_FORM, info);
    EXPECT_EQ(ret, false);

    ret = FormStatusTable::GetInstance().GetFormStatusInfo(FormFsmStatus::INIT, FormFsmEvent::RENDER_FORM, info);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(info.nextStatus, FormFsmStatus::RENDERING);
    EXPECT_EQ(info.processType, FormFsmProcessType::PROCESS_TASK_DIRECT);
    EXPECT_EQ(info.timeoutMs, FormEventTimeout::TIMEOUT_3_S);

    GTEST_LOG_(INFO) << "GetFormStatusInfoTest end";
}
}  // namespace