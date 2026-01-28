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
#include "status_mgr_center/form_render_status.h"
#include "status_mgr_center/form_status_common.h"
#include "fms_log_wrapper.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
const int64_t FORM_ID_ONE = 1;
const int64_t FORM_ID_ZERO = 0;
class FormRenderStatusTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FormRenderStatusTest::SetUpTestCase()
{}

void FormRenderStatusTest::TearDownTestCase()
{}

void FormRenderStatusTest::SetUp()
{}

void FormRenderStatusTest::TearDown()
{}

/**
 * @tc.name: FormRenderStatusTest_0001
 * @tc.desc: Verify GetFormStatus SetFormStatus and DeleteFormStatus
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderStatusTest, FormRenderStatusTest_0001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderStatusTest_0001 start";

    int64_t formId = FORM_ID_ONE;
    FormRenderStatus::GetInstance().DeleteFormStatus(formId);
    bool ret = FormRenderStatus::GetInstance().HasFormStatus(formId);
    EXPECT_EQ(ret, false);

    FormFsmStatus status = FormRenderStatus::GetInstance().GetFormStatus(formId);
    EXPECT_EQ(status, FormFsmStatus::UNPROCESSABLE);

    FormRenderStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RENDERED);
    ret = FormRenderStatus::GetInstance().HasFormStatus(formId);
    EXPECT_EQ(ret, true);

    status = FormRenderStatus::GetInstance().GetFormStatus(formId);
    EXPECT_EQ(status, FormFsmStatus::RENDERED);

    FormRenderStatus::GetInstance().SetFormStatus(formId, FormFsmStatus::RECYCLED);
    status = FormRenderStatus::GetInstance().GetFormStatus(formId);
    EXPECT_EQ(status, FormFsmStatus::RECYCLED);

    FormRenderStatus::GetInstance().DeleteFormStatus(formId);
    ret = FormRenderStatus::GetInstance().HasFormStatus(formId);
    EXPECT_EQ(ret, false);

    int64_t dFormId = FORM_ID_ZERO;
    FormRenderStatus::GetInstance().DeleteFormStatus(dFormId);
    ret = FormRenderStatus::GetInstance().HasFormStatus(dFormId);
    EXPECT_EQ(ret, false);

    GTEST_LOG_(INFO) << "FormRenderStatusTest_0001 end";
}
}  // namespace