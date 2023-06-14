/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "form_constants.h"
#include "form_mgr_errors.h"
#define private public
#include "form_render_service_extension.h"
#undef private
#include "gmock/gmock.h"
#include "fms_log_wrapper.h"
#include "want.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

class FormRenderServiceExtensionTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};
void FormRenderServiceExtensionTest::SetUpTestCase()
{}

void FormRenderServiceExtensionTest::TearDownTestCase()
{}

void FormRenderServiceExtensionTest::SetUp()
{}

void FormRenderServiceExtensionTest::TearDown()
{}

/**
 * @tc.name: FormRenderServiceExtensionTest_001
 * @tc.desc: Verify Init interface executes as expected.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceExtensionTest, FormRenderServiceExtensionTest_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceExtensionTest_001 start";
    std::unique_ptr<Runtime> runtime = nullptr;
    auto formRenderServiceExtension = FormRenderServiceExtension::Create(runtime);
    std::shared_ptr<AbilityLocalRecord> record = nullptr;
    std::shared_ptr<OHOSApplication> application = nullptr;
    std::shared_ptr<AbilityHandler> handler = nullptr;
    sptr<IRemoteObject> token = nullptr;
    formRenderServiceExtension->Init(record, application, handler, token);
    GTEST_LOG_(INFO) << "FormRenderServiceExtensionTest_001 end";
}

/**
 * @tc.name: FormRenderServiceExtensionTest_002
 * @tc.desc: Verify OnCommand interface executes as expected.
 * @tc.type: FUNC
 */
HWTEST_F(FormRenderServiceExtensionTest, FormRenderServiceExtensionTest_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "FormRenderServiceExtensionTest_002 start";
    std::unique_ptr<Runtime> runtime = nullptr;
    auto formRenderServiceExtension = FormRenderServiceExtension::Create(runtime);
    AAFwk::Want want;
    bool restart = true;
    int startId = 1;
    formRenderServiceExtension->OnCommand(want, restart, startId);
    GTEST_LOG_(INFO) << "FormRenderServiceExtensionTest_002 end";
}