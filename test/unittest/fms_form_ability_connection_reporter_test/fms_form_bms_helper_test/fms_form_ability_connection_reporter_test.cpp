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
#include "form_ability_connection_reporter.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class FmsFormAbilityConnectionReporterTest : public testing::Test {
public:
    static void SetUpCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void FmsFormAbilityConnectionReporterTest::SetUpCase() {}

void FmsFormAbilityConnectionReporterTest::TearDownTestCase() {}

void FmsFormAbilityConnectionReporterTest::SetUp() {}

void FmsFormAbilityConnectionReporterTest::TearDown() {}

/**
 * @tc.name: FormAbilityConnectionReporterTest_001
 * @tc.desc: Verify function ReportFormAbilityConnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection begin";
    std::string bundleName = "testBundleName";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityConnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_002
 * @tc.desc: Verify function ReportFormAbilityDisconnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection begin";
    std::string bundleName = "testBundleName";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityDisconnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection end";
}
} // namespace AppExecFwk
} // namespace OHOS
