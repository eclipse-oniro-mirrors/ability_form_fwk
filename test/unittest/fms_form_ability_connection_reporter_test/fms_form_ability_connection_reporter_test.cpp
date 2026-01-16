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
#include "common/connection/form_ability_connection_reporter.h"

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
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_001 begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityConnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_001 end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_002
 * @tc.desc: Verify function ReportFormAbilityDisconnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_002 begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityDisconnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_002 end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_003
 * @tc.desc: Verify function ReportFormAbilityConnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityConnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_004
 * @tc.desc: Verify function ReportFormAbilityDisconnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityDisconnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_005
 * @tc.desc: Verify function ReportFormAbilityConnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityConnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_006
 * @tc.desc: Verify function ReportFormAbilityDisconnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityDisconnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_007
 * @tc.desc: Verify function ReportFormAbilityConnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityConnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_008
 * @tc.desc: Verify function ReportFormAbilityDisconnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityDisconnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_009
 * @tc.desc: Verify function ReportFormAbilityConnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityConnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityConnection end";
}

/**
 * @tc.name: FormAbilityConnectionReporterTest_0010
 * @tc.desc: Verify function ReportFormAbilityDisconnection.
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormAbilityConnectionReporterTest, FormAbilityConnectionReporterTest_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection begin";
    std::string bundleName = "";
    FormAbilityConnectionReporter::GetInstance().ReportFormAbilityDisconnection(bundleName);
    GTEST_LOG_(INFO) << "FormAbilityConnectionReporterTest_ReportFormAbilityDisconnection end";
}
} // namespace AppExecFwk
} // namespace OHOS
