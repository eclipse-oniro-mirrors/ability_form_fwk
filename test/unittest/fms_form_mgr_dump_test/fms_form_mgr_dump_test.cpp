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

#include "form_ams_helper.h"
#include "form_bms_helper.h"
#define private public
#include "form_mgr_service.h"
#undef private
#include "if_system_ability_manager.h"
#include "mock_ability_manager.h"
#include "mock_bundle_manager.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
class FmsFormMgrDumpTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    void CreateProviderData();
protected:
    std::shared_ptr<FormMgrService> formyMgrServ_ = DelayedSingleton<FormMgrService>::GetInstance();
};

void FmsFormMgrDumpTest::SetUpTestCase()
{
    FormBmsHelper::GetInstance().SetBundleManager(new BundleMgrService());
}

void FmsFormMgrDumpTest::TearDownTestCase()
{}

void FmsFormMgrDumpTest::SetUp()
{
    formyMgrServ_->OnStart();
}

void FmsFormMgrDumpTest::TearDown()
{
    formyMgrServ_->OnStop();
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump with no args works.
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_001, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_001 start";

    std::vector<std::u16string> args = {};
    std::string result;
    formyMgrServ_->Dump(args, result);
    EXPECT_NE(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_001 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump help works.
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_002, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_002 start";

    std::vector<std::u16string> args = {u"-h"};
    std::string result;
    formyMgrServ_->Dump(args, result);
    EXPECT_NE(result.find("options list:"), string::npos);

    args[0] = u"--help";
    formyMgrServ_->Dump(args, result);
    EXPECT_NE(result.find("options list:"), string::npos);

    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_002 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump storage works.
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_003, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_003 start";

    std::vector<std::u16string> args = {u"-s"};
    std::string result;
    formyMgrServ_->Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    args[0] = u"--storage";
    formyMgrServ_->Dump(args, result);
    EXPECT_EQ(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_003 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump by bundle name works.
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_004, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_004 start";

    std::vector<std::u16string> args = {u"-n"};
    std::string result;
    formyMgrServ_->Dump(args, result);
    EXPECT_NE(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_004 end";
}

/*
 * Feature: FormMgrService
 * Function: FormMgr
 * SubFunction: Dump Function
 * FunctionPoints: FormMgr Dump interface
 * EnvConditions: Mobile that can run ohos test framework
 * CaseDescription: Verify if FormMgr invoke dump by form id works.
 */
HWTEST_F(FmsFormMgrDumpTest, Dump_005, TestSize.Level0)
{
    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_005 start";

    std::vector<std::u16string> args = {u"-i"};
    std::string result;
    formyMgrServ_->Dump(args, result);
    EXPECT_NE(result.find("error"), string::npos);

    GTEST_LOG_(INFO) << "fms_form_mgr_dump_test_005 end";
}
}