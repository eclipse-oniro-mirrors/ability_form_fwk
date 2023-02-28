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

#include "access_token.h"
#include "form_mgr_errors.h"
#define private public
#include "form_mgr_service.h"
#include "tokenid_kit.h"
#undef private
#include "mock_form_provider_client.h"
#include "hilog_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

extern void MockGetTokenTypeFlag(int32_t mockRet);
extern void MockGetCallingUid(int32_t mockRet);
extern void MockVerifyAccessToken(int32_t mockRet);

namespace {
const std::string NAME_FORM_MGR_SERVICE_PERMISSION_VERIFY = "FmsFormMgrServicePermissionVerifyTest";

class FmsFormMgrServicePermissionVerifyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormMgrServicePermissionVerifyTest::SetUpTestCase()
{}

void FmsFormMgrServicePermissionVerifyTest::TearDownTestCase()
{}

void FmsFormMgrServicePermissionVerifyTest::SetUp()
{}

void FmsFormMgrServicePermissionVerifyTest::TearDown()
{}

/**
 * @tc.number: FmsFormMgrServicePermissionVerifyTest_0001
 * @tc.name: test IsSACall function.
 * @tc.desc: Verify that the IsSACall interface is called normally and the return value is true.
 */
HWTEST_F(FmsFormMgrServicePermissionVerifyTest, FmsFormMgrServicePermissionVerify_0001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerify_0001 start";
    FormMgrService formMgrService;
    MockGetTokenTypeFlag(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE);
    MockGetCallingUid(0);
    EXPECT_EQ(true, formMgrService.IsSACall());
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerify_0001 end";
}

/**
 * @tc.number: FmsFormMgrServicePermissionVerifyTest_0002
 * @tc.name: test IsSACall function.
 * @tc.desc: Verify that the IsSACall interface is called normally and the return value is true.
 */
HWTEST_F(FmsFormMgrServicePermissionVerifyTest, FmsFormMgrServicePermissionVerify_0002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerify_0002 start";
    FormMgrService formMgrService;
    MockGetCallingUid(1000);
    EXPECT_EQ(true, formMgrService.IsSACall());
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerify_0002 end";
}

/**
 * @tc.number: FmsFormMgrServicePermissionVerifyTest_0003
 * @tc.name: test IsSACall function.
 * @tc.desc: Verify that the IsSACall interface is called without permission and the return value is false.
 */
HWTEST_F(FmsFormMgrServicePermissionVerifyTest, FmsFormMgrServicePermissionVerifyTest_0003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerifyTest_0003 start";
    FormMgrService formMgrService;
    MockGetTokenTypeFlag(0);
    MockGetCallingUid(0);
    EXPECT_EQ(false, formMgrService.IsSACall());
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerifyTest_0003 end";
}

/**
 * @tc.number: FmsFormMgrServicePermissionVerifyTest_0004
 * @tc.name: test VerifyCallingPermission function.
 * @tc.desc: Verify that the VerifyCallingPermission interface is called without permission and the return value is false.
 */
HWTEST_F(FmsFormMgrServicePermissionVerifyTest, FmsFormMgrServicePermissionVerifyTest_0004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerifyTest_0004 start";
    FormMgrService formMgrService;
    MockVerifyAccessToken(-1);
    EXPECT_EQ(false, formMgrService.VerifyCallingPermission("ohos.permission.REQUIRE_FORM"));
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerifyTest_0004 end";
}

/**
 * @tc.number: FmsFormMgrServicePermissionVerifyTest_0005
 * @tc.name: test VerifyCallingPermission function.
 * @tc.desc: Verify that the VerifyCallingPermission interface is called normally and the return value is true.
 */
HWTEST_F(FmsFormMgrServicePermissionVerifyTest, FmsFormMgrServicePermissionVerifyTest_0005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerifyTest_0005 start";
    FormMgrService formMgrService;
    MockVerifyAccessToken(0);
    EXPECT_EQ(true, formMgrService.VerifyCallingPermission("ohos.permission.REQUIRE_FORM"));
    GTEST_LOG_(INFO) << "FmsFormMgrServicePermissionVerifyTest_0005 end";
}
}