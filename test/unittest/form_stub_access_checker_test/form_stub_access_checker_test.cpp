/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstdint>
#include <initializer_list>
#include <vector>

#include "bundle_constants.h"
#include "form_ipc_context.h"
#include "form_mgr_errors.h"
#include "form_permission_policy.h"
#include "form_stub_access_checker.h"

// Mock control functions defined in mock_tokenid_kit.cpp.
void MockIsSystemAppByFullTokenID(bool mockRet);

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

void MockIsSACall(bool mockRet);
void MockGetCallerUserId(int32_t userId);
void MockGetForegroundUsers(std::vector<int32_t> foregroundUsers);
void MockVerifyCallingPermission(bool mockRet);

namespace {

// Reset all mock controls to safe defaults before each scenario.
void ResetMocks()
{
    MockIsSACall(false);
    MockVerifyCallingPermission(true);
    MockGetCallerUserId(Constants::ANY_USERID);
    MockGetForegroundUsers({});
    MockIsSystemAppByFullTokenID(false);
}

FormPermissionPolicy MakePolicy(std::initializer_list<CheckType> steps)
{
    FormPermissionPolicy policy{};
    EXPECT_TRUE(steps.size() <= FormPermissionPolicy::MAX_CHECK_COUNT);
    size_t index = 0;
    for (CheckType step : steps) {
        policy.checks[index] = step;
        ++index;
    }
    policy.checkCount = static_cast<uint8_t>(steps.size());
    return policy;
}

FormIpcContext MakeContext()
{
    return FormIpcContext{1000, 0xdeadbeefcafe0000ULL, 42};
}

}  // namespace

class FormStubAccessCheckerTest : public ::testing::Test {
public:
    void SetUp() override
    {
        ResetMocks();
    }
};

/**
 * @tc.name: EmptyPolicyReturnsOk
 * @tc.desc: A policy with no effective check steps evaluates to ERR_OK instead of
 *           failing closed, matching the checker contract for empty policies.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, EmptyPolicyReturnsOk, TestSize.Level0)
{
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: SaBypassWithSaCallShortCircuitsLaterSteps
 * @tc.desc: When the caller is a system service, the SaBypass step passes immediately
 *           and later steps (here SystemApp, set up to deny) are never evaluated.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SaBypassWithSaCallShortCircuitsLaterSteps, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(true);
    // SystemApp stays denied; passing proves the chain was short-circuited.
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SaBypass, CheckType::SystemApp}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: SaBypassWithoutSaCallSkipsFirstStep
 * @tc.desc: Without a SA identity the SaBypass slot is skipped without denying;
 *           the next step decides, and here SystemApp passes.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SaBypassWithoutSaCallSkipsFirstStep, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SaBypass, CheckType::SystemApp}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: SaBypassWithoutSaCallDeniesOnLaterStep
 * @tc.desc: A non-SA caller skips SaBypass and is denied by the later SystemApp step
 *           with ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SaBypassWithoutSaCallDeniesOnLaterStep, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SaBypass, CheckType::SystemApp}), MakeContext()),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
}

/**
 * @tc.name: SaBypassAsOnlyStepReturnsOk
 * @tc.desc: The execution loop starts after the SaBypass slot, so a policy containing
 *           only SaBypass has no effective steps and returns ERR_OK.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SaBypassAsOnlyStepReturnsOk, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(false);
    // The loop starts after the SaBypass slot, so a lone SaBypass never denies.
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SaBypass}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: SaOnlyWithSaCallPasses
 * @tc.desc: The SaOnly step requires a SA identity; a SA caller passes the check.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SaOnlyWithSaCallPasses, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(true);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SaOnly}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: SaOnlyWithoutSaCallDenies
 * @tc.desc: The SaOnly step denies non-SA callers with the generic permission deny code.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SaOnlyWithoutSaCallDenies, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(false);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SaOnly}), MakeContext()),
        ERR_APPEXECFWK_FORM_PERMISSION_DENY);
}

/**
 * @tc.name: SystemCallerSaCallPasses
 * @tc.desc: SystemCaller is satisfied when either probe passes; a SA identity alone
 *           is sufficient for the step to pass.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SystemCallerSaCallPasses, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(true);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SystemCaller}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: SystemCallerSystemAppPasses
 * @tc.desc: Without SA identity, a full-token system app also satisfies the
 *           SystemCaller step.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SystemCallerSystemAppPasses, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SystemCaller}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: SystemCallerBothFailDenySys
 * @tc.desc: A caller that is neither a SA nor a system app is denied by SystemCaller
 *           with ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SystemCallerBothFailDenySys, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SystemCaller}), MakeContext()),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
}

/**
 * @tc.name: SystemAppPasses
 * @tc.desc: The SystemApp step passes when the full-token probe reports a system app.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SystemAppPasses, TestSize.Level0)
{
    ResetMocks();
    MockIsSystemAppByFullTokenID(true);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SystemApp}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: SystemAppFailsDenySys
 * @tc.desc: The SystemApp step denies non-system-app callers with
 *           ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, SystemAppFailsDenySys, TestSize.Level0)
{
    ResetMocks();
    MockIsSystemAppByFullTokenID(false);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::SystemApp}), MakeContext()),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
}

/**
 * @tc.name: PermissionGrantedReturnsOk
 * @tc.desc: The Permission step returns ERR_OK when VerifyCallingPermission grants the
 *           permission required by the policy.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, PermissionGrantedReturnsOk, TestSize.Level0)
{
    ResetMocks();
    MockVerifyCallingPermission(true);
    FormPermissionPolicy policy = MakePolicy({CheckType::Permission});
    policy.permName = Constants::PERMISSION_REQUIRE_FORM;
    policy.permDenyCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(policy, MakeContext()), ERR_OK);
}

/**
 * @tc.name: PermissionDeniedReturnsBakedCode
 * @tc.desc: On denial the checker returns the row's baked permDenyCode verbatim
 *           instead of substituting a generic deny code.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, PermissionDeniedReturnsBakedCode, TestSize.Level0)
{
    ResetMocks();
    MockVerifyCallingPermission(false);
    FormPermissionPolicy policy = MakePolicy({CheckType::Permission});
    policy.permName = Constants::PERMISSION_REQUIRE_FORM;
    // Explicit baked override; the assertion proves the checker returns it verbatim.
    policy.permDenyCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(policy, MakeContext()), ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE);
}

/**
 * @tc.name: CrossAccountForegroundUserPasses
 * @tc.desc: A caller on a foreground user passes CrossAccount even without the interact
 *           permission; the in-test permission denial proves the skip.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, CrossAccountForegroundUserPasses, TestSize.Level0)
{
    ResetMocks();
    MockGetCallerUserId(100);
    MockGetForegroundUsers({100});
    // Permission stays denied; passing proves foreground users skip the permission check.
    MockVerifyCallingPermission(false);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::CrossAccount}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: CrossAccountBackgroundUserWithInteractPermissionPasses
 * @tc.desc: A background-user caller holding the interact permission passes the
 *           CrossAccount step.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, CrossAccountBackgroundUserWithInteractPermissionPasses, TestSize.Level0)
{
    ResetMocks();
    MockGetCallerUserId(101);
    MockGetForegroundUsers({100});
    MockVerifyCallingPermission(true);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::CrossAccount}), MakeContext()), ERR_OK);
}

/**
 * @tc.name: CrossAccountBackgroundUserWithoutInteractPermissionDenies
 * @tc.desc: A background-user caller without the interact permission is denied with
 *           ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, CrossAccountBackgroundUserWithoutInteractPermissionDenies, TestSize.Level0)
{
    ResetMocks();
    MockGetCallerUserId(101);
    MockGetForegroundUsers({100});
    MockVerifyCallingPermission(false);
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(MakePolicy({CheckType::CrossAccount}), MakeContext()),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY);
}

/**
 * @tc.name: UnknownStepDenies
 * @tc.desc: An unrecognized CheckType value is denied with the generic permission deny
 *           code instead of being skipped.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, UnknownStepDenies, TestSize.Level0)
{
    ResetMocks();
    FormStubAccessChecker checker;
    FormPermissionPolicy policy{};
    policy.checks[0] = static_cast<CheckType>(0xFF);
    policy.checkCount = 1;
    EXPECT_EQ(checker.Check(policy, MakeContext()), ERR_APPEXECFWK_FORM_PERMISSION_DENY);
}

/**
 * @tc.name: ChainStopsAtFirstDeny
 * @tc.desc: When SystemCaller denies, the chain stops immediately; the later
 *           Permission step's baked deny code is never produced.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, ChainStopsAtFirstDeny, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(false);
    MockVerifyCallingPermission(true);
    FormPermissionPolicy policy = MakePolicy({CheckType::SystemCaller, CheckType::Permission});
    policy.permName = Constants::PERMISSION_REQUIRE_FORM;
    policy.permDenyCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    FormStubAccessChecker checker;
    // The deny comes from SystemCaller, not from the Permission step's baked code.
    EXPECT_EQ(checker.Check(policy, MakeContext()), ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS);
}

/**
 * @tc.name: FullChainPasses
 * @tc.desc: SaBypass, SystemCaller, Permission and CrossAccount steps compose: a
 *           non-SA system app with granted permission passes the whole chain.
 * @tc.type: FUNC
 */
HWTEST_F(FormStubAccessCheckerTest, FullChainPasses, TestSize.Level0)
{
    ResetMocks();
    MockIsSACall(false);
    MockIsSystemAppByFullTokenID(true);
    MockVerifyCallingPermission(true);
    MockGetCallerUserId(100);
    MockGetForegroundUsers({100});
    FormPermissionPolicy policy = MakePolicy(
        {CheckType::SaBypass, CheckType::SystemCaller, CheckType::Permission, CheckType::CrossAccount});
    policy.permName = Constants::PERMISSION_REQUIRE_FORM;
    policy.permDenyCode = ERR_APPEXECFWK_FORM_PERMISSION_DENY;
    FormStubAccessChecker checker;
    EXPECT_EQ(checker.Check(policy, MakeContext()), ERR_OK);
}

}  // namespace AppExecFwk
}  // namespace OHOS
