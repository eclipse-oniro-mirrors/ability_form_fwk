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

#include <algorithm>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "form_ipc_context.h"
#include "form_ipc_dispatch_table.h"
#include "form_mgr_interface.h"
#include "form_permission_policy.h"
#include "form_stub_access_checker.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {

// Fake checker that records invocations.
class RecordingChecker : public IStubAccessChecker {
public:
    ErrCode Check(const FormPermissionPolicy &policy, const FormIpcContext &context) override
    {
        calls++;
        lastPolicy = policy;
        lastContext = context;
        return denyResult;
    }
    size_t calls = 0;
    FormPermissionPolicy lastPolicy{};
    FormIpcContext lastContext{};
    ErrCode denyResult = ERR_OK;
};

}  // namespace

class FormIpcDispatchTableTest : public ::testing::Test {};

/**
 * @tc.name: AllCodesUniqueSortedViewStrictlyAscendingPermutation
 * @tc.desc: Every registered code resolves via Find to its own row, and the collected
 *           codes are strictly ascending and form a permutation of the source entries.
 * @tc.type: FUNC
 */
HWTEST_F(FormIpcDispatchTableTest, AllCodesUniqueSortedViewStrictlyAscendingPermutation, TestSize.Level0)
{
    const HandlerEntry *entries = FormIpcDispatchTable::GetInstance().GetEntries();
    const size_t entryCount = FormIpcDispatchTable::GetInstance().GetEntryCount();
    std::vector<uint32_t> sorted;
    sorted.reserve(entryCount);
    // Collect Find results in source order; Find returns sorted-view lookup.
    for (size_t i = 0; i < entryCount; ++i) {
        const HandlerEntry &e = entries[i];
        const HandlerEntry *found = FormIpcDispatchTable::GetInstance().Find(static_cast<uint32_t>(e.code));
        ASSERT_NE(found, nullptr);
        sorted.push_back(static_cast<uint32_t>(found->code));
    }
    ASSERT_EQ(sorted.size(), entryCount);
    std::sort(sorted.begin(), sorted.end());
    // Strictly ascending.
    for (size_t i = 1; i < sorted.size(); ++i) {
        EXPECT_LT(sorted[i - 1], sorted[i]) << "at index " << i;
    }
    // SortedView is a permutation of entries.
    std::vector<uint32_t> source;
    source.reserve(entryCount);
    for (size_t i = 0; i < entryCount; ++i) {
        source.push_back(static_cast<uint32_t>(entries[i].code));
    }
    std::sort(source.begin(), source.end());
    EXPECT_EQ(sorted, source);
}

/**
 * @tc.name: GetAccessCheckerNonNullDefaultFailClosed
 * @tc.desc: The table installs a non-null default checker before SetAccessChecker runs;
 *           an empty policy is denied with ERR_APPEXECFWK_FORM_PERMISSION_DENY.
 * @tc.type: FUNC
 */
HWTEST_F(FormIpcDispatchTableTest, GetAccessCheckerNonNullDefaultFailClosed, TestSize.Level0)
{
    const auto &table = FormIpcDispatchTable::GetInstance();
    auto defaultChecker = table.GetAccessChecker();
    ASSERT_NE(defaultChecker, nullptr);
    FormPermissionPolicy emptyPolicy{};
    FormIpcContext context{1000, 0xdeadbeefcafe0000ULL, 42};
    EXPECT_EQ(defaultChecker->Check(emptyPolicy, context), ERR_APPEXECFWK_FORM_PERMISSION_DENY);
}

/**
 * @tc.name: SetAccessCheckerInjectsAndObserved
 * @tc.desc: An injected checker is observed by GetAccessChecker and receives the exact
 *           policy and context passed to Check.
 * @tc.type: FUNC
 */
HWTEST_F(FormIpcDispatchTableTest, SetAccessCheckerInjectsAndObserved, TestSize.Level0)
{
    auto &table = FormIpcDispatchTable::GetInstance();
    auto original = table.GetAccessChecker();
    ASSERT_NE(original, nullptr);
    auto fake = std::make_shared<RecordingChecker>();
    table.SetAccessChecker(fake);
    EXPECT_EQ(table.GetAccessChecker().get(), fake.get());
    FormPermissionPolicy p{};
    FormIpcContext context{1, 2, 3};
    EXPECT_EQ(table.GetAccessChecker()->Check(p, context), ERR_OK);
    EXPECT_EQ(fake->calls, 1u);
    EXPECT_EQ(fake->lastContext.callingUid, 1);
    EXPECT_EQ(fake->lastContext.callingTokenId, 2u);
    EXPECT_EQ(fake->lastContext.callingPid, 3);
    EXPECT_EQ(fake->lastPolicy.checkCount, 0);
    // Restore original so later tests see the default fail-closed checker.
    table.SetAccessChecker(original);
}

/**
 * @tc.name: GetDefaultDenyCodeMappings
 * @tc.desc: Known permission names map to their dedicated deny codes; unknown
 *           permission names fall back to the common deny code.
 * @tc.type: FUNC
 */
HWTEST_F(FormIpcDispatchTableTest, GetDefaultDenyCodeMappings, TestSize.Level0)
{
    EXPECT_EQ(GetDefaultDenyCode(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE);
    EXPECT_EQ(GetDefaultDenyCode(Constants::PERMISSION_FORM_CUSTOM_CONFIG),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_CUSTOM_CONFIG);
    EXPECT_EQ(GetDefaultDenyCode(Constants::PERMISSION_UPDATE_FORM_CROSS_BUNDLE),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY_UPDATE_FORM_CROSS_BUNDLE);
    EXPECT_EQ(GetDefaultDenyCode(Constants::PERMISSION_REQUIRE_FORM),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    EXPECT_EQ(GetDefaultDenyCode(Constants::PERMISSION_AGENT_REQUIRE_FORM),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY);
    EXPECT_EQ(GetDefaultDenyCode("ohos.permission.SOMETHING_ELSE"),
              ERR_APPEXECFWK_FORM_PERMISSION_DENY);
}

/**
 * @tc.name: Assertion4_CodeHandlerPairsComplete
 * @tc.desc: Every row carries a non-null handler and Find resolves each registered
 *           code back to the same row (code, handler, checkCount).
 * @tc.type: FUNC
 */
HWTEST_F(FormIpcDispatchTableTest, Assertion4_CodeHandlerPairsComplete, TestSize.Level0)
{
    const auto &table = FormIpcDispatchTable::GetInstance();
    const HandlerEntry *entries = table.GetEntries();
    for (size_t i = 0; i < table.GetEntryCount(); ++i) {
        const HandlerEntry &e = entries[i];
        EXPECT_NE(e.handler, nullptr) << "Null handler for code " << static_cast<uint32_t>(e.code);
        const HandlerEntry *found = table.Find(static_cast<uint32_t>(e.code));
        ASSERT_NE(found, nullptr) << "Find miss for code " << static_cast<uint32_t>(e.code);
        EXPECT_EQ(found->code, e.code);
        EXPECT_EQ(found->handler, e.handler);
        EXPECT_EQ(found->policy.checkCount, e.policy.checkCount);
    }
}

}  // namespace AppExecFwk
}  // namespace OHOS
