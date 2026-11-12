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
#include <array>
#include <cstdint>
#include <set>
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

// 11 reserved Message enum names from design doc 1.5.2.
constexpr std::array<uint32_t, 11> kReservedCodes = {{
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ADD_FORM_INFO),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_ADD_FORM_OHOS),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_BATCH_ADD_FORM_RECORDS_ST),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CHECK_AND_DELETE_INVALID_FORMS),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CLEAR_FORM_RECORDS_ST),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DISTRIBUTED_DATA_ADD_FORM__ST),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_DISTRIBUTED_DATA_DELETE_FORM__ST),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_EVENT_NOTIFY),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELEASE_CACHED_FORM),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REMOVE_FORM_INFO),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_ROUTER_ACTION),
}};

// 20 B-1 union B-2 method codes (design doc appendix B-1 and B-2).
constexpr std::array<uint32_t, 20> kEmptyPolicyCodes = {{
    // B-1 (17 methods)
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_IS_SYSTEM_APP_FORM),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_FORM),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_FORM_PROVIDER_INFO),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_SET_NEXT_REFRESH_TIME),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORMS_INFO),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFO_BY_ID),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_PUBLISHED_FORM_INFOS),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_ABILITY_BY_FMS),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_START_UI_ABILITY_BY_FMS),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UPDATE_PROXY_FORM),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_WITH_SNAPSHOT),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_OPEN_FORM_EDIT_ABILITY),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_CLOSE_FORM_EDIT_ABILITY),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_OVERFLOW),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_FORM_RECT),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELOAD_FORMS),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_RELOAD_ALL_FORMS),
    // B-2 (3 methods)
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REGISTER_PUBLISH_FORM_INTERCEPTOR),
    static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_UNREGISTER_PUBLISH_FORM_INTERCEPTOR),
}};

}  // namespace

class FormIpcDispatchTableTest : public ::testing::Test {};

HWTEST_F(FormIpcDispatchTableTest, TableSizeIs123, TestSize.Level0)
{
    const auto &table = FormIpcDispatchTable::GetInstance();
    const HandlerEntry *entries = table.GetEntries();
    size_t count = 0;
    for (size_t i = 0; i < table.GetEntryCount(); ++i) {
        (void)entries[i];
        ++count;
    }
    EXPECT_EQ(count, 123u);
}

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

HWTEST_F(FormIpcDispatchTableTest, FindHitsSameRowAndNullForReserved, TestSize.Level0)
{
    const auto &table = FormIpcDispatchTable::GetInstance();
    const HandlerEntry *entries = table.GetEntries();
    const size_t entryCount = table.GetEntryCount();
    // Every entry is findable and yields the same (code, handler).
    for (size_t i = 0; i < entryCount; ++i) {
        const HandlerEntry &e = entries[i];
        const HandlerEntry *found = table.Find(static_cast<uint32_t>(e.code));
        ASSERT_NE(found, nullptr) << "Find returned null for code " << static_cast<uint32_t>(e.code);
        EXPECT_EQ(found->code, e.code);
        EXPECT_EQ(found->handler, e.handler);
    }
    // All 11 reserved enum values return nullptr.
    for (uint32_t code : kReservedCodes) {
        EXPECT_EQ(table.Find(code), nullptr) << "Find should miss for reserved code " << code;
    }
}

HWTEST_F(FormIpcDispatchTableTest, EmptyPolicySubsetB1UnionB2, TestSize.Level0)
{
    const auto &table = FormIpcDispatchTable::GetInstance();
    for (uint32_t code : kEmptyPolicyCodes) {
        const HandlerEntry *found = table.Find(code);
        ASSERT_NE(found, nullptr) << "Missing B-1/B-2 code " << code;
        EXPECT_EQ(found->policy.checkCount, 0) << "B-1/B-2 code " << code
                                               << " should have empty policy";
    }
}

HWTEST_F(FormIpcDispatchTableTest, GetAccessCheckerNonNullDefaultFailClosed, TestSize.Level0)
{
    const auto &table = FormIpcDispatchTable::GetInstance();
    auto defaultChecker = table.GetAccessChecker();
    ASSERT_NE(defaultChecker, nullptr);
    FormPermissionPolicy emptyPolicy{};
    FormIpcContext context{1000, 0xdeadbeefcafe0000ULL, 42};
    EXPECT_EQ(defaultChecker->Check(emptyPolicy, context), ERR_APPEXECFWK_FORM_PERMISSION_DENY);
}

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

// Assertion 1 (value domain reconciliation): every Message enum name is
// either registered (123) or reserved (11).
HWTEST_F(FormIpcDispatchTableTest, Assertion1_DomainReconciliation134, TestSize.Level0)
{
    const auto &table = FormIpcDispatchTable::GetInstance();
    const HandlerEntry *entries = table.GetEntries();
    std::set<uint32_t> registeredCodes;
    for (size_t i = 0; i < table.GetEntryCount(); ++i) {
        registeredCodes.insert(static_cast<uint32_t>(entries[i].code));
    }
    EXPECT_EQ(registeredCodes.size(), 123u);

    // Reserved codes must NOT overlap with registered.
    for (uint32_t code : kReservedCodes) {
        EXPECT_EQ(registeredCodes.count(code), 0u)
            << "Reserved code " << code << " unexpectedly registered";
    }

    std::set<uint32_t> reservedSet(kReservedCodes.begin(), kReservedCodes.end());
    for (uint32_t code : registeredCodes) {
        EXPECT_EQ(reservedSet.count(code), 0u)
            << "Registered code " << code << " is in reserved set";
    }

    std::set<uint32_t> allCodes = registeredCodes;
    allCodes.insert(kReservedCodes.begin(), kReservedCodes.end());
    EXPECT_EQ(allCodes.size(), 134u);
}

// Assertion 4 (code-handler completeness).
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

// Assertion 5-g (baked): permDenyCode carries the final baked deny value for every
// row: non-zero exactly when the row has a Permission step, and only the two
// agent rows keep the DENY_AGENT_REQUIRE_FORM override.
HWTEST_F(FormIpcDispatchTableTest, Assertion5g_PermDenyOverrideExactlyTwo, TestSize.Level0)
{
    const auto &table = FormIpcDispatchTable::GetInstance();
    const HandlerEntry *entries = table.GetEntries();
    std::vector<uint32_t> agentOverrideCodes;
    for (size_t i = 0; i < table.GetEntryCount(); ++i) {
        const HandlerEntry &e = entries[i];
        bool hasPermissionStep = false;
        for (uint8_t j = 0; j < e.policy.checkCount; ++j) {
            if (e.policy.checks[j] == CheckType::Permission) {
                hasPermissionStep = true;
                break;
            }
        }
        if (hasPermissionStep) {
            EXPECT_NE(e.policy.permDenyCode, 0)
                << "Permission row " << static_cast<uint32_t>(e.code) << " must carry a baked permDenyCode";
        } else {
            EXPECT_EQ(e.policy.permDenyCode, 0)
                << "Non-Permission row " << static_cast<uint32_t>(e.code) << " must keep permDenyCode zero";
        }
        if (e.policy.permDenyCode == ERR_APPEXECFWK_FORM_PERMISSION_DENY_AGENT_REQUIRE_FORM) {
            agentOverrideCodes.push_back(static_cast<uint32_t>(e.code));
        }
    }
    ASSERT_EQ(agentOverrideCodes.size(), 2u)
        << "Exactly 2 agent permDenyCode overrides expected, found "
        << agentOverrideCodes.size();
    std::set<uint32_t> expectedCodes = {
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_GET_AVAILABLE_FORM_HOST_SERVICES),
        static_cast<uint32_t>(IFormMgr::Message::FORM_MGR_REQUEST_PUBLISH_FORM_CROSS_DEVICE),
    };
    std::set<uint32_t> actualCodes(agentOverrideCodes.begin(), agentOverrideCodes.end());
    EXPECT_EQ(actualCodes, expectedCodes);
}

// Chain shape tally.
HWTEST_F(FormIpcDispatchTableTest, ShapeTallyMatchesDesignDoc, TestSize.Level0)
{
    const auto &table = FormIpcDispatchTable::GetInstance();
    const HandlerEntry *entries = table.GetEntries();
    size_t chainRows = 0;
    size_t emptyRows = 0;
    size_t saBypassRows = 0;
    size_t saOnlyRows = 0;
    size_t permRows = 0;
    size_t crossRows = 0;

    for (size_t row = 0; row < table.GetEntryCount(); ++row) {
        const HandlerEntry &e = entries[row];
        if (e.policy.checkCount == 0) {
            ++emptyRows;
        } else {
            ++chainRows;
        }
        for (uint8_t i = 0; i < e.policy.checkCount; ++i) {
            if (e.policy.checks[i] == CheckType::SaBypass) ++saBypassRows;
            if (e.policy.checks[i] == CheckType::SaOnly) ++saOnlyRows;
            if (e.policy.checks[i] == CheckType::Permission) ++permRows;
            if (e.policy.checks[i] == CheckType::CrossAccount) ++crossRows;
        }
    }

    EXPECT_EQ(chainRows, 103u) << "chain-shaped rows";
    EXPECT_EQ(emptyRows, 20u) << "empty-policy rows (B-1 + B-2)";
    EXPECT_EQ(chainRows + emptyRows, 123u);
    EXPECT_EQ(saBypassRows, 48u) << "SaBypass rows (shape-1 dispatch entries)";
    EXPECT_EQ(saOnlyRows, 2u) << "SaOnly rows (SA-guarded messages moved onto the table)";
}

}  // namespace AppExecFwk
}  // namespace OHOS
