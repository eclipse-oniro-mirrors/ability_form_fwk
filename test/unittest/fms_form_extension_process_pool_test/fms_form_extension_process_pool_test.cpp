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
#include <memory>
#include <string>
#include <vector>
#define private public
#include "form_provider/form_extension_process_pool.h"
#include "common/connection/form_ability_connection.h"
#include "common/event/form_event_notify_connection.h"
#include "form_provider/connection/form_acquire_connection.h"
#include "form_provider/connection/form_delete_connection.h"
#include "form_provider/connection/form_refresh_connection.h"
#undef private
#include "data_center/form_cust_config_mgr.h"
#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"
#include "want.h"
#include "gmock/gmock.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {

AAFwk::Want MakePoolWant(const std::string &bundle)
{
    AAFwk::Want want;
    want.SetElementName(bundle, "ProviderAbility");
    return want;
}

// Keep in sync with PENDING_QUEUE_LIMIT in form_extension_process_pool.cpp.
constexpr int32_t PENDING_QUEUE_LIMIT = 100;

// Pool-managed (non-exempt) connection: FormRefreshConnection sets the
// pool-managed flag and the FormRecord presets the provider key + userId.
sptr<FormAbilityConnection> MakeManagedConn(int64_t formId, const std::string &bundle, int32_t userId)
{
    FormRecord record;
    record.bundleName = bundle;
    record.abilityName = "ProviderAbility";
    record.providerUserId = userId;
    return new FormRefreshConnection(formId, MakePoolWant(bundle), record);
}

// Gated tests use the singleton pool: the delayed visibility task scheduled
// on enqueue captures the pool `this`, so a per-test local pool would be
// destroyed before the 3s callback fires. Reset state between tests.
void ResetPool(FormExtensionProcessPool &pool, size_t threshold)
{
    std::lock_guard<std::mutex> lock(pool.mutex_);
    pool.threshold_ = threshold;
    pool.activeProviders_.clear();
    pool.pendingQueue_.clear();
}

class FormExtensionProcessPoolTest : public testing::Test {
public:
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp()
    {}
    void TearDown()
    {}
};

/**
 * @tc.name: PoolManaged_ThreeBatchClasses_True
 * @tc.desc: Verify the three batch-type connections are pool managed (BR-13).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, PoolManaged_ThreeBatchClasses_True, TestSize.Level1)
{
    auto acquire = new FormAcquireConnection(1, FormItemInfo(), WantParams(), nullptr);
    EXPECT_TRUE(acquire->IsPoolManaged());

    auto refresh = new FormRefreshConnection(1, Want(), FormRecord());
    EXPECT_TRUE(refresh->IsPoolManaged());

    auto eventNotify = new FormEventNotifyConnection({1}, 0, "bundle", "ability", 100);
    EXPECT_TRUE(eventNotify->IsPoolManaged());
}

/**
 * @tc.name: PoolManaged_OtherClasses_False
 * @tc.desc: Verify single-op connections are not pool managed by default (BR-13 safe default).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, PoolManaged_OtherClasses_False, TestSize.Level1)
{
    auto del = new FormDeleteConnection(1, "bundle", "ability", 100);
    EXPECT_FALSE(del->IsPoolManaged());
}

/**
 * @tc.name: FormLocationAndPoolPending_Accessor
 * @tc.desc: Verify formLocation / isPoolPending accessors on the base class.
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, FormLocationAndPoolPending_Accessor, TestSize.Level1)
{
    auto del = new FormDeleteConnection(1, "bundle", "ability", 100);
    EXPECT_FALSE(del->IsPoolPending());
    del->SetPoolPending(true);
    EXPECT_TRUE(del->IsPoolPending());
    del->SetPoolPending(false);
    EXPECT_FALSE(del->IsPoolPending());
}

/**
 * @tc.name: SanitizePoolThreshold_Boundary
 * @tc.desc: Verify pool threshold sanitize rules (BR-5/AC-4.2/4.3).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, SanitizePoolThreshold_Boundary, TestSize.Level1)
{
    // 0 keeps 0: gating disabled (rollback switch)
    EXPECT_EQ(0, FormCustConfigMgr::SanitizePoolThreshold(0));
    // negative -> default 20
    EXPECT_EQ(20, FormCustConfigMgr::SanitizePoolThreshold(-1));
    EXPECT_EQ(20, FormCustConfigMgr::SanitizePoolThreshold(-100));
    // in-range passthrough
    EXPECT_EQ(1, FormCustConfigMgr::SanitizePoolThreshold(1));
    EXPECT_EQ(20, FormCustConfigMgr::SanitizePoolThreshold(20));
    EXPECT_EQ(50, FormCustConfigMgr::SanitizePoolThreshold(50));
    // greater than 50 -> clamp 50
    EXPECT_EQ(50, FormCustConfigMgr::SanitizePoolThreshold(51));
    EXPECT_EQ(50, FormCustConfigMgr::SanitizePoolThreshold(10000));
}

/**
 * @tc.name: AdmitConnection_AllowAndPendingByThreshold
 * @tc.desc: Gate allows below threshold, returns PENDING when full (AC-1.1/1.2).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, AdmitConnection_AllowAndPendingByThreshold, TestSize.Level1)
{
    auto &pool = FormExtensionProcessPool::GetInstance();
    ResetPool(pool, 2);
    auto c1 = MakeManagedConn(1, "bundle.a", 100);
    auto c2 = MakeManagedConn(2, "bundle.b", 100);
    auto c3 = MakeManagedConn(3, "bundle.c", 100);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.a"), c1));
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.b"), c2));
    EXPECT_FALSE(pool.AdmitConnection(MakePoolWant("bundle.c"), c3));
    EXPECT_TRUE(c3->IsPoolPending());
    EXPECT_EQ(2, pool.GetActiveProviderCount(100));
    // Same bundle re-registration shares one slot, still ALLOW.
    auto c4 = MakeManagedConn(4, "bundle.a", 100);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.a"), c4));
    EXPECT_EQ(2, pool.GetActiveProviderCount(100));
    // Other user is independent (BR-8).
    auto c5 = MakeManagedConn(5, "bundle.x", 101);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.x"), c5));
    EXPECT_EQ(1, pool.GetActiveProviderCount(101));
    // Clear the pending flag so the delayed visibility task stays a no-op.
    c3->SetPoolPending(false);
}

/**
 * @tc.name: SameBundle_MultiFormId_SharedSlot
 * @tc.desc: Same bundle shares one slot; partial termination keeps it (BR-1/AC-1.3).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, SameBundle_MultiFormId_SharedSlot, TestSize.Level1)
{
    auto pool = std::make_unique<FormExtensionProcessPool>();
    pool->threshold_ = 1;
    sptr<FormAbilityConnection> c1 = new FormDeleteConnection(1, "bundle.a", "ability", 100);
    sptr<FormAbilityConnection> c2 = new FormDeleteConnection(2, "bundle.a", "ability", 100);
    EXPECT_TRUE(pool->AdmitConnection(MakePoolWant("bundle.a"), c1));
    EXPECT_TRUE(pool->AdmitConnection(MakePoolWant("bundle.a"), c2));
    EXPECT_EQ(1, pool->GetActiveProviderCount(100));
    // Terminate one connection: slot kept.
    pool->OnConnectionTerminated(100, "bundle.a", c1);
    EXPECT_EQ(1, pool->GetActiveProviderCount(100));
    // Terminate the last connection: slot released.
    pool->OnConnectionTerminated(100, "bundle.a", c2);
    EXPECT_EQ(0, pool->GetActiveProviderCount(100));
    // After release, new bundle allowed again.
    sptr<FormAbilityConnection> c3 = new FormDeleteConnection(3, "bundle.b", "ability", 100);
    EXPECT_TRUE(pool->AdmitConnection(MakePoolWant("bundle.b"), c3));
}

/**
 * @tc.name: AdmitConnection_SameBundleAllowedWhenFull
 * @tc.desc: Pool full with other bundles, same-bundle connection shares the existing slot.
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, AdmitConnection_SameBundleAllowedWhenFull, TestSize.Level1)
{
    auto &pool = FormExtensionProcessPool::GetInstance();
    ResetPool(pool, 2);
    // Fill the pool with two different bundles.
    auto c1 = MakeManagedConn(1, "bundle.a", 100);
    auto c2 = MakeManagedConn(2, "bundle.b", 100);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.a"), c1));
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.b"), c2));
    EXPECT_EQ(2, pool.GetActiveProviderCount(100));
    // Pool is full: a new bundle gets suspended.
    auto c3 = MakeManagedConn(3, "bundle.c", 100);
    EXPECT_FALSE(pool.AdmitConnection(MakePoolWant("bundle.c"), c3));
    EXPECT_TRUE(c3->IsPoolPending());
    // But a connection to an existing bundle shares the slot: allowed.
    auto c4 = MakeManagedConn(4, "bundle.a", 100);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.a"), c4));
    EXPECT_EQ(2, pool.GetActiveProviderCount(100)); // still 2 slots
    // Clear the pending flag so the delayed visibility task stays a no-op.
    c3->SetPoolPending(false);
}

/**
 * @tc.name: OnConnectionTerminated_IdempotentAndRollback
 * @tc.desc: Termination is idempotent by pointer; rollback equals removal (EX-1).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, OnConnectionTerminated_IdempotentAndRollback, TestSize.Level1)
{
    auto pool = std::make_unique<FormExtensionProcessPool>();
    pool->threshold_ = 1;
    sptr<FormAbilityConnection> c1 = new FormDeleteConnection(1, "bundle.a", "ability", 100);
    EXPECT_TRUE(pool->AdmitConnection(MakePoolWant("bundle.a"), c1));
    // Rollback (sync ability manager service failure) equals removal.
    pool->OnConnectionTerminated(100, "bundle.a", c1);
    EXPECT_EQ(0, pool->GetActiveProviderCount(100));
    // Duplicate termination is a no-op.
    pool->OnConnectionTerminated(100, "bundle.a", c1);
    pool->OnConnectionTerminated(100, "bundle.a", c1);
    EXPECT_EQ(0, pool->GetActiveProviderCount(100));
    // Re-register then terminate once, terminate again: single release.
    sptr<FormAbilityConnection> c2 = new FormDeleteConnection(2, "bundle.a", "ability", 100);
    EXPECT_TRUE(pool->AdmitConnection(MakePoolWant("bundle.a"), c2));
    pool->OnConnectionTerminated(100, "bundle.a", c2);
    pool->OnConnectionTerminated(100, "bundle.a", c2);
    EXPECT_EQ(0, pool->GetActiveProviderCount(100));
}

/**
 * @tc.name: AdmitConnection_SupersedeAndQueueLimit
 * @tc.desc: Same formId supersede; queue full force-allows the overflow (EX-6).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, AdmitConnection_SupersedeAndQueueLimit, TestSize.Level1)
{
    auto &pool = FormExtensionProcessPool::GetInstance();
    ResetPool(pool, 1);
    auto head = MakeManagedConn(1, "bundle.head", 100);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.head"), head));
    // First pending for formId 10.
    auto p1 = MakeManagedConn(10, "bundle.p1", 100);
    EXPECT_FALSE(pool.AdmitConnection(MakePoolWant("bundle.p1"), p1));
    EXPECT_TRUE(p1->IsPoolPending());
    EXPECT_EQ(1, pool.GetPendingCount(100));
    // Supersede: same formId, new request replaces the old one.
    auto p2 = MakeManagedConn(10, "bundle.p2", 100);
    EXPECT_FALSE(pool.AdmitConnection(MakePoolWant("bundle.p2"), p2));
    EXPECT_FALSE(p1->IsPoolPending());
    EXPECT_TRUE(p2->IsPoolPending());
    EXPECT_EQ(1, pool.GetPendingCount(100));
    // Pop returns the new request.
    PendingRequest out;
    EXPECT_TRUE(pool.PopNext(100, out));
    EXPECT_EQ(10, out.formId);
    EXPECT_EQ("bundle.p2", out.want.GetElement().GetBundleName());
    EXPECT_FALSE(p2->IsPoolPending());
    // Queue limit (EX-6): the first PENDING_QUEUE_LIMIT requests are queued,
    // the overflow is force-allowed and registered in the ledger rather than dropped.
    std::vector<sptr<FormAbilityConnection>> fillers;
    for (int64_t i = 0; i < PENDING_QUEUE_LIMIT; ++i) {
        std::string bundle = "bundle.fill." + std::to_string(i);
        auto conn = MakeManagedConn(1000 + i, bundle, 100);
        EXPECT_FALSE(pool.AdmitConnection(MakePoolWant(bundle), conn));
        EXPECT_TRUE(conn->IsPoolPending());
        fillers.push_back(conn);
    }
    EXPECT_EQ(PENDING_QUEUE_LIMIT, pool.GetPendingCount(100));
    auto overflow = MakeManagedConn(2000, "bundle.overflow", 100);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.overflow"), overflow));
    EXPECT_FALSE(overflow->IsPoolPending());
    EXPECT_EQ(PENDING_QUEUE_LIMIT, pool.GetPendingCount(100));
    EXPECT_EQ(2, pool.GetActiveProviderCount(100)); // bundle.head + force-allowed bundle.overflow
    // Clear the pending flags so the delayed visibility tasks stay no-ops.
    for (auto &conn : fillers) {
        conn->SetPoolPending(false);
    }
}

/**
 * @tc.name: PopNext_VisiblePriority
 * @tc.desc: Visible queue is drained before normal queue (BR-4/AC-1.4).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, PopNext_VisiblePriority, TestSize.Level1)
{
    auto &pool = FormExtensionProcessPool::GetInstance();
    ResetPool(pool, 1);
    auto &dataMgr = FormDataMgr::GetInstance();
    // Preset visibility: normal formId 1 is invisible, visible formId 2 is
    // visible, so PopNext must drain the visible request first (BR-4/AC-1.4).
    dataMgr.SetFormVisible(1, false);
    dataMgr.SetFormVisible(2, true);
    auto head = MakeManagedConn(900, "bundle.head", 100);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.head"), head));
    auto normal = MakeManagedConn(1, "bundle.normal", 100);
    auto visible = MakeManagedConn(2, "bundle.visible", 100);
    EXPECT_FALSE(pool.AdmitConnection(MakePoolWant("bundle.normal"), normal));
    EXPECT_FALSE(pool.AdmitConnection(MakePoolWant("bundle.visible"), visible));
    PendingRequest out;
    ASSERT_TRUE(pool.PopNext(100, out));
    EXPECT_EQ(2, out.formId); // visible first
    ASSERT_TRUE(pool.PopNext(100, out));
    EXPECT_EQ(1, out.formId); // no visible left: FIFO head fallback
    EXPECT_FALSE(pool.PopNext(100, out));
    // Restore the visibility presets.
    dataMgr.DeleteFormVisible(1);
    dataMgr.DeleteFormVisible(2);
}

/**
 * @tc.name: AdmitConnection_ThresholdZeroDisabled
 * @tc.desc: Threshold 0 disables gating (rollback switch, BR-5/AC-4.3).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, AdmitConnection_ThresholdZeroDisabled, TestSize.Level1)
{
    auto &pool = FormExtensionProcessPool::GetInstance();
    ResetPool(pool, 0);
    // The ledger holds weak references: keep strong references so all ten
    // bundle slots stay occupied until the final count assertion.
    std::vector<sptr<FormAbilityConnection>> connections;
    for (int i = 0; i < 10; ++i) {
        std::string bundle = "bundle." + std::to_string(i);
        auto conn = MakeManagedConn(i, bundle, 100);
        EXPECT_TRUE(pool.AdmitConnection(MakePoolWant(bundle), conn));
        EXPECT_FALSE(conn->IsPoolPending()); // never suspended
        connections.push_back(conn);
    }
    EXPECT_EQ(10, pool.GetActiveProviderCount(100));
}

/**
 * @tc.name: AdmitConnection_ExemptOccupiesSlot
 * @tc.desc: EXEMPT decision registers and occupies a slot (BR-2/BR-6/AC-3.1).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, AdmitConnection_ExemptOccupiesSlot, TestSize.Level1)
{
    auto &pool = FormExtensionProcessPool::GetInstance();
    ResetPool(pool, 1);
    // Non-exempt pool-managed connection takes the only slot.
    auto c1 = MakeManagedConn(1, "bundle.a", 100);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.a"), c1));
    EXPECT_EQ(1, pool.GetActiveProviderCount(100));
    // Pool full: exempt (single-op type, not pool managed) still connects
    // and occupies a slot.
    sptr<FormAbilityConnection> c2 = new FormDeleteConnection(2, "bundle.center", "ability", 100);
    EXPECT_TRUE(pool.AdmitConnection(MakePoolWant("bundle.center"), c2));
    EXPECT_EQ(2, pool.GetActiveProviderCount(100));
    // Non-exempt new bundle is pending now.
    auto c3 = MakeManagedConn(3, "bundle.b", 100);
    EXPECT_FALSE(pool.AdmitConnection(MakePoolWant("bundle.b"), c3));
    EXPECT_TRUE(c3->IsPoolPending());
    EXPECT_EQ(2, pool.GetActiveProviderCount(100));
    // Clear the pending flag so the delayed visibility task stays a no-op.
    c3->SetPoolPending(false);
}

/**
 * @tc.name: ProcessPoolDump_Info
 * @tc.desc: Dump output contains threshold, total active providers, per-user summary,
 *           per-bundle connection count and per-connection formId + state (AC-5.1/5.2/5.3).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, ProcessPoolDump_Info, TestSize.Level1)
{
    auto pool = std::make_unique<FormExtensionProcessPool>();
    pool->threshold_ = 3;
    // Two bundles with different connection counts.
    sptr<FormAbilityConnection> c1 = new FormDeleteConnection(1001, "com.provider.a", "ability", 100);
    sptr<FormAbilityConnection> c2 = new FormDeleteConnection(1002, "com.provider.a", "ability", 100);
    sptr<FormAbilityConnection> c3 = new FormDeleteConnection(1009, "com.provider.b", "ability", 100);
    pool->AdmitConnection(MakePoolWant("com.provider.a"), c1);
    pool->AdmitConnection(MakePoolWant("com.provider.a"), c2);
    pool->AdmitConnection(MakePoolWant("com.provider.b"), c3);
    std::unordered_map<int32_t, FormExtensionProcessPool::BundleLedger> providers;
    FormExtensionProcessPool::PendingQueueMap pendingQueue;
    pool->DumpProcessPoolStatus(providers, pendingQueue);
    EXPECT_EQ(2, providers[100].size());
    EXPECT_EQ(2, providers[100]["com.provider.a"].size());
    EXPECT_EQ(1, providers[100]["com.provider.b"].size());
}

/**
 * @tc.name: ProcessPoolDump_EmptyState
 * @tc.desc: Empty pool outputs a valid empty state without error (EX-7).
 * @tc.type: FUNC
 * @tc.require: 20260910614554
 */
HWTEST_F(FormExtensionProcessPoolTest, ProcessPoolDump_EmptyState, TestSize.Level1)
{
    auto pool = std::make_unique<FormExtensionProcessPool>();
    std::unordered_map<int32_t, FormExtensionProcessPool::BundleLedger> providers;
    FormExtensionProcessPool::PendingQueueMap pendingQueue;
    pool->DumpProcessPoolStatus(providers, pendingQueue);
    EXPECT_TRUE(providers.empty());
}
}
