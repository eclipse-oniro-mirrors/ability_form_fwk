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

#ifndef OHOS_FORM_FWK_FORM_EXTENSION_PROCESS_POOL_H
#define OHOS_FORM_FWK_FORM_EXTENSION_PROCESS_POOL_H

#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "common/connection/form_ability_connection.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @struct PendingRequest
 * @brief A suspended connect request waiting for a free pool slot.
 */
struct PendingRequest {
    AAFwk::Want want;
    sptr<FormAbilityConnection> connect;
    int32_t userId = 0;
    int64_t formId = -1;
    int64_t enqueueTimestamp = 0; // boot time in milliseconds
    // Explicit userId from the original caller (-1 = ConnectServiceAbility without userId).
    int32_t connectUserId = -1;
};

struct WptrHash {
    size_t operator()(const wptr<FormAbilityConnection> &w) const
    {
        return std::hash<FormAbilityConnection *>()(w.GetRefPtr());
    }
};

/**
 * @class FormExtensionProcessPool
 * @brief FormExtension process pool gate and ledger.
 *
 * Ledger: unordered_map<userId, unordered_map<bundleName,
 *         unordered_set<wptr<FormAbilityConnection>, WptrHash>>>.
 * One (userId, bundleName) entry with a non-empty set counts as one pool
 * slot (one FormExtension process). All registrations occupy a slot so the
 * ledger reflects real process usage. Weak references do not extend
 * connection lifetime; dead references are skipped on traversal.
 *
 * Pending queue: per-userId FIFO deque (natural insertion order).
 * Replay is bundle-granular: find the first visible request, then collect
 * and replay ALL requests for that request's bundleName together (they
 * share one FormExtension process).
 *
 * Locking: mutex_ guards ledger and queues; no IPC/callback under the lock.
 * Replay is issued by the connection layer outside the pool lock and must
 * re-enter the gate (ConnectServiceAbility) to prevent over-admission.
 */
class FormExtensionProcessPool final {
public:
    static FormExtensionProcessPool& GetInstance();
    DISALLOW_COPY_AND_MOVE(FormExtensionProcessPool);
    using BundleSet = std::unordered_set<wptr<FormAbilityConnection>, WptrHash>;
    using BundleLedger = std::unordered_map<std::string, BundleSet>;
    using PendingQueueMap = std::unordered_map<int32_t, std::deque<PendingRequest>>;

    /**
     * @brief Pool admission check for one connect request. The decision,
     *        registration and enqueue are atomic under a single lock.
     * @return true to proceed with the ability manager service connect, false when suspended.
     */
    bool AdmitConnection(const AAFwk::Want &want, const sptr<FormAbilityConnection> &connect,
        int32_t connectUserId = -1);

    /**
     * @brief Connection terminated (disconnect or async connect failure):
     *        remove the registration; erase the bundle entry when its set
     *        becomes empty (slot released). Idempotent by pointer.
     */
    void OnConnectionTerminated(int32_t userId, const std::string &bundleName,
        const sptr<FormAbilityConnection> &connect);

    /**
     * @brief Count non-empty bundle entries of the user (occupied slots).
     */
    int32_t GetActiveProviderCount(int32_t userId);

    /**
     * @brief Total pending request count of the user.
     */
    int32_t GetPendingCount(int32_t userId);

    /**
     * @brief Force-admit a pending connection (bypass threshold). Used by the
     *        3-second visibility timeout: if the card is still visible after
     *        waiting, allow the process to start.
     */
    bool ForceAdmitConnection(const AAFwk::Want &want, const sptr<FormAbilityConnection> &connect);

    /**
     * @brief Copy the internal ledger and pending queue to output
     *        parameters under one lock. Callers parse the raw data.
     */
    void DumpProcessPoolStatus(std::unordered_map<int32_t, BundleLedger> &activeProviders,
        PendingQueueMap &pendingQueue);

private:
    FormExtensionProcessPool();
    ~FormExtensionProcessPool();
    size_t GetActiveProviderCountNoLock(int32_t userId) const;
    void CleanDeadConnectionsNoLock();
    int32_t GetPendingCountNoLock(int32_t userId);
    bool RemoveRegistrationNoLock(int32_t userId, const std::string &bundleName,
        const sptr<FormAbilityConnection> &connect);

    /**
     * @brief Pop the first currently-visible pending request; falls back
     *        to the FIFO head if none is visible.
     */
    bool PopNext(int32_t userId, PendingRequest &out);

    /**
     * @brief Pop the first pending request matching the given bundleName.
     */
    bool PopNextByBundle(int32_t userId, const std::string &bundleName, PendingRequest &out);

    /**
     * @brief Schedule an async replay of a pending request through the ability manager service gate.
     */
    void ReplayRequest(const PendingRequest &request);

    /**
     * @brief Pop the first visible request's bundle and replay all requests
     *        for that bundle together (they share one FormExtension process).
     */
    void ReplayPendingHead(int32_t userId);

    /**
     * @brief Schedule a delayed check: if the card is still visible after
     *        3 seconds of waiting, force-admit the connection.
     */
    void ScheduleVisibilityTimeout(const AAFwk::Want &want,
        const sptr<FormAbilityConnection> &connect, int32_t connectUserId);

    /**
     * @brief Timeout callback: force-admit if still pending and visible.
     */
    void OnPendingVisibilityTimeout(const AAFwk::Want &want,
        const sptr<FormAbilityConnection> &connect, int32_t connectUserId);

    /**
     * @brief Check if the connection is exempt from threshold gating
     *        (single-op type or card-center system-app location).
     */
    static bool IsExemptedConnection(const sptr<FormAbilityConnection> &connect);

    /**
     * @brief Threshold check and registration. Caller must hold mutex_.
     * @return true if registered (proceed), false if pool full (enqueue).
     */
    bool TryAcquire(const AAFwk::Want &want,
        const sptr<FormAbilityConnection> &connect, int32_t userId, bool isExempt);

    /**
     * @brief Suspend a request into the pending queue (same-formId supersede,
     *        queue limit check). Caller must hold mutex_.
     */
    void FilterSameTypePendingNoLock(int32_t userId, int64_t formId,
        const sptr<FormAbilityConnection> &connect);
    bool EnqueuePending(const AAFwk::Want &want,
        const sptr<FormAbilityConnection> &connect, int32_t userId, int32_t connectUserId);

    mutable std::mutex mutex_;
    size_t threshold_ = 0;
    std::unordered_map<int32_t, BundleLedger> activeProviders_;
    PendingQueueMap pendingQueue_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_EXTENSION_PROCESS_POOL_H
