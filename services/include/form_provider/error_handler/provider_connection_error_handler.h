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

#ifndef OHOS_FORM_FWK_PROVIDER_CONNECTION_ERROR_HANDLER_H
#define OHOS_FORM_FWK_PROVIDER_CONNECTION_ERROR_HANDLER_H

#include <functional>
#include <mutex>
#include <unordered_map>

#include "refbase.h"
#include "common/connection/form_ability_connection.h"
#include "common/retry_policy/retry_policy.h"
#include "common/util/form_task_common.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = AAFwk::Want;

/**
 * @class FormProviderConnectionErrorHandler
 * Base class for handling provider connection errors with retry policy management.
 * Provides dual-signal confirmed delayed retry mechanism for IPC errors.
 */
class FormProviderConnectionErrorHandler : public RefBase {
public:
    virtual ~FormProviderConnectionErrorHandler() = default;

    /**
     * @brief Check if the error code indicates remote object is dead.
     * @param errorCode IPC error code.
     * @return true if remote is dead (32 or 29189), false otherwise.
     */
    static bool IsRemoteDead(int errorCode);

    /**
     * @brief Handle send request failed error (first signal in dual-signal mechanism).
     *        Marks sendRequestFailed signal and checks dual-signal condition.
     * @param formId Form ID.
     * @param errorCode IPC error code.
     * @param want Want parameter for retry.
     * @return true if handled (waiting for disconnect OR retry already scheduled),
     *         false if unrecoverable (non-dead-error/no-connection/retry-limit-reached).
     */
    virtual bool HandleSendRequestFailed(int64_t formId, int errorCode, const Want &want);

    /**
     * @brief Handle disconnect error (second signal in dual-signal mechanism).
     *        Checks dual-signal condition and triggers retry if confirmed.
     * @param formId Form ID.
     * @param connection Form ability connection object.
     * @return true if dual-signal confirmed and retry scheduled, false otherwise.
     */
    virtual bool HandleDisconnectError(int64_t formId, const sptr<FormAbilityConnection> &connection);

    /**
     * @brief Register callback waiting after SendRequest returned ERR_OK: enters
     *        WAITING_CALLBACK, records connectId and starts the 10s callback timeout.
     *        Preserves retryCount across retries in the same retry chain.
     * @param formId Form ID.
     * @param connectId Connect id for callback matching.
     */
    void StartCallbackPending(int64_t formId, int32_t connectId);

    /**
     * @brief Notify callback arrival (called at OnAcquire head): WAITING_CALLBACK ->
     *        CALLBACK_COMPLETED, cancels pending timeouts, keeps the policy until
     *        disconnect cleanup or next registration. No-op without a matching
     *        WAITING_CALLBACK policy (absent / wrong stage / connectId mismatch).
     * @param formId Form ID (0 when the want carries no form identity, no policy matches).
     * @param connectId Connect id carried by the callback.
     */
    void OnCallbackArrived(int64_t formId, int32_t connectId);

    /**
     * @brief Remove retry policy for specified form.
     * @param formId Form ID.
     */
    void RemoveRetryPolicy(int64_t formId);

protected:
    static constexpr int32_t IPC_ERR_DEAD_OBJECT = 32;
    static constexpr int32_t IPC_ERR_SERVICE_DIED = 29189;
    // Fallback timeout waiting for the second dual-signal (disconnect or sendRequest).
    static constexpr int32_t RETRY_SIGNAL_TIMEOUT_MS = 5000; // ms
    // Callback timeout spec (aligned with DETECT_FORM_EXIT_TIMEOUT_DELAY, not adjustable):
    // neither callback nor disconnect within 10s -> out of scope, erase policy without retry.
    // Order dependency: StartCallbackPending must be called before DelayedFormExitDetect so
    // that the callback timeout fires first; otherwise the exit-detect disconnect converts
    // the scenario from "give up" to "retry".
    static constexpr int32_t CALLBACK_TIMEOUT_MS = 10 * 1000; // ms

    std::unordered_map<int64_t, RetryPolicy> retryPolicyMap_;
    std::mutex retryPolicyMutex_;

    /**
     * @brief Schedule retry task with exponential backoff delay.
     *        Calculates next delay based on retry policy and schedules retry.
     * @param formId Form ID.
     * @param policy Retry policy configuration.
     * @param retryFunc Retry function to execute.
     */
    virtual void ScheduleRetry(int64_t formId, const RetryPolicy &policy, std::function<void()> retryFunc);

    /**
     * @brief Get default retry policy configuration.
     * @return Default retry policy with maxRetryCount=3, strategyType=LINEAR, baseDelayMs=500, maxDelayMs=1500.
     */
    RetryPolicy GetDefaultRetryPolicy() const;

    /**
     * @brief Ensure retry policy exists for specified form (create default if absent).
     *        Caller MUST hold retryPolicyMutex_ before calling.
     * @param formId Form ID.
     * @return Reference to retry policy in retryPolicyMap_.
     */
    RetryPolicy &EnsureRetryPolicyLocked(int64_t formId);

    /**
     * @brief Start the dual-signal fallback timeout. If the second signal does not arrive
     *        within RETRY_SIGNAL_TIMEOUT_MS, OnSignalTimeout cleans up the stuck policy.
     *        Common to refresh and acquire (both hit S2 when FormExtension exits after the op).
     * @param formId Form ID.
     */
    void StartSignalTimeout(int64_t formId);

    /**
     * @brief Timeout handler: erase the policy if only one of the two signals arrived.
     * @param formId Form ID.
     */
    void OnSignalTimeout(int64_t formId);

    /**
     * @brief Cancel pending dual-signal timeout task for specified form.
     * @param formId Form ID.
     */
    void CancelSignalTimeout(int64_t formId);

    /**
     * @brief Start the 10s callback timeout for WAITING_CALLBACK. OnCallbackTimeout
     *        erases the policy when neither callback nor disconnect arrived.
     * @param formId Form ID.
     * @param connectId Connect id registered for this round (stale-round guard).
     */
    void StartCallbackTimeout(int64_t formId, int32_t connectId);

    /**
     * @brief Callback timeout handler: erase the policy if still WAITING_CALLBACK
     *        on the same round (expectedConnectId matches).
     * @param formId Form ID.
     * @param expectedConnectId Connect id captured at registration.
     */
    void OnCallbackTimeout(int64_t formId, int32_t expectedConnectId);

    /**
     * @brief Cancel pending callback timeout task for specified form.
     * @param formId Form ID.
     */
    void CancelCallbackTimeout(int64_t formId);

    /**
     * @brief Cancel all pending retry + signal-timeout tasks for specified form.
     *        Thread-safe (FormProviderQueue handles its own locking); safe to call within retryPolicyMutex_.
     * @param formId Form ID.
     */
    void CancelPendingTasks(int64_t formId);

    // --- Concrete common algorithm (subclasses customize via hooks below, not by overriding) ---

    /**
     * @brief Execute retry: clone connection and reconnect via AMS.
     *        Calls OnPrepareRetryConnect before connect; aborts if policy/form gone.
     * @param formId Form ID.
     * @param originalConnection Connection captured at dual-signal time (for CreateRetryConnection).
     */
    void ExecuteRetry(int64_t formId, const sptr<FormAbilityConnection> &originalConnection);

    /**
     * @brief Commit a retry attempt: cancel signal timeout, increment count, reset signals,
     *        and schedule the retry task (key = GetRetryTaskType()).
     * @param formId Form ID.
     * @param policy Retry policy (caller holds retryPolicyMutex_).
     * @param connection Connection to clone at retry time.
     */
    void ScheduleRetryWithReset(int64_t formId, RetryPolicy &policy, const sptr<FormAbilityConnection> &connection);

    /**
     * @brief Handle disconnect when stage=WAITING_CALLBACK: callback lost, retry or limit-reached.
     *        Caller MUST hold retryPolicyMutex_.
     * @return true (always handled).
     */
    bool HandleDisconnectOnWaitingCallback(int64_t formId, RetryPolicy &policy,
        const sptr<FormAbilityConnection> &connection);

    /**
     * @brief Handle disconnect when stage=WAITING_DISCONNECT_CONFIRM: dual-signal confirmed, retry or limit-reached.
     *        Caller MUST hold retryPolicyMutex_.
     * @return true (always handled).
     */
    bool HandleDisconnectOnWaitingConfirm(int64_t formId, RetryPolicy &policy,
        const sptr<FormAbilityConnection> &connection);

    /**
     * @brief Check retry limit: if reached, cancel pending tasks, erase policy, call OnRetryLimitReached.
     *        Caller MUST hold retryPolicyMutex_.
     * @return true if limit reached (terminal), false if retry can proceed.
     */
    bool CheckRetryLimitReached(int64_t formId, RetryPolicy &policy);

    // --- Virtual hooks: subclass variation points ---

    /**
     * @brief Get the delay-task key for this handler (refresh/acquire return their own
     *        TaskType so tasks of the two handlers never collide on one formId). The
     *        callback/signal timeouts and the retry task share this key slot: each policy
     *        stage has at most one active delay task and transitions cancel in pairs.
     * @return TaskType for ScheduleDelayTask/CancelDelayTask.
     */
    virtual TaskType GetRetryTaskType() const = 0;

    /**
     * @brief Called when retry limit is reached (terminal failure).
     *        Default is no-op; override to add scenario-specific failure reporting
     *        (e.g. acquire reports SendFormFailedEvent).
     * @param formId Form ID.
     */
    virtual void OnRetryLimitReached(int64_t formId) {};
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_PROVIDER_CONNECTION_ERROR_HANDLER_H