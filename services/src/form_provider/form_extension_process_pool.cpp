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

#include "form_provider/form_extension_process_pool.h"

#include "common/util/form_util.h"
#include "data_center/form_cust_config_mgr.h"
#include "data_center/form_data_mgr.h"
#include "form_constants.h"
#include "fms_log_wrapper.h"
#include "ams_mgr/form_ams_helper.h"
#include "form_mgr/form_mgr_queue.h"
#include "util/form_time_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t PENDING_QUEUE_LIMIT = 100;
constexpr int32_t PENDING_VISIBLE_CHECK_DELAY_MS = 3000; // 3s visibility timeout

ErrCode ConnectProvider(const AAFwk::Want &want, const sptr<FormAbilityConnection> &connect,
    int32_t connectUserId)
{
    if (connectUserId != -1) {
        return FormAmsHelper::GetInstance().ConnectServiceAbilityWithUserId(want, connect, connectUserId);
    }
    return FormAmsHelper::GetInstance().ConnectServiceAbility(want, connect);
}

bool CleanDeadConnectionsFromBundleSet(FormExtensionProcessPool::BundleSet &connectionSet)
{
    for (auto connectionIter = connectionSet.begin(); connectionIter != connectionSet.end();) {
        if (connectionIter->promote() == nullptr) {
            connectionIter = connectionSet.erase(connectionIter);
        } else {
            ++connectionIter;
        }
    }
    return connectionSet.empty();
}

void CleanDeadConnectionsFromUserLedger(FormExtensionProcessPool::BundleLedger &userLedger)
{
    for (auto bundleIter = userLedger.begin(); bundleIter != userLedger.end();) {
        if (CleanDeadConnectionsFromBundleSet(bundleIter->second)) {
            bundleIter = userLedger.erase(bundleIter);
        } else {
            ++bundleIter;
        }
    }
}

} // namespace

FormExtensionProcessPool& FormExtensionProcessPool::GetInstance()
{
    static FormExtensionProcessPool instance;
    return instance;
}

FormExtensionProcessPool::FormExtensionProcessPool()
{
    threshold_ = FormCustConfigMgr::GetInstance().GetFormExtensionProcessPoolMax();
}

FormExtensionProcessPool::~FormExtensionProcessPool() = default;

size_t FormExtensionProcessPool::GetActiveProviderCountNoLock(int32_t userId) const
{
    auto userIter = activeProviders_.find(userId);
    if (userIter == activeProviders_.end()) {
        return 0;
    }
    return userIter->second.size();
}

void FormExtensionProcessPool::CleanDeadConnectionsNoLock()
{
    for (auto userIter = activeProviders_.begin(); userIter != activeProviders_.end();) {
        CleanDeadConnectionsFromUserLedger(userIter->second);
        if (userIter->second.empty()) {
            userIter = activeProviders_.erase(userIter);
        } else {
            ++userIter;
        }
    }
}

bool FormExtensionProcessPool::IsExemptedConnection(const sptr<FormAbilityConnection> &connect)
{
    // Single-op connection types are not threshold-gated.
    if (!connect->IsPoolManaged()) {
        return true;
    }
    // Card-center system-app exemption: query the latest formLocation from
    // FormDataMgr (single source of truth, kept fresh by UpdateFormLocation).
    Constants::FormLocation location = Constants::FormLocation::OTHER;
    bool found = FormDataMgr::GetInstance().AccessFormRecord(connect->GetFormId(),
        [&location](const FormRecord &record) {
            location = record.formLocation;
        });
    if (!found) {
        return false;
    }
    return FormUtil::IsFormCenterLocation(location);
}

bool FormExtensionProcessPool::AdmitConnection(const AAFwk::Want &want,
    const sptr<FormAbilityConnection> &connect, int32_t connectUserId)
{
    if (connect == nullptr) {
        return true;
    }
    int32_t userId = connect->GetUserId();
    // Exemption depends only on connection attributes and FormDataMgr state,
    // queried outside the pool lock to avoid a nested cross-module lock.
    bool isExempt = IsExemptedConnection(connect);

    // Minimal lock scope: gate decision + enqueue must be atomic.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (TryAcquire(want, connect, userId, isExempt)) {
            return true;
        }
        if (!EnqueuePending(want, connect, userId, connectUserId)) {
            // Queue full: allow the connection rather than silently dropping it.
            std::string bundleName = want.GetElement().GetBundleName();
            activeProviders_[userId][bundleName].insert(connect);
            HILOG_ERROR("PoolGate queue full, force allow formId:%{public}" PRId64,
                connect->GetFormId());
            return true;
        }
    }
    ScheduleVisibilityTimeout(want, connect, connectUserId);
    HILOG_WARN("PoolGate PENDING formId:%{public}" PRId64 " bundle:%{public}s",
        connect->GetFormId(), want.GetElement().GetBundleName().c_str());
    return false;
}

bool FormExtensionProcessPool::TryAcquire(const AAFwk::Want &want,
    const sptr<FormAbilityConnection> &connect, int32_t userId, bool isExempt)
{
    std::string bundleName = want.GetElement().GetBundleName();
    // Remove dead weak references in the target bundle before checking hasExistingSlot.
    CleanDeadConnectionsNoLock();
    BundleLedger &userLedger = activeProviders_[userId];
    // Same-bundle connections share the existing process slot: always allow.
    auto existingBundle = userLedger.find(bundleName);
    bool hasExistingSlot = existingBundle != userLedger.end() && !existingBundle->second.empty();
    if (isExempt || threshold_ == 0 || hasExistingSlot
        || GetActiveProviderCountNoLock(userId) < threshold_) {
        userLedger[bundleName].insert(connect);
        return true;
    }
    return false;
}

void FormExtensionProcessPool::FilterSameTypePendingNoLock(int32_t userId, int64_t formId,
    const sptr<FormAbilityConnection> &connect)
{
    auto userIter = pendingQueue_.find(userId);
    if (userIter == pendingQueue_.end()) {
        return;
    }
    for (auto requestIter = userIter->second.begin(); requestIter != userIter->second.end(); ++requestIter) {
        if (requestIter->formId != formId || requestIter->connect == nullptr
            || requestIter->connect->GetConnectionType() != connect->GetConnectionType()) {
            continue;
        }
        requestIter->connect->SetPoolPending(false);
        userIter->second.erase(requestIter);
        if (userIter->second.empty()) {
            pendingQueue_.erase(userIter);
        }
        return;
    }
}

bool FormExtensionProcessPool::EnqueuePending(const AAFwk::Want &want,
    const sptr<FormAbilityConnection> &connect, int32_t userId, int32_t connectUserId)
{
    int64_t formId = connect->GetFormId();
    FilterSameTypePendingNoLock(userId, formId, connect);
    if (GetPendingCountNoLock(userId) >= PENDING_QUEUE_LIMIT) {
        HILOG_ERROR("pending queue full, formId %{public}" PRId64, formId);
        return false;
    }
    PendingRequest request;
    request.want = want;
    request.connect = connect;
    request.userId = userId;
    request.formId = formId;
    request.enqueueTimestamp = Common::FormTimeUtil::GetBootTimeMs();
    request.connectUserId = connectUserId;
    pendingQueue_[userId].emplace_back(std::move(request));
    connect->SetPoolPending(true);
    return true;
}

bool FormExtensionProcessPool::RemoveRegistrationNoLock(int32_t userId, const std::string &bundleName,
    const sptr<FormAbilityConnection> &connection)
{
    auto userIter = activeProviders_.find(userId);
    if (userIter == activeProviders_.end()) {
        return false;
    }
    auto bundleIter = userIter->second.find(bundleName);
    if (bundleIter == userIter->second.end()) {
        return false;
    }
    // Idempotent remove by pointer (wptr == sptr comparison).
    wptr<FormAbilityConnection> weak(connection);
    bundleIter->second.erase(weak);
    if (bundleIter->second.empty()) {
        userIter->second.erase(bundleIter);
        if (userIter->second.empty()) {
            activeProviders_.erase(userIter);
        }
        return true;
    }
    return false;
}

void FormExtensionProcessPool::OnConnectionTerminated(int32_t userId, const std::string &bundleName,
    const sptr<FormAbilityConnection> &connection)
{
    if (connection == nullptr) {
        return;
    }
    bool slotReleased = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        slotReleased = RemoveRegistrationNoLock(userId, bundleName, connection);
    }
    if (slotReleased) {
        ReplayPendingHead(userId);
    }
}

bool FormExtensionProcessPool::ForceAdmitConnection(const AAFwk::Want &want,
    const sptr<FormAbilityConnection> &connect)
{
    if (connect == nullptr || !connect->IsPoolPending()) {
        return false;
    }
    int32_t userId = connect->GetUserId();
    std::string bundleName = want.GetElement().GetBundleName();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // Re-check under lock: PopNext may have already popped this request
        // between the outer IsPoolPending check and here, causing a duplicate connect.
        if (!connect->IsPoolPending()) {
            return false;
        }
        // Remove the specific pending request for this connection (by pointer, not formId,
        // to avoid removing a different-type request that shares the same formId).
        auto &forceQueue = pendingQueue_[userId];
        for (auto requestIter = forceQueue.begin(); requestIter != forceQueue.end(); ++requestIter) {
            if (requestIter->connect == connect) {
                forceQueue.erase(requestIter);
                if (forceQueue.empty()) {
                    pendingQueue_.erase(userId);
                }
                break;
            }
        }
        activeProviders_[userId][bundleName].insert(connect);
    }
    connect->SetPoolPending(false);
    HILOG_INFO("ForceAdmit visible formId:%{public}" PRId64, connect->GetFormId());
    return true;
}

void FormExtensionProcessPool::ScheduleVisibilityTimeout(const AAFwk::Want &want,
    const sptr<FormAbilityConnection> &connect, int32_t connectUserId)
{
    AAFwk::Want wantCopy = want;
    sptr<FormAbilityConnection> connectCopy = connect;
    if (!FormMgrQueue::GetInstance().ScheduleTask(PENDING_VISIBLE_CHECK_DELAY_MS,
        [wantCopy, connectCopy, connectUserId]() {
            FormExtensionProcessPool::GetInstance().OnPendingVisibilityTimeout(
                wantCopy, connectCopy, connectUserId);
        })) {
        HILOG_ERROR("ScheduleTask failed, visibility timeout disabled for this request");
    }
}

void FormExtensionProcessPool::OnPendingVisibilityTimeout(const AAFwk::Want &want,
    const sptr<FormAbilityConnection> &connect, int32_t connectUserId)
{
    if (connect == nullptr || !connect->IsPoolPending()) {
        return; // Already replayed or superseded.
    }
    if (!FormDataMgr::GetInstance().GetFormVisible(connect->GetFormId())) {
        return; // Card not visible, stay in queue.
    }
    if (!ForceAdmitConnection(want, connect)) {
        return;
    }
    ErrCode connectResult = ConnectProvider(want, connect, connectUserId);
    if (connectResult != ERR_OK) {
        HILOG_ERROR("VisibilityTimeout connect failed, errorCode:%{public}d", connectResult);
    }
}

void FormExtensionProcessPool::ReplayPendingHead(int32_t userId)
{
    PendingRequest trigger;
    if (!PopNext(userId, trigger)) {
        return;
    }
    ReplayRequest(trigger);

    // Replay all remaining requests for the same bundle (they share the process).
    std::string bundleName = trigger.want.GetElement().GetBundleName();
    PendingRequest request;
    while (PopNextByBundle(userId, bundleName, request)) {
        ReplayRequest(request);
    }
}

bool FormExtensionProcessPool::PopNextByBundle(int32_t userId, const std::string &bundleName,
    PendingRequest &out)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto userQueueIter = pendingQueue_.find(userId);
    if (userQueueIter == pendingQueue_.end()) {
        return false;
    }
    auto &requestQueue = userQueueIter->second;
    for (auto requestIter = requestQueue.begin(); requestIter != requestQueue.end(); ++requestIter) {
        if (requestIter->want.GetElement().GetBundleName() != bundleName) {
            continue;
        }
        out = std::move(*requestIter);
        requestQueue.erase(requestIter);
        if (out.connect != nullptr) {
            out.connect->SetPoolPending(false);
        }
        if (requestQueue.empty()) {
            pendingQueue_.erase(userQueueIter);
        }
        return true;
    }
    return false;
}

void FormExtensionProcessPool::ReplayRequest(const PendingRequest &request)
{
    HILOG_INFO("PoolReplay formId:%{public}" PRId64, request.formId);
    AAFwk::Want want = request.want;
    sptr<FormAbilityConnection> connect = request.connect;
    int32_t connectUserId = request.connectUserId;
    bool scheduled = FormMgrQueue::GetInstance().ScheduleTask(0, [want, connect, connectUserId]() {
        ErrCode asyncResult = ConnectProvider(want, connect, connectUserId);
        if (asyncResult != ERR_OK) {
            HILOG_ERROR("Async replay connect failed, errorCode:%{public}d", asyncResult);
        }
    });
    if (!scheduled) {
        HILOG_ERROR("ScheduleTask failed, execute replay synchronously");
        ErrCode syncResult = ConnectProvider(want, connect, connectUserId);
        if (syncResult != ERR_OK) {
            HILOG_ERROR("Synchronous replay connect failed, errorCode:%{public}d", syncResult);
        }
    }
}

bool FormExtensionProcessPool::PopNext(int32_t userId, PendingRequest &out)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto userQueueIter = pendingQueue_.find(userId);
    if (userQueueIter == pendingQueue_.end() || userQueueIter->second.empty()) {
        return false;
    }
    auto &requestQueue = userQueueIter->second;
    // Prefer the first currently-visible request; FIFO head as fallback.
    auto requestIter = requestQueue.begin();
    for (; requestIter != requestQueue.end(); ++requestIter) {
        if (FormDataMgr::GetInstance().GetFormVisible(requestIter->formId)) {
            break;
        }
    }
    if (requestIter == requestQueue.end()) {
        requestIter = requestQueue.begin();
    }
    out = std::move(*requestIter);
    requestQueue.erase(requestIter);
    if (out.connect != nullptr) {
        out.connect->SetPoolPending(false);
    }
    if (requestQueue.empty()) {
        pendingQueue_.erase(userQueueIter);
    }
    return true;
}

int32_t FormExtensionProcessPool::GetActiveProviderCount(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return static_cast<int32_t>(GetActiveProviderCountNoLock(userId));
}

int32_t FormExtensionProcessPool::GetPendingCountNoLock(int32_t userId)
{
    auto userQueueIter = pendingQueue_.find(userId);
    return userQueueIter != pendingQueue_.end() ? static_cast<int32_t>(userQueueIter->second.size()) : 0;
}

int32_t FormExtensionProcessPool::GetPendingCount(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    return GetPendingCountNoLock(userId);
}

void FormExtensionProcessPool::DumpProcessPoolStatus(
    std::unordered_map<int32_t, BundleLedger> &activeProviders,
    PendingQueueMap &pendingQueue)
{
    std::lock_guard<std::mutex> lock(mutex_);
    activeProviders = activeProviders_;
    pendingQueue = pendingQueue_;
}

} // namespace AppExecFwk
} // namespace OHOS
