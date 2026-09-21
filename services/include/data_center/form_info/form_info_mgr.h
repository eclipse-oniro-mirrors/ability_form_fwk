/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_INFO_MGR_H
#define OHOS_FORM_FWK_FORM_INFO_MGR_H

#include <atomic>
#include <shared_mutex>
#include <singleton.h>
#include <unordered_map>
#include <unordered_set>
#include <functional>

#include "appexecfwk_errors.h"
#include "bundle_form_info.h"
#include "form_custom_config.h"
#include "bundle_info.h"
#include "form_info.h"
#include "form_info_filter.h"
#include "data_center/form_record/form_record.h"
#include "resource_manager.h"
#include "form_mgr/form_mgr_queue.h"

namespace OHOS {
namespace AppExecFwk {
class FormInfoMgr final : public DelayedRefSingleton<FormInfoMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormInfoMgr)

public:
    DISALLOW_COPY_AND_MOVE(FormInfoMgr);

    ErrCode Start();

    ErrCode UpdateStaticFormInfos(const std::string &bundleName, int32_t userId);

    ErrCode Remove(const std::string &bundleName, int32_t userId);

    ErrCode GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByBundle(
        const std::string &bundleName, std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetTemplateFormsInfoByBundle(
        const std::string &bundleName, std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetTemplateFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByFilter(
        const FormInfoFilter &filter, std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByRecord(const FormRecord &formRecord, FormInfo &formInfo);

    ErrCode GetFormsInfoByModuleWithoutCheck(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetTemplateFormsInfoByModuleWithoutCheck(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode AddDynamicFormInfo(FormInfo &formInfo, int32_t userId);

    ErrCode RemoveDynamicFormInfo(const std::string &bundleName, const std::string &moduleName,
                                  const std::string &formName, int32_t userId);

    ErrCode RemoveAllDynamicFormsInfo(const std::string &bundleName, int32_t userId);

    ErrCode ReloadFormInfos(int32_t userId, std::function<void()> doneCallback = nullptr);

    bool PublishFmsReadyEvent();

    bool HasReloadedFormInfos(int32_t userId);

    void ClearReloadUserId(int32_t userId);

    ErrCode RemoveUserId(int32_t userId);

    ErrCode GetAppFormVisibleNotifyByBundleName(const std::string &bundleName,
        int32_t providerUserId, bool &appFormVisibleNotify);

    bool IsMultiAppForm(const FormInfo &formInfo);
    bool IsTemplateFormImperativeFwkValid(const FormInfo &formInfo);

    bool IsDeleteCacheInUpgradeScene(const FormInfo &formInfo);

    void UpdateFormShowConfigs(const std::vector<FormCustomConfig> &configs);

private:
    // ===== Types =====

    // Explicit tri-partition of bundles, produced by pure classification.
    // removeBundles entries are recorded only; actual Remove is executed by the caller.
    struct BundleClassifyResult {
        std::vector<std::string> updateBundles;
        std::vector<std::string> removeBundles;
        std::vector<std::string> newBundles;

        size_t TotalWorkload() const
        {
            return updateBundles.size() + removeBundles.size() + newBundles.size();
        }
    };

    // Batched reload context, alive across chained queue tasks via shared_ptr.
    struct ReloadContext {
        int32_t userId = Constants::INVALID_USER_ID;
        std::vector<std::string> pendingBundles;      // newBundles + updateBundles (ordered)
        std::vector<std::string> removeBundles;          // executed in T_fin
        size_t offset = 0;                            // next batch start index
        int32_t retryCount = 0;                       // T0 backoff retries for GetBundleVersionMap failures
        std::vector<size_t> failedBatches;            // failed batch start offsets, retried once in T_fin
        bool isNeedUpdateAll = false;                 // set in T0, version written back in T_fin
        std::vector<std::function<void()>> doneCallbacks; // FIFO; re-entry appends; fired after publish in T_fin
        // Atomic: written by RemoveUserId, read at batch boundaries; thread safety must
        // not depend on the implicit same-queue assumption of the callers.
        std::atomic<bool> aborted {false};
    };

    // Batch executor: re-submits onto FormMgrQueue (serial chaining).
    // Returns false if submission failed (queue full/shutdown); caller must clean up ctx.
    // Tests replace this member directly via #define private public (no test-only setter).
    using BatchExecutor = std::function<bool(std::function<void()>)>;

    // ===== Member functions =====

    std::shared_ptr<BundleFormInfo> GetOrCreateBundleFromInfo(const std::string &bundleName);
    static bool IsCaller(const std::string& bundleName);
    static bool CheckBundlePermission();
    static ErrCode CheckDynamicFormInfo(FormInfo &formInfo, const BundleInfo &bundleInfo);
    ErrCode LoadFormInfosFromDb();
    static ErrCode GetBundleVersionMap(
        std::unordered_map<std::string, std::uint32_t> &bundleVersionMap, int32_t userId);
    // Pure classification without side effects: reads bundleFormInfoMap_, no Remove, no map mutation.
    BundleClassifyResult ClassifyBundles(bool isNeedUpdateAll, int32_t userId,
        const std::unordered_map<std::string, std::uint32_t> &bundleVersionMap) const;
    // T0: load DB, fetch version map, classify, build ctx, dispatch first batch.
    void StartReloadBatches(std::shared_ptr<ReloadContext> ctx);
    // Handle GetBundleVersionMap failure: exponential backoff retry, give-up reports FAULT.
    void HandleReloadRetry(std::shared_ptr<ReloadContext> ctx, ErrCode result);
    // Fire all pending callbacks (anti-hang) after clearing the in-flight registry.
    void FireReloadCallbacks(std::shared_ptr<ReloadContext> ctx);
    // Tk: process one batch, dispatch next or T_fin.
    void ProcessReloadBatch(std::shared_ptr<ReloadContext> ctx);
    // T_fin: retry failed batches once, write back version, execute removeBundles, mark, publish, fire callbacks.
    void FinishReloadBatches(std::shared_ptr<ReloadContext> ctx);
    // Retry failed batches exactly once and clear the failure list.
    void RetryFailedBatches(std::shared_ptr<ReloadContext> ctx);
    // Execute removeBundles cleanup under the map lock.
    void RemoveUninstalledBundles(std::shared_ptr<ReloadContext> ctx);
    // Single batch: BMS load outside lock, map update inside lock.
    ErrCode ProcessBundleBatch(const std::vector<std::string> &bundleNames, int32_t userId);
    // In-lock memory merge of one loaded batch; collects RDB writes for the caller's batch commit.
    void MergeBundleBatch(std::unordered_map<std::string, std::vector<FormInfo>> &formInfosMap, int32_t userId,
        std::vector<std::pair<std::string, std::string>> &dirtyStorages,
        std::vector<std::string> &removedStorages);
    // Submit next batch task via batchExecutor_; on failure, fire callbacks to avoid leaking ctx.
    void SubmitBatchTask(std::shared_ptr<ReloadContext> ctx, std::function<void()> task);

    // ===== Member variables =====

    // In-flight reload registry: prevents duplicate chains when multiple trigger sources
    // interleave between batches (reloadUserIds_ is only inserted in T_fin).
    // Guarded by reloadUserIdsMutex_. Registered in ReloadFormInfos, cleared in T_fin or on T0 failure.
    std::unordered_map<int32_t, std::weak_ptr<ReloadContext>> reloadingCtxs_;
    BatchExecutor batchExecutor_ = [](std::function<void()> task) -> bool {
        return FormMgrQueue::GetInstance().ScheduleTask(0, std::move(task), Common::TaskQos::QOS_DEADLINE_REQUEST);
    };
    mutable std::shared_timed_mutex bundleFormInfoMapMutex_ {};
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap_ {};
    mutable std::shared_mutex reloadUserIdsMutex_;
    std::unordered_set<int32_t> reloadUserIds_;
    std::once_flag startOnceFlag_;
    ErrCode startResult_ = ERR_OK;
    std::map<std::string, bool> appFormVisibleNotifyMap_;
    std::mutex appFormVisibleNotifyMapMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_INFO_MGR_H
