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

#include "data_center/form_info/form_info_mgr.h"

#include <algorithm>
#include <iterator>

#include "fms_log_wrapper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_info/form_info_helper.h"
#include "data_center/form_info/form_info_storage.h"
#include "data_center/form_info/form_info_rdb_storage_mgr.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"
#include "hitrace_meter.h"
#include "in_process_call_wrapper.h"
#include "ipc_skeleton.h"
#include "json_serializer.h"
#include "permission_verification.h"
#include "form_event_report.h"
#include "common_event.h"
#include "common_event_manager.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *FMS_IS_READY_EVENT = "fmsIsReady";
constexpr const char *PERMISSION_REQUIRE_FORM = "ohos.permission.REQUIRE_FORM";
constexpr const char *IS_DELETE_CACHE_FALSE = "false";
constexpr uint32_t GET_BUNDLE_INFO_WITH_ABILITY_EXTENSIONS =
    static_cast<uint32_t>(BundleFlag::GET_BUNDLE_WITH_ABILITIES) |
    static_cast<uint32_t>(BundleFlag::GET_BUNDLE_INFO_EXCLUDE_EXT);
constexpr int32_t MAX_RELOAD_RETRY = 3;
constexpr int64_t RETRY_DELAYS_MS[MAX_RELOAD_RETRY] = {100, 200, 400};
constexpr size_t RELOAD_BATCH_SIZE = 50;
}  // namespace
FormInfoMgr::FormInfoMgr()
{
    HILOG_INFO("create");
}

FormInfoMgr::~FormInfoMgr() = default;

ErrCode FormInfoMgr::LoadFormInfosFromDb()
{
    std::vector<std::pair<std::string, std::string>> formInfoStorages;
    ErrCode errCode = FormInfoRdbStorageMgr::GetInstance().LoadFormInfos(formInfoStorages);
    if (errCode != ERR_OK) {
        HILOG_ERROR("LoadFormInfos failed");
        return errCode;
    }

    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (const auto &item: formInfoStorages) {
        const std::string &bundleName = item.first;
        const std::string &formInfoStoragesJson = item.second;
        auto bundleFormInfoPtr = std::make_shared<BundleFormInfo>(bundleName);
        errCode = bundleFormInfoPtr->InitFromJson(formInfoStoragesJson);
        if (errCode != ERR_OK) {
            HILOG_ERROR("InitFromJson failed for %{public}s, removing corrupted entry", bundleName.c_str());
            FormInfoRdbStorageMgr::GetInstance().RemoveBundleFormInfos(bundleName);
            continue;
        }
        HILOG_INFO("load bundle %{public}s form infos success.", bundleName.c_str());
        bundleFormInfoMap_[bundleName] = bundleFormInfoPtr;
    }
    HILOG_INFO("load bundle form infos from db done");
    return ERR_OK;
}

ErrCode FormInfoMgr::Start()
{
    // std::call_once guarantees Start() loads DB exactly once.
    std::call_once(startOnceFlag_, [this]() { startResult_ = LoadFormInfosFromDb(); });
    return startResult_;
}

ErrCode FormInfoMgr::UpdateStaticFormInfos(const std::string &bundleName, int32_t userId)
{
    HILOG_INFO("UpdateStaticFormInfos: %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::shared_ptr<BundleFormInfo> bundleFormInfoPtr;
    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto search = bundleFormInfoMap_.find(bundleName);
    if (search != bundleFormInfoMap_.end()) {
        bundleFormInfoPtr = search->second;
    } else {
        bundleFormInfoPtr = std::make_shared<BundleFormInfo>(bundleName);
    }

    std::unordered_map<std::string, std::vector<FormInfo>> formInfosMap;
    std::vector<std::string> bundleNames;
    bundleNames.push_back(bundleName);
    ErrCode errCode = FormInfoHelper::LoadFormConfigInfoByBundleNames(bundleNames, userId, formInfosMap);
    if (errCode != ERR_OK) {
        HILOG_ERROR("get formInfosMap fail, errCode:%{public}d", errCode);
        return errCode;
    }
    std::vector<FormInfo> formInfos;
    for (auto &formInfoPair : formInfosMap) {
        formInfos = formInfoPair.second;
        break;
    }
    errCode = bundleFormInfoPtr->UpdateStaticFormInfos(formInfos, userId);
    if (errCode != ERR_OK) {
        HILOG_ERROR("UpdateStaticFormInfos failed!");
        return errCode;
    }

    if (bundleFormInfoPtr->Empty()) {
        // no forms found, no need to be inserted into the map
        return ERR_OK;
    }

    bundleFormInfoMap_[bundleName] = bundleFormInfoPtr;
    HILOG_INFO("success, bundleName=%{public}s", bundleName.c_str());
    return ERR_OK;
}

ErrCode FormInfoMgr::Remove(const std::string &bundleName, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        // BundleFormInfo not found, no need to remove
        return ERR_OK;
    }

    ErrCode errCode = ERR_OK;
    if (bundleFormInfoIter->second != nullptr) {
        errCode = bundleFormInfoIter->second->Remove(userId);
    }

    if (bundleFormInfoIter->second && bundleFormInfoIter->second->Empty()) {
        bundleFormInfoMap_.erase(bundleFormInfoIter);
    }
    HILOG_INFO("success, bundleName=%{public}s", bundleName.c_str());
    return errCode;
}

ErrCode FormInfoMgr::GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (!CheckBundlePermission()) {
        HILOG_ERROR("CheckBundlePermission is failed");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (const auto &bundleFormInfo : bundleFormInfoMap_) {
        if (bundleFormInfo.second != nullptr) {
            bundleFormInfo.second->GetAllFormsInfo(formInfos, userId);
        }
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (!CheckBundlePermission()) {
        HILOG_ERROR("CheckBundlePermission is failed");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (const auto &bundleFormInfo : bundleFormInfoMap_) {
        if (bundleFormInfo.second != nullptr) {
            bundleFormInfo.second->GetAllTemplateFormsInfo(formInfos, userId);
        }
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByFilter(
    const FormInfoFilter &filter, std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (!CheckBundlePermission()) {
        if (filter.bundleName.empty() || !IsCaller(filter.bundleName)) {
            HILOG_ERROR("Permission is wrong");
            return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
        }
    }
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    if (filter.bundleName.empty()) {
        for (const auto &bundleFormInfo : bundleFormInfoMap_) {
            if (bundleFormInfo.second != nullptr) {
                bundleFormInfo.second->GetFormsInfoByFilter(filter, formInfos, userId);
            }
        }
    } else {
        auto bundleFormInfoIter = bundleFormInfoMap_.find(filter.bundleName);
        if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
            HILOG_WARN("no forms found for bundle name:%{public}s", filter.bundleName.c_str());
            return ERR_OK;
        }
        if (bundleFormInfoIter->second != nullptr) {
            bundleFormInfoIter->second->GetFormsInfoByFilter(filter, formInfos, userId);
        }
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByBundle(
    const std::string &bundleName, std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!CheckBundlePermission() && !IsCaller(bundleName)) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }

    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_DEBUG("no forms found");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (bundleFormInfoIter->second != nullptr) {
        bundleFormInfoIter->second->GetAllFormsInfo(formInfos, userId);
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetTemplateFormsInfoByBundle(
    const std::string &bundleName, std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!CheckBundlePermission() && !IsCaller(bundleName)) {
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }

    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (bundleFormInfoIter->second != nullptr) {
        bundleFormInfoIter->second->GetAllTemplateFormsInfo(formInfos, userId);
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!CheckBundlePermission() && !IsCaller(bundleName)) {
        HILOG_ERROR("CheckBundlePermission and IsCaller failed");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }

    return GetFormsInfoByModuleWithoutCheck(bundleName, moduleName, formInfos, userId);
}

ErrCode FormInfoMgr::GetTemplateFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (!CheckBundlePermission() && !IsCaller(bundleName)) {
        HILOG_ERROR("CheckBundlePermission and IsCaller failed");
        return ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE;
    }

    return GetTemplateFormsInfoByModuleWithoutCheck(bundleName, moduleName, formInfos, userId);
}

ErrCode FormInfoMgr::GetFormsInfoByModuleWithoutCheck(const std::string &bundleName, const std::string &moduleName,
    std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found for %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (bundleFormInfoIter->second != nullptr) {
        bundleFormInfoIter->second->GetFormsInfoByModule(moduleName, formInfos, userId);
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetTemplateFormsInfoByModuleWithoutCheck(const std::string &bundleName,
    const std::string &moduleName, std::vector<FormInfo> &formInfos, int32_t userId)
{
    if (bundleName.empty()) {
        HILOG_ERROR("empty bundleName");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found for %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }

    if (bundleFormInfoIter->second != nullptr) {
        bundleFormInfoIter->second->GetTemplateFormsInfoByModule(moduleName, formInfos, userId);
    }
    return ERR_OK;
}

ErrCode FormInfoMgr::GetFormsInfoByRecord(const FormRecord &formRecord, FormInfo &formInfo)
{
    std::vector<FormInfo> formInfos;
    {
        std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
        auto bundleFormInfoIter = bundleFormInfoMap_.find(formRecord.bundleName);
        if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
            HILOG_ERROR("no forms found for %{public}s", formRecord.bundleName.c_str());
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }

        if (bundleFormInfoIter->second == nullptr) {
            HILOG_ERROR("null BundleFormInfo");
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }

        bundleFormInfoIter->second->GetFormsInfoByModule(formRecord.moduleName, formInfos, formRecord.userId);
    }
    for (const FormInfo &info : formInfos) {
        if (info.name == formRecord.formName) {
            formInfo = info;
            break;
        }
    }
    return formInfo.name.empty() ? ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED : ERR_OK;
}

ErrCode FormInfoMgr::CheckDynamicFormInfo(FormInfo &formInfo, const BundleInfo &bundleInfo)
{
    for (auto &moduleInfo : bundleInfo.hapModuleInfos) {
        if (formInfo.moduleName != moduleInfo.moduleName) {
            continue;
        }
        for (auto &abilityInfo : moduleInfo.abilityInfos) {
            if (formInfo.abilityName != abilityInfo.name) {
                continue;
            }
            formInfo.src = "";
            return ERR_OK;
        }
        for (auto &extensionInfos : moduleInfo.extensionInfos) {
            if (formInfo.abilityName != extensionInfos.name) {
                continue;
            }
            formInfo.src = "./js/" + formInfo.name + "/pages/index/index";
            return ERR_OK;
        }
        HILOG_ERROR("No match abilityName found");
        return ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY;
    }

    HILOG_ERROR("No match moduleName found");
    return ERR_APPEXECFWK_FORM_NO_SUCH_MODULE;
}

ErrCode FormInfoMgr::AddDynamicFormInfo(FormInfo &formInfo, int32_t userId)
{
    BundleInfo bundleInfo;
    int32_t flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ABILITY) |
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY);
    if (!FormBmsHelper::GetInstance().GetBundleInfoByFlags(formInfo.bundleName, flag, userId, bundleInfo)) {
        HILOG_ERROR("get bundleInfo failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    ErrCode errCode = CheckDynamicFormInfo(formInfo, bundleInfo);
    if (errCode != ERR_OK) {
        HILOG_ERROR("fail CheckDynamicFormInfo");
        return errCode;
    }

    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(formInfo.bundleName);
    std::shared_ptr<BundleFormInfo> bundleFormInfoPtr;
    if (bundleFormInfoIter != bundleFormInfoMap_.end()) {
        bundleFormInfoPtr = bundleFormInfoIter->second;
    } else {
        bundleFormInfoPtr = std::make_shared<BundleFormInfo>(formInfo.bundleName);
    }

    return bundleFormInfoPtr->AddDynamicFormInfo(formInfo, userId);
}

ErrCode FormInfoMgr::RemoveDynamicFormInfo(const std::string &bundleName, const std::string &moduleName,
                                           const std::string &formName, int32_t userId)
{
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found in bundle %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return bundleFormInfoIter->second->RemoveDynamicFormInfo(moduleName, formName, userId);
}

ErrCode FormInfoMgr::RemoveAllDynamicFormsInfo(const std::string &bundleName, int32_t userId)
{
    std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
        HILOG_ERROR("no forms found in bundle %{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return bundleFormInfoIter->second->RemoveAllDynamicFormsInfo(userId);
}

std::shared_ptr<BundleFormInfo> FormInfoMgr::GetOrCreateBundleFromInfo(const std::string &bundleName)
{
    {
        std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
        auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
        if (bundleFormInfoIter != bundleFormInfoMap_.end()) {
            // found
            return bundleFormInfoIter->second;
        }
    }

    // not found
    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
    // try to find again
    if (bundleFormInfoIter != bundleFormInfoMap_.end()) {
        // found
        return bundleFormInfoIter->second;
    }
    auto bundleFormInfoPtr = std::make_shared<BundleFormInfo>(bundleName);
    bundleFormInfoMap_[bundleName] = bundleFormInfoPtr;
    return bundleFormInfoPtr;
}

bool FormInfoMgr::IsCaller(const std::string& bundleName)
{
    AppExecFwk::BundleInfo bundleInfo;
    if (!FormBmsHelper::GetInstance().GetBundleInfoDefault(
        bundleName, FormUtil::GetCurrentAccountId(), bundleInfo)) {
        HILOG_ERROR("get bundleInfo failed");
        return false;
    }
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    if (bundleInfo.applicationInfo.accessTokenId == callerToken) {
        return true;
    }
    return false;
}

bool FormInfoMgr::CheckBundlePermission()
{
    if (FormUtil::IsSACall()) {
        return true;
    }
    if (FormUtil::VerifyCallingPermission(AppExecFwk::Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        return true;
    }
    HILOG_ERROR("Permission verification failed");
    return false;
}

ErrCode FormInfoMgr::ReloadFormInfos(const int32_t userId, std::function<void()> doneCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("userId:%{public}d", userId);
    {
        std::shared_lock<std::shared_mutex> lock(reloadUserIdsMutex_);
        if (reloadUserIds_.count(userId) != 0) {
            HILOG_INFO("userId %{public}d already reloaded, skip", userId);
            lock.unlock();
            if (doneCallback != nullptr) {
                doneCallback();
            }
            return ERR_OK;
        }
    }
    std::shared_ptr<ReloadContext> ctx;
    {
        std::unique_lock<std::shared_mutex> lock(reloadUserIdsMutex_);
        auto it = reloadingCtxs_.find(userId);
        if (it != reloadingCtxs_.end()) {
            // In-flight chain: reloadUserIds_ is not inserted until T_fin, so a second
            // trigger arriving between batches must not start a duplicate chain.
            auto inFlight = it->second.lock();
            if (inFlight == nullptr) {
                // Normally unreachable: while the entry exists, at least one queued
                // closure of the chain still holds the shared_ptr. A null here means
                // the old chain ended abnormally without erase (coding error).
                HILOG_ERROR("userId %{public}d stale reload entry, clean up", userId);
                reloadingCtxs_.erase(it);
                lock.unlock();
                if (doneCallback != nullptr) {
                    doneCallback();
                }
                return ERR_OK;
            }
            HILOG_INFO("userId %{public}d reload in-flight, append callback", userId);
            if (doneCallback != nullptr) {
                inFlight->doneCallbacks.push_back(std::move(doneCallback));
            }
            return ERR_OK;
        }
        ctx = std::make_shared<ReloadContext>();
        ctx->userId = userId;
        if (doneCallback != nullptr) {
            ctx->doneCallbacks.push_back(std::move(doneCallback));
        }
        reloadingCtxs_[userId] = ctx;
    }
    SubmitBatchTask(ctx, [ctx]() {
        FormInfoMgr::GetInstance().StartReloadBatches(ctx);
    });
    return ERR_OK;
}

void FormInfoMgr::StartReloadBatches(std::shared_ptr<ReloadContext> ctx)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (ctx->aborted.load()) {
        HILOG_INFO("reload aborted before start, userId:%{public}d", ctx->userId);
        SubmitBatchTask(ctx, [ctx]() {
            FormInfoMgr::GetInstance().FinishReloadBatches(ctx);
        });
        return;
    }
    // ensure DB data is loaded before touching bundleFormInfoMap_.
    Start();
    std::unordered_map<std::string, std::uint32_t> bundleVersionMap;
    ErrCode result = GetBundleVersionMap(bundleVersionMap, ctx->userId);
    if (result != ERR_OK) {
        HandleReloadRetry(ctx, result);
        return;
    }
    std::string versionCode;
    FormInfoRdbStorageMgr::GetInstance().GetFormVersionCode(versionCode);
    int oldVersionCode = 0;
    bool convertOk = FormUtil::ConvertStringToInt(versionCode, oldVersionCode);
    ctx->isNeedUpdateAll = versionCode.empty() || !convertOk ||
        Constants::FORM_VERSION_CODE != oldVersionCode;
    HILOG_INFO("bundle number:%{public}zu, old versionCode:%{public}s, new versionCode:%{public}d",
        bundleVersionMap.size(), versionCode.c_str(), Constants::FORM_VERSION_CODE);

    BundleClassifyResult classify;
    {
        std::shared_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
        classify = ClassifyBundles(ctx->isNeedUpdateAll, ctx->userId, bundleVersionMap);
    }

    ctx->removeBundles = std::move(classify.removeBundles);
    ctx->pendingBundles = std::move(classify.newBundles);
    ctx->pendingBundles.insert(ctx->pendingBundles.end(),
        std::make_move_iterator(classify.updateBundles.begin()),
        std::make_move_iterator(classify.updateBundles.end()));
    HILOG_INFO("reload batches begin, user:%{public}d, total:%{public}zu, batches:%{public}zu",
        ctx->userId, ctx->pendingBundles.size(),
        (ctx->pendingBundles.size() + RELOAD_BATCH_SIZE - 1) / RELOAD_BATCH_SIZE);

    SubmitBatchTask(ctx, [ctx]() {
        if (ctx->pendingBundles.empty() && ctx->removeBundles.empty()) {
            FormInfoMgr::GetInstance().FinishReloadBatches(ctx);
        } else {
            FormInfoMgr::GetInstance().ProcessReloadBatch(ctx);
        }
    });
}

void FormInfoMgr::HandleReloadRetry(std::shared_ptr<ReloadContext> ctx, ErrCode result)
{
    HILOG_ERROR("GetBundleVersionMap failed, %{public}d, retryCount:%{public}d",
        result, ctx->retryCount);
    if (ctx->retryCount >= MAX_RELOAD_RETRY) {
        FireReloadCallbacks(ctx);
        FormEventReport::SendFormFailedEvent(FormEventName::RELOAD_FORM_FAILED,
            HiSysEventType::FAULT, result);
        return;
    }
    // Exponential backoff via delayed re-submission; TaskKey dedup prevents
    // duplicate retry chains when another trigger arrives during backoff.
    int64_t delayMs = RETRY_DELAYS_MS[ctx->retryCount];
    ctx->retryCount++;
    bool scheduled = FormMgrQueue::GetInstance().ScheduleDelayTask(
        Common::TaskKey("ReloadRetry_" + std::to_string(ctx->userId)), delayMs,
        [ctx]() { FormInfoMgr::GetInstance().StartReloadBatches(ctx); },
        Common::TaskQos::QOS_DEADLINE_REQUEST);
    if (!scheduled) {
        // Anti-hang: submission failed, give up this chain instead of leaking it.
        HILOG_ERROR("schedule retry failed, give up, userId:%{public}d", ctx->userId);
        FireReloadCallbacks(ctx);
        FormEventReport::SendFormFailedEvent(FormEventName::RELOAD_FORM_FAILED,
            HiSysEventType::FAULT, result);
    }
}

void FormInfoMgr::FireReloadCallbacks(std::shared_ptr<ReloadContext> ctx)
{
    std::vector<std::function<void()>> callbacks;
    {
        std::unique_lock<std::shared_mutex> lock(reloadUserIdsMutex_);
        reloadingCtxs_.erase(ctx->userId);
        callbacks.swap(ctx->doneCallbacks);
    }
    for (auto &callback : callbacks) {
        callback();
    }
}

void FormInfoMgr::SubmitBatchTask(std::shared_ptr<ReloadContext> ctx, std::function<void()> task)
{
    if (!batchExecutor_(std::move(task))) {
        HILOG_ERROR("batchExecutor_ submission failed, give up chain, userId:%{public}d", ctx->userId);
        FireReloadCallbacks(ctx);
        FormEventReport::SendFormFailedEvent(FormEventName::RELOAD_FORM_FAILED,
            HiSysEventType::FAULT, ERR_APPEXECFWK_FORM_COMMON_CODE);
    }
}

void FormInfoMgr::ProcessReloadBatch(std::shared_ptr<ReloadContext> ctx)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HILOG_INFO("process reload batch, offset:%{public}zu, total:%{public}zu, userId:%{public}d",
        ctx->offset, ctx->pendingBundles.size(), ctx->userId);
    if (ctx->aborted.load()) {
        HILOG_INFO("reload aborted at batch offset:%{public}zu, userId:%{public}d",
            ctx->offset, ctx->userId);
        // T_fin (aborted branch) fires callbacks and clears the registry: no hanging.
        SubmitBatchTask(ctx, [ctx]() {
            FormInfoMgr::GetInstance().FinishReloadBatches(ctx);
        });
        return;
    }
    if (ctx->offset >= ctx->pendingBundles.size()) {
        SubmitBatchTask(ctx, [ctx]() {
            FormInfoMgr::GetInstance().FinishReloadBatches(ctx);
        });
        return;
    }
    size_t end = std::min(ctx->offset + RELOAD_BATCH_SIZE, ctx->pendingBundles.size());
    std::vector<std::string> batch(ctx->pendingBundles.begin() + ctx->offset,
                                   ctx->pendingBundles.begin() + end);

    ErrCode batchErr = ProcessBundleBatch(batch, ctx->userId);
    if (batchErr != ERR_OK) {
        ctx->failedBatches.push_back(ctx->offset);
        HILOG_ERROR("batch range %{public}zu to %{public}zu failed, %{public}d", ctx->offset, end, batchErr);
    }
    ctx->offset = end;

    if (ctx->offset < ctx->pendingBundles.size()) {
        SubmitBatchTask(ctx, [ctx]() {
            FormInfoMgr::GetInstance().ProcessReloadBatch(ctx);
        });
    } else {
        SubmitBatchTask(ctx, [ctx]() {
            FormInfoMgr::GetInstance().FinishReloadBatches(ctx);
        });
    }
}

void FormInfoMgr::FinishReloadBatches(std::shared_ptr<ReloadContext> ctx)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    // Aborted (user removed): fire callbacks only, skip mark/publish/version write-back.
    if (ctx->aborted.load()) {
        HILOG_INFO("reload aborted at finish, userId:%{public}d, skip mark/publish", ctx->userId);
        FireReloadCallbacks(ctx);
        return;
    }
    RetryFailedBatches(ctx);
    // Version write-back after all batches complete: prerequisite of the fast path on next boot.
    if (ctx->isNeedUpdateAll) {
        FormInfoRdbStorageMgr::GetInstance().UpdateFormVersionCode();
    }
    RemoveUninstalledBundles(ctx);

    std::vector<std::function<void()>> callbacks;
    {
        std::unique_lock<std::shared_mutex> lock(reloadUserIdsMutex_);
        reloadUserIds_.insert(ctx->userId);
        reloadingCtxs_.erase(ctx->userId);
        callbacks.swap(ctx->doneCallbacks);
    }
    bool publishRet = PublishFmsReadyEvent();
    if (!publishRet) {
        HILOG_ERROR("failed to publish fmsIsReady event with permission");
    }
    // Fired strictly after publish: consumers (e.g. rerender) rely on fmsIsReady semantics.
    for (auto &callback : callbacks) {
        callback();
    }
}

void FormInfoMgr::RetryFailedBatches(std::shared_ptr<ReloadContext> ctx)
{
    for (const auto &start : ctx->failedBatches) {
        size_t end = std::min(start + RELOAD_BATCH_SIZE, ctx->pendingBundles.size());
        std::vector<std::string> batch(ctx->pendingBundles.begin() + start,
                                       ctx->pendingBundles.begin() + end);
        ErrCode retryErr = ProcessBundleBatch(batch, ctx->userId);
        if (retryErr != ERR_OK) {
            HILOG_ERROR("retry batch from %{public}zu still failed, %{public}d", start, retryErr);
        }
    }
    ctx->failedBatches.clear();
}

void FormInfoMgr::RemoveUninstalledBundles(std::shared_ptr<ReloadContext> ctx)
{
    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (const auto &bundleName : ctx->removeBundles) {
        auto it = bundleFormInfoMap_.find(bundleName);
        if (it == bundleFormInfoMap_.end()) {
            continue;
        }
        HILOG_WARN("bundle %{public}s not in versionMap and not installed, Remove", bundleName.c_str());
        it->second->Remove(ctx->userId);
        if (it->second->Empty()) {
            bundleFormInfoMap_.erase(it);
        }
    }
    HILOG_INFO("batches end, formInfoMapSize:%{public}zu", bundleFormInfoMap_.size());
}

ErrCode FormInfoMgr::ProcessBundleBatch(const std::vector<std::string> &bundleNames, int32_t userId)
{
    std::unordered_map<std::string, std::vector<FormInfo>> formInfosMap;
    ErrCode errCode = FormInfoHelper::LoadFormConfigInfoByBundleNames(bundleNames, userId, formInfosMap);
    if (errCode != ERR_OK) {
        HILOG_ERROR("LoadFormConfigInfoByBundleNames fail, errCode:%{public}d", errCode);
        return errCode;
    }
    std::vector<std::pair<std::string, std::string>> dirtyStorages;
    std::vector<std::string> removedStorages;
    MergeBundleBatch(formInfosMap, userId, dirtyStorages, removedStorages);
    errCode = FormInfoRdbStorageMgr::GetInstance().BatchUpdateBundleFormInfos(std::move(dirtyStorages));
    for (const auto &bundleName : removedStorages) {
        FormInfoRdbStorageMgr::GetInstance().RemoveBundleFormInfos(bundleName);
    }
    if (errCode != ERR_OK) {
        // Whole batch rolled back: memory is ahead of RDB until the T_fin retry re-runs it.
        HILOG_ERROR("batch commit form info storages failed, errCode:%{public}d", errCode);
        return errCode;
    }
    return ERR_OK;
}

void FormInfoMgr::MergeBundleBatch(std::unordered_map<std::string, std::vector<FormInfo>> &formInfosMap,
    int32_t userId, std::vector<std::pair<std::string, std::string>> &dirtyStorages,
    std::vector<std::string> &removedStorages)
{
    // Memory updates under the map lock; RDB writes are committed as one transaction
    // per batch after the lock (N_card fsync -> N_card/50).
    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (auto &formInfoPair : formInfosMap) {
        const std::string &bundleName = formInfoPair.first;
        if (bundleName.empty()) {
            HILOG_WARN("empty bundleName, skip");
            continue;
        }
        std::vector<FormInfo> &formInfos = formInfoPair.second;
        auto bundleFormInfoIter = bundleFormInfoMap_.find(bundleName);
        std::shared_ptr<BundleFormInfo> bundleFormInfoPtr;
        if (bundleFormInfoIter != bundleFormInfoMap_.end()) {
            bundleFormInfoPtr = bundleFormInfoIter->second;
        } else {
            bundleFormInfoPtr = std::make_shared<BundleFormInfo>(bundleName);
        }
        std::string storageJson;
        bool needRemoveStorage = false;
        ErrCode errCode = bundleFormInfoPtr->UpdateStaticFormInfosBatch(
            formInfos, userId, storageJson, needRemoveStorage);
        if (errCode != ERR_OK) {
            HILOG_ERROR("update forms info failed, bundleName=%{public}s, errCode:%{public}d",
                bundleName.c_str(), errCode);
            continue;
        }
        if (needRemoveStorage) {
            // The map entry is reclaimed by RemoveUninstalledBundles or user removal, not here.
            removedStorages.push_back(bundleName);
            continue;
        }
        if (bundleFormInfoIter == bundleFormInfoMap_.end()) {
            bundleFormInfoMap_[bundleName] = bundleFormInfoPtr;
            HILOG_INFO("add forms info success, bundleName=%{public}s", bundleName.c_str());
        } else {
            HILOG_INFO("update forms info success, bundleName=%{public}s", bundleName.c_str());
        }
        dirtyStorages.emplace_back(bundleName, std::move(storageJson));
    }
}

bool FormInfoMgr::PublishFmsReadyEvent()
{
    HILOG_INFO("publish fmsIsReady event");
    Want eventWant;
    eventWant.SetAction(FMS_IS_READY_EVENT);
    CommonEventData eventData;
    eventData.SetWant(eventWant);
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSubscriberPermissions({PERMISSION_REQUIRE_FORM});
    bool ret = EventFwk::CommonEventManager::PublishCommonEvent(eventData, publishInfo);
    return ret;
}

void FormInfoMgr::ClearReloadUserId(int32_t userId)
{
    HILOG_INFO("clear reload userId:%{public}d", userId);
    std::unique_lock<std::shared_mutex> lock(reloadUserIdsMutex_);
    reloadUserIds_.erase(userId);
}

ErrCode FormInfoMgr::RemoveUserId(int32_t userId)
{
    HILOG_INFO("remove userId:%{public}d", userId);
    {
        std::unique_lock<std::shared_mutex> lock(reloadUserIdsMutex_);
        auto it = reloadingCtxs_.find(userId);
        if (it != reloadingCtxs_.end()) {
            // lock() cannot be null here: same reasoning as the re-entry guard.
            auto inFlight = it->second.lock();
            if (inFlight != nullptr) {
                inFlight->aborted.store(true);
            }
            HILOG_INFO("abort in-flight reload for removed userId:%{public}d", userId);
        }
    }
    {
        std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
        for (auto it = bundleFormInfoMap_.begin(); it != bundleFormInfoMap_.end();) {
            it->second->Remove(userId);
            if (it->second->Empty()) {
                it = bundleFormInfoMap_.erase(it);
            } else {
                ++it;
            }
        }
    }
    ClearReloadUserId(userId);
    return ERR_OK;
}

bool FormInfoMgr::HasReloadedFormInfos(int32_t userId)
{
    std::shared_lock<std::shared_mutex> lock(reloadUserIdsMutex_);
    bool reloaded = reloadUserIds_.count(userId) != 0;
    HILOG_DEBUG("userId %{public}d reloaded state %{public}d", userId, reloaded);
    return reloaded;
}

ErrCode FormInfoMgr::GetAppFormVisibleNotifyByBundleName(const std::string &bundleName,
    int32_t providerUserId, bool &appFormVisibleNotify)
{
    std::lock_guard<std::mutex> lock(appFormVisibleNotifyMapMutex_);
    auto iter = appFormVisibleNotifyMap_.find(bundleName);
    if (iter == appFormVisibleNotifyMap_.end()) {
        AppExecFwk::ApplicationInfo info;
        if (FormBmsHelper::GetInstance().GetApplicationInfo(bundleName, providerUserId, info) != ERR_OK) {
            HILOG_ERROR("get ApplicationInfo failed");
            return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
        }
        appFormVisibleNotifyMap_.emplace(bundleName, info.formVisibleNotify);
        appFormVisibleNotify = info.formVisibleNotify;
        HILOG_INFO("bundleName=%{public}s, appFormVisibleNotify=%{public}d", bundleName.c_str(), appFormVisibleNotify);
    } else {
        appFormVisibleNotify = iter->second;
    }
    return ERR_OK;
}

bool FormInfoMgr::IsMultiAppForm(const FormInfo &formInfo)
{
    bool isMultiAppForm = false;
    for (auto dataIter = formInfo.customizeDatas.begin(); dataIter != formInfo.customizeDatas.end();) {
        if (std::string(Constants::IS_MULTI_APP_FORM) == dataIter->name &&
            std::string(Constants::IS_MULTI_APP_FORM_TRUE) == dataIter->value) {
            isMultiAppForm = true;
            break;
        }
        ++dataIter;
    }
    return isMultiAppForm;
}

bool FormInfoMgr::IsTemplateFormImperativeFwkValid(const FormInfo &formInfo)
{
    for (const auto &dataIter : formInfo.customizeDatas) {
        if (dataIter.name == Constants::TEMPLATE_FORM_IMPERATIVE_FWK_NAME) {
            auto it = std::find(Constants::TEMPLATE_FORM_IMPERATIVE_FWKS,
                Constants::TEMPLATE_FORM_IMPERATIVE_FWKS_END, dataIter.value);
            if (it == Constants::TEMPLATE_FORM_IMPERATIVE_FWKS_END) {
                return false;
            }
        }
    }
    return true;
}

bool FormInfoMgr::IsDeleteCacheInUpgradeScene(const FormInfo &formInfo)
{
    for (auto dataIter = formInfo.customizeDatas.begin(); dataIter != formInfo.customizeDatas.end(); ++dataIter) {
        if (Constants::IS_DELETE_CACHE_IN_UPGRADE_SCENE == dataIter->name &&
            dataIter->value == IS_DELETE_CACHE_FALSE) {
            return false;
        }
    }
    return true;
}

ErrCode FormInfoMgr::GetBundleVersionMap(
    std::unordered_map<std::string, std::uint32_t> &bundleVersionMap, int32_t userId)
{
    if (!FormBmsHelper::GetInstance().IsBundleMgrValid()) {
        HILOG_ERROR("get bundleMgr failed");
        return ERR_APPEXECFWK_FORM_GET_BMS_FAILED;
    }

    std::vector<ExtensionAbilityInfo> extensionInfos {};
    if (!FormBmsHelper::GetInstance().QueryExtensionAbilityInfosByType(
        ExtensionAbilityType::FORM, userId, extensionInfos)) {
        HILOG_ERROR("get extension infos failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    std::vector<BundleInfo> bundleInfos {};
    if (!FormBmsHelper::GetInstance().GetBundleInfos(
        static_cast<int32_t>(GET_BUNDLE_INFO_WITH_ABILITY_EXTENSIONS), bundleInfos, userId)) {
        HILOG_ERROR("get bundle infos failed");
        return ERR_APPEXECFWK_FORM_GET_INFO_FAILED;
    }

    // get names of bundles that must contain stage forms
    for (auto &extensionInfo : extensionInfos) {
        bundleVersionMap.emplace(std::move(extensionInfo.bundleName), extensionInfo.applicationInfo.versionCode);
    }
    // get names of bundles that may contain fa forms
    for (auto &bundleInfo : bundleInfos) {
        if (!bundleInfo.abilityInfos.empty() && !bundleInfo.abilityInfos[0].isStageBasedModel) {
            bundleVersionMap.emplace(std::move(bundleInfo.name), bundleInfo.versionCode);
        }
    }
    return ERR_OK;
}

FormInfoMgr::BundleClassifyResult FormInfoMgr::ClassifyBundles(bool isNeedUpdateAll, int32_t userId,
    const std::unordered_map<std::string, std::uint32_t> &bundleVersionMap) const
{
    BundleClassifyResult result;
    for (const auto &bundleFormInfoPair : bundleFormInfoMap_) {
        const std::string &bundleName = bundleFormInfoPair.first;
        auto bundleVersionPair = bundleVersionMap.find(bundleName);
        if (bundleVersionPair == bundleVersionMap.end()) {
            // versionMap is built by QueryExtensionAbilityInfosByType which skips disabled apps,
            // double-check with GetBundleInfoByFlags to avoid removing disabled-but-installed apps.
            BundleInfo bundleInfo;
            int32_t flags = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
            bool bundleExists = FormBmsHelper::GetInstance().GetBundleInfoByFlags(
                bundleName, flags, userId, bundleInfo);
            if (bundleExists) {
                HILOG_WARN("bundle %{public}s not in versionMap but still installed(disabled), skip Remove",
                    bundleName.c_str());
                continue;
            }
            HILOG_WARN("bundle %{public}s not in versionMap and not installed, removeBundles",
                bundleName.c_str());
            result.removeBundles.push_back(bundleName);
            continue;
        }

        if (!isNeedUpdateAll) {
            uint32_t newVersionCode = bundleVersionPair->second;
            uint32_t oldVersionCode = bundleFormInfoPair.second->GetVersionCode(userId);
            if (oldVersionCode == newVersionCode) {
                continue;
            }
            HILOG_INFO("bundle %{public}s version changed, old:%{public}u, new:%{public}u, userId:%{public}d",
                bundleName.c_str(), oldVersionCode, newVersionCode, userId);
        }
        result.updateBundles.push_back(bundleName);
    }

    // Entries present in versionMap but absent from map are freshly installed bundles.
    for (const auto &bundleVersionPair : bundleVersionMap) {
        if (bundleFormInfoMap_.find(bundleVersionPair.first) == bundleFormInfoMap_.end()) {
            result.newBundles.push_back(bundleVersionPair.first);
        }
    }
    HILOG_INFO("classify done, update:%{public}zu, remove:%{public}zu, new:%{public}zu",
        result.updateBundles.size(), result.removeBundles.size(), result.newBundles.size());
    return result;
}

void FormInfoMgr::UpdateFormShowConfigs(const std::vector<FormCustomConfig> &configs)
{
    HILOG_DEBUG("call, config size:%{public}zu", configs.size());
    // Group configs by bundleName
    std::unordered_map<std::string, std::vector<FormCustomConfig>> bundleConfigsMap;
    for (const auto &config : configs) {
        bundleConfigsMap[config.bundleName].push_back(config);
    }

    std::unique_lock<std::shared_timed_mutex> guard(bundleFormInfoMapMutex_);
    for (const auto &[bundleName, bundleConfigs] : bundleConfigsMap) {
        auto iter = bundleFormInfoMap_.find(bundleName);
        if (iter == bundleFormInfoMap_.end() || iter->second == nullptr) {
            HILOG_WARN("no BundleFormInfo for %{public}s", bundleName.c_str());
            continue;
        }
        iter->second->UpdateFormShowConfigs(bundleConfigs);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
