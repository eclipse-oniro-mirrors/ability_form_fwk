/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "common/event/form_event_util.h"

#include <regex>
#include <dirent.h>
#include "directory_ex.h"

#include "fms_log_wrapper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_cache_mgr.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_data_proxy_mgr.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_info/form_info_mgr.h"
#include "form_mgr/form_mgr_adapter.h"
#include "form_render/form_render_mgr.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "common/util/form_trust_mgr.h"
#include "common/util/form_util.h"
#include "form_provider/form_provider_mgr.h"
#include "want.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "feature/param_update/param_control.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int NORMAL_BUNDLE_MODULE_LENGTH = 1;

void UpdateRecordByBundleInfo(const BundleInfo &bundleInfo, FormRecord &formRecord)
{
    formRecord.modulePkgNameMap.clear();
    if (!bundleInfo.hapModuleInfos.empty()) {
        for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
            auto hapPath = hapModuleInfo.hapPath;
            auto moduleName = hapModuleInfo.moduleName;
            HILOG_INFO("update record %{public}" PRId64 ". packageName is %{public}s, hap path is %{public}s, "
                "jsFormCodePath:%{public}s", formRecord.formId, hapModuleInfo.packageName.c_str(), hapPath.c_str(),
                formRecord.jsFormCodePath.c_str());
            if (hapPath.find(Constants::ABS_CODE_PATH) != std::string::npos) {
                hapPath = std::regex_replace(hapPath, std::regex(Constants::ABS_CODE_PATH), Constants::LOCAL_BUNDLES);
            }
            nlohmann::json moduleInfos = {
                {Constants::MODULE_PKG_NAME_KEY, hapModuleInfo.packageName},
                {Constants::MODULE_HAP_PATH_KEY, hapPath}
            };
            formRecord.modulePkgNameMap.emplace(std::make_pair(moduleName, moduleInfos.dump()));
            if ((formRecord.isDistributedForm && moduleName == formRecord.uiModule) ||
                (!formRecord.isDistributedForm && moduleName == formRecord.moduleName)) {
                HILOG_INFO("update jsFormCodePath, isDistributedForm:%{public}d", formRecord.isDistributedForm);
                formRecord.jsFormCodePath = hapPath;
            }
        }
    }

    formRecord.hapSourceDirs.clear();
    for (const auto &item : bundleInfo.applicationInfo.moduleInfos) {
        if (formRecord.moduleName == item.moduleName) {
            formRecord.hapSourceDirs.emplace_back(item.moduleSourceDir);
        }
    }
}
}

void FormEventUtil::HandleBundleFormInfoChanged(const std::string &bundleName, int32_t userId, bool &needReload)
{
    needReload = FormTrustMgr::GetInstance().IsTrust(bundleName);
    FormTrustMgr::GetInstance().MarkTrustFlag(bundleName, true);
    FormInfoMgr::GetInstance().UpdateStaticFormInfos(bundleName, userId);
}

void FormEventUtil::HandleUpdateFormCloud(const std::string &bundleName)
{
    FormMgrAdapter::GetInstance().UpdateFormCloudUpdateDuration(bundleName);
}

void FormEventUtil::HandleProviderUpdated(const std::string &bundleName, const int userId,
    const bool needReload, const bool needCheckVersion)
{
    HILOG_WARN(
        "bundleName:%{public}s, userId:%{public}d, needReload:%{public}d", bundleName.c_str(), userId, needReload);
    std::vector<FormRecord> formInfos;
    if (!FormDataMgr::GetInstance().GetFormRecord(bundleName, formInfos, userId)) {
        return;
    }

    std::vector<FormInfo> targetForms;
    if (FormInfoMgr::GetInstance().GetFormsInfoByBundle(bundleName, targetForms, userId) != ERR_OK) {
        return;
    }

    BundlePackInfo bundlePackInfo;
    bool hasPackInfo = FormBmsHelper::GetInstance().GetBundlePackInfo(bundleName, userId, bundlePackInfo);
    HILOG_INFO("bundleName:%{public}s, hasPackInfo:%{public}d", bundleName.c_str(), hasPackInfo);
    BundleInfo bundleInfo;
    if (FormBmsHelper::GetInstance().GetBundleInfoV9(bundleName, userId, bundleInfo) != ERR_OK) {
        HILOG_ERROR("get bundleInfo failed");
        return;
    }
    std::vector<int64_t> removedForms;
    std::vector<FormRecord> updatedForms;
    bool isBundleDistributed = FormDistributedMgr::GetInstance().IsBundleDistributed(bundleInfo.name, userId);
    for (FormRecord& formRecord : formInfos) {
        int64_t formId = formRecord.formId;
        HILOG_INFO("bundle update, formName:%{public}s, moduleName:%{public}s, isDistributedForm:%{public}d, "
            "isBundleDistributed:%{public}d, formId:%{public}" PRId64, formRecord.formName.c_str(),
            formRecord.moduleName.c_str(), formRecord.isDistributedForm, isBundleDistributed, formId);

        if (needCheckVersion && bundleInfo.versionCode == formRecord.versionCode &&
            formRecord.isDistributedForm == isBundleDistributed) {
            HILOG_WARN("form: %{public}s, versionCode is same and no package format change. formId:%{public}" PRId64,
                formRecord.formName.c_str(), formId);
            continue;
        }

        if (ProviderFormUpdated(formId, formRecord, targetForms, bundleInfo)) {
            updatedForms.emplace_back(formRecord);
            continue;
        }
        if (hasPackInfo && ProviderFormUpdated(formId, formRecord, bundlePackInfo, bundleInfo)) {
            updatedForms.emplace_back(formRecord);
            continue;
        }

        if (formRecord.formTempFlag) {
            FormDataMgr::GetInstance().DeleteTempForm(formId);
        } else {
            FormDbCache::GetInstance().DeleteFormInfo(formId);
        }
        HILOG_WARN(
            "delete form record, formName:%{public}s, formId:%{public}" PRId64, formRecord.formName.c_str(), formId);
        removedForms.emplace_back(formId);
        FormDataMgr::GetInstance().DeleteFormRecord(formId);
        FormRenderMgr::GetInstance().StopRenderingForm(formId, formRecord);
        FormDataProxyMgr::GetInstance().UnsubscribeFormData(formId);
    }
    HandleProviderUpdatedDetail(removedForms, updatedForms, bundleName, userId, needReload);
}

void FormEventUtil::HandleFormReload(
    const std::string &bundleName, const int userId, const bool needReload, const std::vector<FormRecord> &updatedForms)
{
    Want want;
    want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
    want.SetParam(Constants::FORM_ENABLE_UPDATE_REFRESH_KEY, true);
    want.SetParam(Constants::FORM_DATA_UPDATE_TYPE, Constants::FULL_UPDATE);
    FormMgrAdapter::GetInstance().DelayRefreshFormsOnAppUpgrade(updatedForms, want);
    if (needReload) {
        FormRenderMgr::GetInstance().ReloadForm(std::move(updatedForms), bundleName, userId);
    } else {
        FormTrustMgr::GetInstance().HandleConnectFailed(updatedForms, userId);
    }
}

void FormEventUtil::HandleOnUnlock(int32_t userId)
{
    FormRenderMgr::GetInstance().OnUnlock(userId);
}

void FormEventUtil::HandleBundleFormInfoRemoved(const std::string &bundleName, int32_t userId)
{
    FormTrustMgr::GetInstance().MarkTrustFlag(bundleName, true);
    FormInfoMgr::GetInstance().Remove(bundleName, userId);
    FormDataMgr::GetInstance().RemoveFormCloudUpdateDuration(bundleName);
}

void FormEventUtil::HandleProviderRemoved(const std::string &bundleName, const int32_t userId)
{
    HILOG_INFO("bundleName:%{public}s, userId:%{public}d", bundleName.c_str(), userId);
    // clean removed form in DB
    std::set<int64_t> removedForms;
    std::vector<FormDBInfo> removedDBForm;
    FormDbCache::GetInstance().DeleteFormInfoByBundleName(bundleName, userId, removedDBForm);
    for (const auto &dbForm : removedDBForm) {
        removedForms.emplace(dbForm.formId);
        int32_t matchCount = FormDbCache::GetInstance().GetMatchCount(dbForm.bundleName, dbForm.moduleName);
        if (matchCount == 0) {
            FormBmsHelper::GetInstance().NotifyModuleRemovable(dbForm.bundleName, dbForm.moduleName);
        }
    }
    // clean removed form in FormRecords
    FormDataMgr::GetInstance().CleanRemovedFormRecords(bundleName, removedForms);
    // clean removed temp form in FormRecords
    FormDataMgr::GetInstance().CleanRemovedTempFormRecords(bundleName, userId, removedForms);
    // clean removed forms in FormHostRecords
    std::vector<int64_t> vRemovedForms;
    vRemovedForms.assign(removedForms.begin(), removedForms.end());
    FormDataMgr::GetInstance().CleanHostRemovedForms(vRemovedForms);
    // clean removed form timers
    for (auto &formId : removedForms) {
        FormTimerMgr::GetInstance().RemoveFormTimer(formId);
        FormDataProxyMgr::GetInstance().UnsubscribeFormData(formId);
    }

    FormRenderMgr::GetInstance().DeleteAcquireForbiddenTasksByBundleName(bundleName);
}

void FormEventUtil::HandleBundleDataCleared(const std::string &bundleName, int32_t userId)
{
    HILOG_WARN("bundleName:%{public}s, userId:%{public}d", bundleName.c_str(), userId);
    // clear dynamic form info
    FormInfoMgr::GetInstance().RemoveAllDynamicFormsInfo(bundleName, userId);

    // as provider data is cleared
    std::set<int64_t> reCreateForms;
    FormDataMgr::GetInstance().GetReCreateFormRecordsByBundleName(bundleName, reCreateForms);
    if (!reCreateForms.empty()) {
        for (int64_t formId : reCreateForms) {
            ReCreateForm(formId);
        }
    }

    int32_t uid = FormBmsHelper::GetInstance().GetUidByBundleName(bundleName, userId);
    if (uid == FormBmsHelper::INVALID_UID) {
        HILOG_ERROR("invalid uid");
        return;
    }
    // as form host data is cleared
    HandleFormHostDataCleared(uid);
}

void FormEventUtil::HandleFormHostDataCleared(const int uid)
{
    HILOG_DEBUG("uid:%{public}d", uid);
    std::map<int64_t, bool> removedFormsMap;
    // clear formDBRecord
    ClearFormDBRecordData(uid, removedFormsMap);

    // clear temp form
    ClearTempFormRecordData(uid, removedFormsMap);

    // clear host data
    FormDataMgr::GetInstance().ClearHostDataByUId(uid);

    // delete forms timer
    for (const auto &removedForm : removedFormsMap) {
        if (removedForm.second) {
            FormTimerMgr::GetInstance().RemoveFormTimer(removedForm.first);
        }
    }
}

bool FormEventUtil::ProviderFormUpdated(const int64_t formId, FormRecord &formRecord,
    const std::vector<FormInfo> &targetForms, const BundleInfo &bundleInfo)
{
    HILOG_INFO("start");
    if (targetForms.empty()) {
        HILOG_ERROR("empty targetForms");
        return false;
    }

    bool isBundleDistributed =
        FormDistributedMgr::GetInstance().IsBundleDistributed(bundleInfo.name, formRecord.providerUserId);
    HILOG_INFO("bundleName: %{public}s, isBundleDistributed: %{public}d, formId:%{public}" PRId64,
        bundleInfo.name.c_str(), isBundleDistributed, formId);
    if (formRecord.isDistributedForm != isBundleDistributed) {
        // The format of the installation package has changed.
        if (!isBundleDistributed || bundleInfo.hapModuleInfos.size() > NORMAL_BUNDLE_MODULE_LENGTH) {
            // whole package install finished
            formRecord.isDistributedForm = isBundleDistributed;
            formRecord.uiModule =
                FormDistributedMgr::GetInstance().GetUiModuleName(bundleInfo.name, formRecord.providerUserId);
            HILOG_INFO("form pack format change, uiModule:%{public}s", formRecord.uiModule.c_str());
        }
    }

    // normal or standalone package install finish, update version info
    if (!isBundleDistributed || bundleInfo.hapModuleInfos.size() > NORMAL_BUNDLE_MODULE_LENGTH) {
        formRecord.lastVersionCode = formRecord.versionCode;
        formRecord.versionCode = bundleInfo.versionCode;
    }

    FormInfo updatedForm;
    bool bGetForm = FormDataMgr::GetInstance().GetUpdatedForm(formRecord, targetForms, updatedForm);
    if (!bGetForm) {
        HILOG_INFO("no updated form");
        return false;
    }
    HILOG_INFO("form is still exist, form:%{public}s, formId:%{public}" PRId64, formRecord.formName.c_str(), formId);

    // update resource
    if (FormMgrAdapter::GetInstance().IsDeleteCacheInUpgradeScene(formRecord)) {
        HILOG_INFO("Delete cache data in upgrade scene");
        FormCacheMgr::GetInstance().DeleteData(formId);
    }
    FormDataMgr::GetInstance().SetNeedRefresh(formId, true);
    FormBmsHelper::GetInstance().NotifyModuleNotRemovable(formRecord.bundleName, formRecord.moduleName);
    FormTimerCfg timerCfg;
    GetTimerCfg(updatedForm.updateEnabled, updatedForm.updateDuration, updatedForm.scheduledUpdateTime, timerCfg);
    SetTimerCfgByMultUpdate(updatedForm.multiScheduledUpdateTime, timerCfg);
    HandleTimerUpdate(formId, formRecord, timerCfg);
    UpdateRecordByBundleInfo(bundleInfo, formRecord);
    UpdateFormRecord(updatedForm, formRecord);
    FormDataMgr::GetInstance().SetVersionUpgrade(formId, true);
    return true;
}

bool FormEventUtil::ProviderFormUpdated(const int64_t formId, FormRecord &formRecord,
    const BundlePackInfo &bundlePackInfo, const BundleInfo &bundleInfo)
{
    HILOG_INFO("start");
    AbilityFormInfo packForm;
    if (!FormDataMgr::GetInstance().GetPackageForm(formRecord, bundlePackInfo, packForm)) {
        HILOG_INFO("no updated form");
        return false;
    }

    HILOG_INFO("form is still in package info, form:%{public}s", formRecord.formName.c_str());
    FormDataMgr::GetInstance().SetRecordNeedFreeInstall(formId, true);
    FormTimerCfg timerCfg;
    GetTimerCfg(packForm.updateEnabled, packForm.updateDuration, packForm.scheduledUpdateTime, timerCfg);
    SetTimerCfgByMultUpdate(packForm.multiScheduledUpdateTime, timerCfg);
    HandleTimerUpdate(formId, formRecord, timerCfg);
    UpdateRecordByBundleInfo(bundleInfo, formRecord);
    UpdateFormRecord(packForm, formRecord);
    FormDataMgr::GetInstance().SetVersionUpgrade(formId, true);
    return true;
}

void FormEventUtil::ClearFormDBRecordData(const int uid, std::map<int64_t, bool> &removedFormsMap)
{
    std::map<int64_t, bool> foundFormsMap;
    std::map<FormIdKey, std::set<int64_t>> noHostFormDbMap;
    FormDbCache::GetInstance().GetNoHostDBForms(uid, noHostFormDbMap, foundFormsMap);
    if (!foundFormsMap.empty()) {
        for (const auto &element : foundFormsMap) {
            FormDataMgr::GetInstance().DeleteFormUserUid(element.first, uid);
        }
    }

    HILOG_DEBUG("noHostFormDbMap size:%{public}zu", noHostFormDbMap.size());
    if (!noHostFormDbMap.empty()) {
        BatchDeleteNoHostDBForms(uid, noHostFormDbMap, foundFormsMap);
    }

    if (!foundFormsMap.empty()) {
        removedFormsMap.insert(foundFormsMap.begin(), foundFormsMap.end());
    }
}

void FormEventUtil::ClearTempFormRecordData(const int uid, std::map<int64_t, bool> &removedFormsMap)
{
    std::map<int64_t, bool> foundFormsMap;
    std::map<FormIdKey, std::set<int64_t>> noHostTempFormsMap;
    FormDataMgr::GetInstance().GetNoHostTempForms(uid, noHostTempFormsMap, foundFormsMap);
    HILOG_DEBUG("noHostTempFormsMap size:%{public}zu", noHostTempFormsMap.size());
    if (!noHostTempFormsMap.empty()) {
        BatchDeleteNoHostTempForms(uid, noHostTempFormsMap, foundFormsMap);
    }
    if (!foundFormsMap.empty()) {
        removedFormsMap.insert(foundFormsMap.begin(), foundFormsMap.end());
    }
}

void FormEventUtil::BatchDeleteNoHostTempForms(const int uid, std::map<FormIdKey,
    std::set<int64_t>> &noHostTempFormsMap, std::map<int64_t, bool> &foundFormsMap)
{
    for (const auto &element : noHostTempFormsMap) {
        std::set<int64_t> formIds = element.second;
        FormIdKey formIdKey = element.first;
        std::string bundleName = formIdKey.bundleName;
        std::string abilityName = formIdKey.abilityName;
        int32_t userId = FormUtil::GetCallerUserId(uid);
        int result = FormProviderMgr::GetInstance().NotifyProviderFormsBatchDelete(bundleName, abilityName, formIds,
            userId);
        if (result != ERR_OK) {
            HILOG_ERROR("NotifyProviderFormsBatchDelete fail bundle:%{public}s ability:%{public}s",
                bundleName.c_str(), abilityName.c_str());
            for (int64_t formId : formIds) {
                FormDataMgr::GetInstance().AddFormUserUid(formId, uid);
            }
        } else {
            for (int64_t formId : formIds) {
                foundFormsMap.emplace(formId, true);
                FormDataMgr::GetInstance().DeleteFormRecord(formId);
                FormDataMgr::GetInstance().DeleteTempForm(formId);
            }
        }
    }
}

void FormEventUtil::GetTimerCfg(const bool updateEnabled,
    const int updateDuration, const std::string &configUpdateAt, FormTimerCfg& cfg)
{
    HILOG_INFO("start");
    if (!updateEnabled) {
        HILOG_INFO("update disable");
        return;
    }

    if (updateDuration > 0) {
        // interval timer
        HILOG_INFO("interval timer updateDuration:%{public}d", updateDuration);
        if (updateDuration <= Constants::MIN_CONFIG_DURATION) {
            cfg.updateDuration = Constants::MIN_PERIOD;
        } else if (updateDuration >= Constants::MAX_CONFIG_DURATION) {
            cfg.updateDuration = Constants::MAX_PERIOD;
        } else {
            cfg.updateDuration = updateDuration * Constants::TIME_CONVERSION;
        }
        cfg.enableUpdate = true;
        return;
    } else {
        // updateAtTimer
        if (configUpdateAt.empty()) {
            HILOG_INFO("empty configUpdateAt");
            return;
        }
        HILOG_INFO("update at timer:%{public}s", configUpdateAt.c_str());
        std::vector<std::string> temp = FormUtil::StringSplit(configUpdateAt, Constants::TIME_DELIMETER);
        if (temp.size() != Constants::UPDATE_AT_CONFIG_COUNT) {
            HILOG_ERROR("invalid config");
            return;
        }
        int hour = FormUtil::ConvertStringToInt(temp[0]);
        int min = FormUtil::ConvertStringToInt(temp[1]);
        if (hour < Constants::MIN_TIME || hour > Constants::MAX_HOUR || min < Constants::MIN_TIME || min >
            Constants::MAX_MINUTE) {
            HILOG_ERROR("invalid time");
            return;
        }

        cfg.updateAtHour = hour;
        cfg.updateAtMin = min;
        cfg.enableUpdate = true;
        return;
    }
}

void FormEventUtil::SetTimerCfgByMultUpdate(const std::string &configMultUpdateAt, FormTimerCfg& cfg)
{
    if (configMultUpdateAt.empty()) {
        return;
    }
    std::vector<std::string> timeList = FormUtil::StringSplit(configMultUpdateAt, Constants::TIMES_DELIMETER);
    if (timeList.size() > Constants::UPDATE_AT_CONFIG_MAX_COUNT) {
        HILOG_ERROR("invalid config");
        return;
    }
    std::vector<std::vector<int>> updateAtTimes;
    for (const auto &time: timeList) {
        std::vector<std::string> temp = FormUtil::StringSplit(time, Constants::TIME_DELIMETER);
        if (temp.size() != Constants::UPDATE_AT_CONFIG_COUNT) {
            HILOG_ERROR("invalid config");
            continue;
        }
        int hour = FormUtil::ConvertStringToInt(temp[0]);
        int min = FormUtil::ConvertStringToInt(temp[1]);
        if (hour < Constants::MIN_TIME || hour > Constants::MAX_HOUR || min < Constants::MIN_TIME || min >
            Constants::MAX_MINUTE) {
            HILOG_ERROR("invalid time");
            continue;
        }
        std::vector<int> newElement = {hour, min};
        updateAtTimes.push_back(newElement);
    }
    if (updateAtTimes.size() > 0) {
        cfg.updateAtTimes = updateAtTimes;
        cfg.enableUpdate = true;
    }
}

void FormEventUtil::HandleAddMultiUpdateTimes(const int64_t formId,
    const FormRecord &record, const FormTimerCfg &timerCfg)
{
    std::vector<std::vector<int>> updateAtTimes = timerCfg.updateAtTimes;
    if (updateAtTimes.size() > 0) {
        for (const auto &time: updateAtTimes) {
            HILOG_INFO("add at timer:%{public}d,%{public}d", time[0], time[1]);
            FormTimerMgr::GetInstance().AddFormTimer(formId,
                time[0], time[1], record.providerUserId);
        }
    } else {
        HILOG_INFO("add at timer:%{public}d,%{public}d", timerCfg.updateAtHour, timerCfg.updateAtMin);
        FormTimerMgr::GetInstance().AddFormTimer(formId, timerCfg.updateAtHour,
            timerCfg.updateAtMin, record.providerUserId);
    }
}

void FormEventUtil::HandleTimerUpdate(const int64_t formId,
    const FormRecord &record, const FormTimerCfg &timerCfg)
{
    // both disable
    if (!record.isEnableUpdate && !timerCfg.enableUpdate) {
        return;
    }

    // enable to disable
    if (record.isEnableUpdate && !timerCfg.enableUpdate) {
        FormDataMgr::GetInstance().SetEnableUpdate(formId, false);
        FormTimerMgr::GetInstance().RemoveFormTimer(formId);
        return;
    }

    // disable to enable
    if (!record.isEnableUpdate && timerCfg.enableUpdate) {
        FormDataMgr::GetInstance().SetUpdateInfo(formId, true,
            timerCfg.updateDuration, timerCfg.updateAtHour, timerCfg.updateAtMin, timerCfg.updateAtTimes);
        if (timerCfg.updateDuration > 0) {
            HILOG_INFO("add interval timer:%{public}" PRId64, timerCfg.updateDuration);
            int64_t updateDuration = timerCfg.updateDuration;
            if (!FormMgrAdapter::GetInstance().GetValidFormUpdateDuration(formId, updateDuration)) {
                HILOG_WARN("Get updateDuration failed, uses local configuration");
            }
            FormTimerMgr::GetInstance().AddFormTimer(formId, updateDuration, record.providerUserId);
        } else {
            HandleAddMultiUpdateTimes(formId, record, timerCfg);
        }
        return;
    }

    // both enable
    UpdateType type = GetUpdateType(record, timerCfg);
    if (type == TYPE_NO_CHANGE) {
        return;
    }

    FormDataMgr::GetInstance().SetUpdateInfo(formId, true,
        timerCfg.updateDuration, timerCfg.updateAtHour, timerCfg.updateAtMin, timerCfg.updateAtTimes);
    auto newTimerCfg = timerCfg;
    if (type == TYPE_INTERVAL_CHANGE || type == TYPE_ATTIME_TO_INTERVAL) {
        int64_t updateDuration = timerCfg.updateDuration;
        if (!FormMgrAdapter::GetInstance().GetValidFormUpdateDuration(formId, updateDuration)) {
            HILOG_WARN("Get updateDuration failed, uses local configuration");
        }
        newTimerCfg.updateDuration = updateDuration;
    }
    FormTimerMgr::GetInstance().UpdateFormTimer(formId, type, newTimerCfg);
}

UpdateType FormEventUtil::GetUpdateType(const FormRecord &record, const FormTimerCfg &timerCfg)
{
    HILOG_DEBUG("call");
    if (record.updateDuration > 0) {
        if (timerCfg.updateDuration > 0) {
            // no change
            if (record.updateDuration == timerCfg.updateDuration) {
                return TYPE_NO_CHANGE;
            }
            // interval change
            return TYPE_INTERVAL_CHANGE;
        } else {
            // interval to update at time
            return TYPE_INTERVAL_TO_ATTIME;
        }
    } else {
        if (timerCfg.updateDuration > 0) {
            // update at time to interval
            return TYPE_ATTIME_TO_INTERVAL;
        } else {
            if (record.updateAtHour == timerCfg.updateAtHour && record.updateAtMin == timerCfg.updateAtMin
                && record.updateAtTimes == timerCfg.updateAtTimes) {
                return TYPE_NO_CHANGE;
            }
            // update at time change
            return TYPE_ATTIME_CHANGE;
        }
    }
}

void FormEventUtil::ReCreateForm(const int64_t formId)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    FormRecord record;
    bool isGetForm = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    if (!isGetForm) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 "", formId);
        return;
    }
    FormCacheMgr::GetInstance().DeleteData(formId);
    FormRecord reCreateRecord;
    reCreateRecord.bundleName = record.bundleName;
    reCreateRecord.abilityName = record.abilityName;
    reCreateRecord.formName = record.formName;
    reCreateRecord.specification = record.specification;
    reCreateRecord.formTempFlag = record.formTempFlag;
    reCreateRecord.isInited = record.isInited;
    reCreateRecord.versionUpgrade = record.versionUpgrade;
    reCreateRecord.isCountTimerRefresh = false;
    reCreateRecord.providerUserId = record.providerUserId;

    Want want;
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, reCreateRecord.formName);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, reCreateRecord.specification);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, reCreateRecord.formTempFlag);
    want.SetParam(Constants::RECREATE_FORM_KEY, true);
    want.SetParam(Constants::PARAM_FORM_RENDERINGMODE_KEY, (int)record.renderingMode);
    FormDataMgr::GetInstance().GetFormHostParams(formId, want);
    FormProviderMgr::GetInstance().ConnectAmsForRefresh(formId, reCreateRecord, want);
}

void FormEventUtil::BatchDeleteNoHostDBForms(const int uid, std::map<FormIdKey, std::set<int64_t>> &noHostFormDbMap,
    std::map<int64_t, bool> &removedFormsMap)
{
    std::set<FormIdKey> removableModuleSet;
    for (const auto &element: noHostFormDbMap) {
        std::set<int64_t> formIds = element.second;
        FormIdKey formIdKey = element.first;
        std::string bundleName = formIdKey.bundleName;
        std::string abilityName = formIdKey.abilityName;
        int32_t userId = FormUtil::GetCallerUserId(uid);
        int result = FormProviderMgr::GetInstance().NotifyProviderFormsBatchDelete(bundleName, abilityName, formIds,
            userId);
        if (result != ERR_OK) {
            HILOG_ERROR("NotifyProviderFormsBatchDelete fail bundle:%{public}s ability:%{public}s",
                bundleName.c_str(), abilityName.c_str());
            for (int64_t formId : formIds) {
                FormDBInfo dbInfo;
                int errCode = FormDbCache::GetInstance().GetDBRecord(formId, dbInfo);
                if (errCode == ERR_OK) {
                    dbInfo.formUserUids.emplace_back(uid);
                    FormDbCache::GetInstance().SaveFormInfo(dbInfo);
                }
            }
        } else {
            for (const int64_t formId : formIds) {
                removedFormsMap.emplace(formId, true);
                FormDBInfo dbInfo;
                int errCode = FormDbCache::GetInstance().GetDBRecord(formId, dbInfo);
                if (errCode == ERR_OK) {
                    FormIdKey removableModuleFormIdKey(dbInfo.bundleName, dbInfo.moduleName);
                    removableModuleSet.emplace(removableModuleFormIdKey);
                    FormDbCache::GetInstance().DeleteFormInfo(formId);
                }
                FormDataMgr::GetInstance().DeleteFormRecord(formId);
            }
        }
    }

    for (const FormIdKey &item : removableModuleSet) {
        int32_t matchCount = FormDbCache::GetInstance().GetMatchCount(item.bundleName, item.moduleName);
        if (matchCount == 0) {
            FormBmsHelper::GetInstance().NotifyModuleRemovable(item.bundleName, item.moduleName);
        }
    }
}

bool FormEventUtil::HandleAdditionalInfoChanged(const std::string &bundleName)
{
    HILOG_DEBUG("Call, bundleName:%{public}s", bundleName.c_str());
    FormMgrAdapter::GetInstance().UpdateFormCloudUpdateDuration(bundleName);
    std::vector<FormRecord> formInfos;
    if (!FormDataMgr::GetInstance().GetFormRecord(bundleName, formInfos)) {
        HILOG_DEBUG("No form info");
        return false;
    }

    for (const auto& formRecord : formInfos) {
        if (!formRecord.isEnableUpdate || (formRecord.updateDuration <= 0)) {
            continue;
        }
        int64_t updateDuration = formRecord.updateDuration;
        if (!FormMgrAdapter::GetInstance().GetValidFormUpdateDuration(formRecord.formId, updateDuration)) {
            HILOG_WARN("Get updateDuration failed, uses local configuration");
        }

        FormTimerCfg timerCfg;
        timerCfg.enableUpdate = true;
        timerCfg.updateDuration = updateDuration;
        FormTimerMgr::GetInstance().UpdateFormTimer(formRecord.formId, UpdateType::TYPE_INTERVAL_CHANGE, timerCfg);
    }
    return true;
}


void FormEventUtil::UpdateMultiUpdateTime(std::string multiScheduledUpdateTime, FormRecord &formRecord)
{
    std::vector<std::string> timeList = FormUtil::StringSplit(multiScheduledUpdateTime,
        Constants::TIMES_DELIMETER);
    if (timeList.size() > Constants::UPDATE_AT_CONFIG_MAX_COUNT) {
        HILOG_ERROR("invalid config");
        return;
    }

    std::vector<std::vector<int>> updateAtTimes;
    for (const auto &time: timeList) {
        HILOG_INFO("UpdateFormRecord add  updateAtTimes");
        std::vector<std::string> temp = FormUtil::StringSplit(time, Constants::TIME_DELIMETER);
        if (temp.size() != Constants::UPDATE_AT_CONFIG_COUNT) {
            HILOG_ERROR("invalid config");
            continue;
        }
        int hour = FormUtil::ConvertStringToInt(temp[0]);
        int min = FormUtil::ConvertStringToInt(temp[1]);
        if (hour < Constants::MIN_TIME || hour > Constants::MAX_HOUR || min < Constants::MIN_TIME || min >
            Constants::MAX_MINUTE) {
            HILOG_ERROR("invalid time");
            continue;
        }
        std::vector<int> newElement = {hour, min};
        updateAtTimes.push_back(newElement);
    }
    if (updateAtTimes.size() > 0) {
        formRecord.updateAtTimes = updateAtTimes;
    }
}

void FormEventUtil::UpdateFormRecord(const FormInfo &formInfo, FormRecord &formRecord)
{
    formRecord.formSrc = formInfo.src;
    formRecord.uiSyntax = formInfo.uiSyntax;
    formRecord.isDynamic = formInfo.isDynamic;
    formRecord.transparencyEnabled = formInfo.transparencyEnabled;
    formRecord.privacyLevel = formInfo.privacyLevel;
    formRecord.isEnableUpdate = formInfo.updateEnabled;
    formRecord.updateDuration = formInfo.updateDuration * Constants::TIME_CONVERSION;
    std::vector<std::string> time = FormUtil::StringSplit(formInfo.scheduledUpdateTime, Constants::TIME_DELIMETER);
    if (time.size() == Constants::UPDATE_AT_CONFIG_COUNT) {
        formRecord.updateAtHour = FormUtil::ConvertStringToInt(time[0]);
        formRecord.updateAtMin = FormUtil::ConvertStringToInt(time[1]);
    }
    std::string multiScheduledUpdateTime_ = formInfo.multiScheduledUpdateTime;
    if (!multiScheduledUpdateTime_.empty()) {
        UpdateMultiUpdateTime(multiScheduledUpdateTime_, formRecord);
    }
    FormUpgradeInfo oldFormUpgradeInfo;
    FormDataMgr::GetInstance().GetFormUpgradeInfo(formRecord.formId, oldFormUpgradeInfo);
    oldFormUpgradeInfo.enableBlurBackground = formInfo.enableBlurBackground;
    formRecord.formUpgradeInfo = oldFormUpgradeInfo;
    HILOG_DEBUG("formId:%{public}" PRId64 "", formRecord.formId);
    FormDataMgr::GetInstance().UpdateFormRecord(formRecord.formId, formRecord);
}

void FormEventUtil::UpdateFormRecord(const AbilityFormInfo &formInfo, FormRecord &formRecord)
{
    formRecord.uiSyntax = (formInfo.type.compare("arkts") == 0 ? FormType::ETS : FormType::JS);
    formRecord.isEnableUpdate = formInfo.updateEnabled;
    formRecord.updateDuration = formInfo.updateDuration * Constants::TIME_CONVERSION;
    std::vector<std::string> time = FormUtil::StringSplit(formInfo.scheduledUpdateTime, Constants::TIME_DELIMETER);
    if (time.size() == Constants::UPDATE_AT_CONFIG_COUNT) {
        formRecord.updateAtHour = FormUtil::ConvertStringToInt(time[0]);
        formRecord.updateAtMin = FormUtil::ConvertStringToInt(time[1]);
    }
    std::string multiScheduledUpdateTime_ = formInfo.multiScheduledUpdateTime;
    if (!multiScheduledUpdateTime_.empty()) {
        UpdateMultiUpdateTime(multiScheduledUpdateTime_, formRecord);
    }
    HILOG_DEBUG("formId:%{public}" PRId64 "", formRecord.formId);
    FormDataMgr::GetInstance().UpdateFormRecord(formRecord.formId, formRecord);
}

void FormEventUtil::HandleProviderUpdatedDetail(const std::vector<int64_t> &removedForms,
    const std::vector<FormRecord> &updatedForms, const std::string &bundleName,
    const int userId, const bool needReload)
{
    if (!removedForms.empty()) {
        HILOG_INFO("clean removed forms and timer");
        FormDataMgr::GetInstance().CleanHostRemovedForms(removedForms);
        for (const int64_t id : removedForms) {
            FormTimerMgr::GetInstance().RemoveFormTimer(id);
        }
    }
    ParamControl::GetInstance().ReloadDueControlByAppUpgrade(updatedForms);
    HandleFormReload(bundleName, userId, needReload, updatedForms);
}
} // namespace AppExecFwk
} // namespace OHOS
