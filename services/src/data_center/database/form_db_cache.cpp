/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "data_center/database/form_db_cache.h"

#include <cinttypes>

#include "fms_log_wrapper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_data_mgr.h"
#include "data_center/database/form_db_info.h"
#include "form_mgr_errors.h"
#include "form_provider/form_provider_mgr.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {
FormDbCache::FormDbCache()
{
    HILOG_INFO("create");
}

FormDbCache::~FormDbCache()
{
    HILOG_INFO("destroy");
}

/**
 * @brief Load form data from DB to DbCache when starting.
 * @return Void.
 */
void FormDbCache::Start()
{
    std::vector<InnerFormInfo> innerFormInfos;
    innerFormInfos.clear();
    if (FormInfoRdbStorageMgr::GetInstance().LoadFormData(innerFormInfos) != ERR_OK) {
        HILOG_ERROR("LoadFormData failed");
        return;
    }
    HILOG_INFO("load form data, size: %{public}zu", innerFormInfos.size());
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (unsigned int i = 0; i < innerFormInfos.size(); i++) {
        FormDBInfo formDBInfo = innerFormInfos.at(i).GetFormDBInfo();
        formDBInfos_.emplace_back(formDBInfo);
    }
}

/**
 * @brief Save or update form data to DbCache and DB.
 * @param formDBInfo Form data.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDbCache::SaveFormInfo(const FormDBInfo &formDBInfo)
{
    HILOG_INFO("formId:%{public}" PRId64, formDBInfo.formId);
    FormDBInfo tmpInfo;
    if (FindAndSaveFormDBInfoCache(formDBInfo, tmpInfo)) {
        if (tmpInfo.Compare(formDBInfo) == false) {
            HILOG_WARN("need update, formId[%{public}" PRId64 "]", formDBInfo.formId);
            InnerFormInfo innerFormInfo(formDBInfo);
            return FormInfoRdbStorageMgr::GetInstance().ModifyStorageFormData(innerFormInfo);
        } else {
            HILOG_WARN("already exist, formId[%{public}" PRId64 "].", formDBInfo.formId);
            return ERR_OK;
        }
    } else {
        InnerFormInfo innerFormInfo(formDBInfo);
        return FormInfoRdbStorageMgr::GetInstance().SaveStorageFormData(innerFormInfo);
    }
}

/**
 * @brief Save or update form data to DbCache and DB.
 * @param formDBInfo Form data.
 * @return Returns ERR_OK on success, others on failure.(NoLock)
 */
ErrCode FormDbCache::SaveFormInfoNolock(const FormDBInfo &formDBInfo)
{
    HILOG_INFO("formId:%{public}" PRId64, formDBInfo.formId);
    auto iter = find(formDBInfos_.begin(), formDBInfos_.end(), formDBInfo);
    if (iter != formDBInfos_.end()) {
        if (iter->Compare(formDBInfo) == false) {
            HILOG_WARN("need update, formId[%{public}" PRId64 "].", formDBInfo.formId);
            *iter = formDBInfo;
            InnerFormInfo innerFormInfo(formDBInfo);
            return FormInfoRdbStorageMgr::GetInstance().ModifyStorageFormData(innerFormInfo);
        } else {
            HILOG_WARN("already exist, formId[%{public}" PRId64 "].", formDBInfo.formId);
            return ERR_OK;
        }
    } else {
        formDBInfos_.emplace_back(formDBInfo);
        InnerFormInfo innerFormInfo(formDBInfo);
        return FormInfoRdbStorageMgr::GetInstance().SaveStorageFormData(innerFormInfo);
    }
}

/**
 * @brief Delete form data in DbCache and DB with formId.
 * @param formId form data Id.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDbCache::DeleteFormInfo(int64_t formId)
{
    HILOG_INFO("form: %{public}" PRId64, formId);
    DeleteFormDBInfoCache(formId);
    if (FormInfoRdbStorageMgr::GetInstance().DeleteStorageFormData(std::to_string(formId)) == ERR_OK) {
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}
/**
 * @brief Delete form data in DbCache and DB with formId.
 * @param formId form data Id.
 * @param removedDBForms Removed db form infos
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDbCache::DeleteFormInfoByBundleName(const std::string &bundleName, const int32_t userId,
    std::vector<FormDBInfo> &removedDBForms)
{
    HILOG_INFO("bundleName: %{public}s", bundleName.c_str());
    GetFormDBInfoCacheByBundleName(bundleName, userId, removedDBForms);

    for (auto iter = removedDBForms.begin(); iter != removedDBForms.end();) {
        if (FormInfoRdbStorageMgr::GetInstance().DeleteStorageFormData(std::to_string(iter->formId)) == ERR_OK) {
            DeleteFormDBInfoCache(iter->formId);
            iter++;
        } else {
            HILOG_WARN("delete storage form data failed, formId:%{public}" PRId64, iter->formId);
            iter = removedDBForms.erase(iter);
        }
    }
    return ERR_OK;
}

/**
 * @brief Get all form data from DbCache.
 * @param formDBInfos Storage all DbCache.
 * @return Void.
 */
void FormDbCache::GetAllFormInfo(std::vector<FormDBInfo> &formDBInfos)
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    formDBInfos = formDBInfos_;
}

/**
 * @brief Get all location data from DbCache.
 * @param locationMap all location data map
 */
void FormDbCache::GetLocationMap(std::map<Constants::FormLocation, int> &locationMap)
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (const auto& dbInfo : formDBInfos_) {
        if (locationMap.count(dbInfo.formLocation) == 0) {
            locationMap[dbInfo.formLocation] = 1;
        } else {
            ++locationMap[dbInfo.formLocation];
        }
    }
}

/**
 * @brief Get all form data in DbCache and DB by bundleName.
 * @param bundleName BundleName.
 * @param userId user ID.
 * @param formDBInfos all db form infos
 */
void FormDbCache::GetAllFormDBInfoByBundleName(const std::string &bundleName, const int32_t userId,
    std::vector<FormDBInfo> &formDBInfos)
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (auto dbInfo : formDBInfos_) {
        if (bundleName == dbInfo.bundleName && dbInfo.userId == userId) {
            formDBInfos.push_back(dbInfo);
        }
    }
}

/**
 * @brief Get record from DB cache with formId
 * @param formId Form data Id
 * @param record Form data
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDbCache::GetDBRecord(const int64_t formId, FormRecord &record) const
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (const FormDBInfo &dbInfo : formDBInfos_) {
        if (dbInfo.formId == formId) {
            record.userId = dbInfo.userId;
            record.providerUserId= dbInfo.providerUserId;
            record.formName = dbInfo.formName;
            record.bundleName = dbInfo.bundleName;
            record.moduleName = dbInfo.moduleName;
            record.abilityName = dbInfo.abilityName;
            record.formUserUids = dbInfo.formUserUids;
            record.formLocation = dbInfo.formLocation;
            record.enableForm = dbInfo.enableForm;
            record.lockForm = dbInfo.lockForm;
            return ERR_OK;
        }
    }
    HILOG_ERROR("not find formId[%{public}" PRId64 "]", formId);
    return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
}
/**
 * @brief Get record from DB cache with formId
 * @param formId Form data Id
 * @param record Form db data
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDbCache::GetDBRecord(const int64_t formId, FormDBInfo &record) const
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (const FormDBInfo &dbInfo : formDBInfos_) {
        if (dbInfo.formId == formId) {
            record = dbInfo;
            return ERR_OK;
        }
    }
    HILOG_ERROR("not find formId[%{public}" PRId64 "]", formId);
    return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
}
/**
 * @brief Use record save or update DB data and DB cache with formId
 * @param formId Form data Id
 * @param record Form data
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDbCache::UpdateDBRecord(const int64_t formId, const FormRecord &record) const
{
    FormDBInfo formDBInfo(formId, record);
    return FormDbCache::GetInstance().SaveFormInfo(formDBInfo);
}
/**
 * @brief Get no host db record.
 * @param uid The caller uid.
 * @param noHostFormDBList no host db record list.
 * @param foundFormsMap Form Id list.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDbCache::GetNoHostDBForms(const int uid, std::map<FormIdKey,
    std::set<int64_t>> &noHostFormDBList, std::map<int64_t, bool> &foundFormsMap)
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (FormDBInfo& dbInfo : formDBInfos_) {
        if (dbInfo.Contains(uid)) {
            dbInfo.Remove(uid);
            if (dbInfo.formUserUids.empty()) {
                FormIdKey formIdKey(dbInfo.bundleName, dbInfo.abilityName);
                auto itIdsSet = noHostFormDBList.find(formIdKey);
                if (itIdsSet == noHostFormDBList.end()) {
                    std::set<int64_t> formIdsSet;
                    formIdsSet.emplace(dbInfo.formId);
                    noHostFormDBList.emplace(formIdKey, formIdsSet);
                } else {
                    itIdsSet->second.emplace(dbInfo.formId);
                }
            } else {
                foundFormsMap.emplace(dbInfo.formId, false);
                SaveFormInfoNolock(dbInfo);
                FormBmsHelper::GetInstance().NotifyModuleNotRemovable(dbInfo.bundleName, dbInfo.moduleName);
            }
        }
    }
    return ERR_OK;
}
/**
 * @brief Get match count by bundleName and moduleName.
 * @param bundleName BundleName.
 * @param moduleName ModuleName.
 * @return Returns match count.
 */
int FormDbCache::GetMatchCount(const std::string &bundleName, const std::string &moduleName)
{
    int32_t matchCount = 0;
    std::vector<FormDBInfo> formDBInfos;
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (const FormDBInfo &dbInfo : formDBInfos_) {
        if (dbInfo.bundleName == bundleName && dbInfo.moduleName == moduleName) {
            ++matchCount;
        }
    }
    return matchCount;
}
/**
 * @brief delete forms bu userId.
 *
 * @param userId user ID.
 */
void FormDbCache::DeleteDBFormsByUserId(const int32_t userId)
{
    HILOG_INFO("userId: %{public}d", userId);
    std::vector<FormDBInfo> removedDBForms;
    GetFormDBInfoCacheByUserId(userId, removedDBForms);
    for (auto &info : removedDBForms) {
        if (FormInfoRdbStorageMgr::GetInstance().DeleteStorageFormData(std::to_string(info.formId)) == ERR_OK) {
            DeleteFormDBInfoCache(info.formId);
        } else {
            HILOG_ERROR("fail delete form, formId[%{public}" PRId64 "]", info.formId);
        }
    }
}

/**
 * @brief handle get no host invalid DB forms.
 * @param userId User ID.
 * @param callingUid The UID of the proxy.
 * @param matchedFormIds The set of the valid forms.
 * @param noHostDBFormsMap The map of the no host forms.
 * @param foundFormsMap The map of the found forms.
 */
void FormDbCache::GetNoHostInvalidDBForms(int32_t userId, int32_t callingUid, std::set<int64_t> &matchedFormIds,
                                          std::map<FormIdKey, std::set<int64_t>> &noHostDBFormsMap,
                                          std::map<int64_t, bool> &foundFormsMap)
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (auto &formRecord: formDBInfos_) {
        int64_t formId = formRecord.formId;
        // check UID
        auto iter = std::find(formRecord.formUserUids.begin(), formRecord.formUserUids.end(), callingUid);
        if (iter == formRecord.formUserUids.end()) {
            continue;
        }
        // check valid form set
        if (matchedFormIds.find(formId) != matchedFormIds.end()) {
            continue;
        }
        // checks if the form provider is the currently active user.
        if (formRecord.providerUserId != userId) {
            continue;
        }

        HILOG_WARN("found invalid form:%{public}" PRId64, formId);
        formRecord.formUserUids.erase(iter);
        if (formRecord.formUserUids.empty()) {
            FormIdKey formIdKey(formRecord.bundleName, formRecord.abilityName);
            auto itIdsSet = noHostDBFormsMap.find(formIdKey);
            if (itIdsSet == noHostDBFormsMap.end()) {
                std::set<int64_t> formIdsSet;
                formIdsSet.emplace(formId);
                noHostDBFormsMap.emplace(formIdKey, formIdsSet);
            } else {
                itIdsSet->second.emplace(formId);
            }
        } else {
            foundFormsMap.emplace(formId, false);
            SaveFormInfoNolock(formRecord);
            FormBmsHelper::GetInstance().NotifyModuleNotRemovable(formRecord.bundleName, formRecord.moduleName);
        }
    }
}

/**
 * @brief handle delete no host DB forms.
 * @param callingUid The UID of the proxy.
 * @param noHostFormDbMap The map of the no host forms.
 * @param foundFormsMap The map of the found forms.
 */
void FormDbCache::BatchDeleteNoHostDBForms(int32_t callingUid, std::map<FormIdKey, std::set<int64_t>> &noHostDBFormsMap,
                                           std::map<int64_t, bool> &foundFormsMap)
{
    std::set<FormIdKey> removableModuleSet;
    for (auto &element : noHostDBFormsMap) {
        std::set<int64_t> &formIds = element.second;
        FormIdKey formIdKey = element.first;
        std::string bundleName = formIdKey.bundleName;
        std::string abilityName = formIdKey.abilityName;
        FormProviderMgr::GetInstance().NotifyProviderFormsBatchDelete(bundleName, abilityName, formIds);
        for (const int64_t formId : formIds) {
            foundFormsMap.emplace(formId, true);
            FormDBInfo dbInfo;
            int errCode = GetDBRecord(formId, dbInfo);
            if (errCode == ERR_OK) {
                FormIdKey removableModuleFormIdKey(dbInfo.bundleName, dbInfo.moduleName);
                removableModuleSet.emplace(removableModuleFormIdKey);
                DeleteFormInfo(formId);
            }
            FormDataMgr::GetInstance().StopRenderingForm(formId);
            FormDataMgr::GetInstance().DeleteFormRecord(formId);
        }
    }

    for (const FormIdKey &item : removableModuleSet) {
        int32_t matchCount = GetMatchCount(item.bundleName, item.moduleName);
        if (matchCount == 0) {
            FormBmsHelper::GetInstance().NotifyModuleRemovable(item.bundleName, item.moduleName);
        }
    }
}

/**
 * @brief handle delete invalid DB forms.
 * @param userId User ID.
 * @param callingUid The UID of the proxy.
 * @param matchedFormIds The set of the valid forms.
 * @param removedFormsMap The map of the removed invalid forms.
 * @return Returns ERR_OK on success, others on failure.
 */
ErrCode FormDbCache::DeleteInvalidDBForms(int32_t userId, int32_t callingUid, std::set<int64_t> &matchedFormIds,
                                          std::map<int64_t, bool> &removedFormsMap)
{
    HILOG_INFO("userId:%{public}d, callingUid:%{public}d", userId, callingUid);
    std::map<int64_t, bool> foundFormsMap {};
    std::map<FormIdKey, std::set<int64_t>> noHostDBFormsMap {};

    GetNoHostInvalidDBForms(userId, callingUid, matchedFormIds, noHostDBFormsMap, foundFormsMap);

    if (!foundFormsMap.empty()) {
        for (const auto &element : foundFormsMap) {
            FormDataMgr::GetInstance().DeleteFormUserUid(element.first, callingUid);
        }
    }

    BatchDeleteNoHostDBForms(callingUid, noHostDBFormsMap, foundFormsMap);
    HILOG_DEBUG("foundFormsMap size:%{public}zu", foundFormsMap.size());
    HILOG_DEBUG("noHostDBFormsMap size:%{public}zu", noHostDBFormsMap.size());

    if (!foundFormsMap.empty()) {
        removedFormsMap.insert(foundFormsMap.begin(), foundFormsMap.end());
#ifdef THEME_MGR_ENABLE
        DeleteThemeForms(removedFormsMap);
#endif
    }

    HILOG_INFO("done");
    return ERR_OK;
}

#ifdef THEME_MGR_ENABLE
void FormDbCache::DeleteThemeForms(std::map<int64_t, bool> &removedFormsMap)
{
    HILOG_INFO("call");
    std::vector<int64_t> removeList;
    for (const auto &element : removedFormsMap) {
        FormDBInfo dbInfo;
        ErrCode getDbRet = FormDbCache::GetInstance().GetDBRecord(element.first, dbInfo);
        HILOG_INFO("getDbRet:%{public}d, isThemeForm:%{public}d", getDbRet, dbInfo.isThemeForm);
        if (getDbRet == ERR_OK && dbInfo.isThemeForm) {
            removeList.emplace_back(element.first);
        }
    }
    if (!removeList.empty()) {
        ThemeManager::ThemeManagerClient::GetInstance().DeleteForm(removeList);
    }
}
#endif

bool FormDbCache::IsHostOwner(int64_t formId, int32_t hostUid)
{
    FormDBInfo dbInfo;
    if (GetDBRecord(formId, dbInfo) != ERR_OK) {
        HILOG_ERROR("get db record failed. formId:%{public}s", std::to_string(formId).c_str());
        return false;
    }

    auto iter = std::find(dbInfo.formUserUids.begin(), dbInfo.formUserUids.end(), hostUid);
    if (iter != dbInfo.formUserUids.end()) {
        return true;
    }

    return false;
}

ErrCode FormDbCache::UpdateFormLocation(const int64_t formId, const int32_t formLocation)
{
    FormDBInfo dbInfo;
    if (FindAndUpdateFormLocation(formId, formLocation, dbInfo)) {
        InnerFormInfo innerFormInfo(dbInfo);
        return FormInfoRdbStorageMgr::GetInstance().ModifyStorageFormData(innerFormInfo);
    }
    return ERR_APPEXECFWK_FORM_INVALID_FORM_ID;
}

/**
 * @brief Get form counts from DbCache by calling user id.
 * @param currentAccountId current account ID.
 * @param callingUid calling user ID.
 * @return Returns form counts.
 */
int FormDbCache::GetFormCountsByCallingUid(const int32_t currentAccountId, const int callingUid)
{
    int callingUidFormCounts = 0;
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (const auto &record : formDBInfos_) {
        if (record.providerUserId != currentAccountId) {
            continue;
        }
        for (const auto &userUid : record.formUserUids) {
            if (userUid != callingUid) {
                continue;
            }
            callingUidFormCounts++;
        }
    }
    return callingUidFormCounts;
}

/**
 * @brief Get all form data size from DbCache.
 * @return Returns form data size.
 */
int32_t FormDbCache::GetAllFormInfoSize()
{
    HILOG_INFO("call");
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    return static_cast<int32_t>(formDBInfos_.size());
}

uint32_t FormDbCache::GetMultiAppFormVersionCode(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(multiAppFormVersionCodeMutex_);
    auto iter = multiAppFormVersionCodeMap_.find(bundleName);
    if (iter != multiAppFormVersionCodeMap_.end()) {
        return iter->second;
    }
    std::string versionCode;
    if (FormInfoRdbStorageMgr::GetInstance().GetMultiAppFormVersionCode(bundleName, versionCode) != ERR_OK ||
        versionCode.empty()) {
        return 0;
    }
    uint32_t code = static_cast<uint32_t>(FormUtil::ConvertStringToInt(versionCode));
    multiAppFormVersionCodeMap_.emplace(bundleName, code);
    return code;
}

void FormDbCache::UpdateMultiAppFormVersionCode(const std::string &bundleName, uint32_t versionCode)
{
    std::lock_guard<std::mutex> lock(multiAppFormVersionCodeMutex_);
    auto iter = multiAppFormVersionCodeMap_.find(bundleName);
    if (iter != multiAppFormVersionCodeMap_.end() && iter->second == versionCode) {
        return;
    }
    multiAppFormVersionCodeMap_[bundleName] = versionCode;
    FormInfoRdbStorageMgr::GetInstance().UpdateMultiAppFormVersionCode(bundleName, std::to_string(versionCode));
}

void FormDbCache::DeleteFormDBInfoCache(int64_t formId)
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    FormDBInfo tmpForm;
    tmpForm.formId = formId;
    auto iter = find(formDBInfos_.begin(), formDBInfos_.end(), tmpForm);
    if (iter == formDBInfos_.end()) {
        HILOG_WARN("not find form:%{public}" PRId64, formId);
    } else {
        formDBInfos_.erase(iter);
    }
}

bool FormDbCache::FindAndSaveFormDBInfoCache(const FormDBInfo &formDBInfo, FormDBInfo &findInfo)
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    auto iter = find(formDBInfos_.begin(), formDBInfos_.end(), formDBInfo);
    if (iter != formDBInfos_.end()) {
        findInfo = *iter;
        if (iter->Compare(formDBInfo) == false) {
            *iter = formDBInfo;
        }
        return true;
    }
    formDBInfos_.emplace_back(formDBInfo);
    return false;
}

bool FormDbCache::FindAndUpdateFormLocation(int64_t formId, int32_t formLocation, FormDBInfo &findInfo)
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    FormDBInfo tmpForm;
    tmpForm.formId = formId;
    auto iter = find(formDBInfos_.begin(), formDBInfos_.end(), tmpForm);
    if (iter != formDBInfos_.end()) {
        findInfo = *iter;
        iter->formLocation = static_cast<Constants::FormLocation>(formLocation);
        return true;
    }
    return false;
}

void FormDbCache::GetFormDBInfoCacheByBundleName(const std::string &bundleName, const int32_t providerUserId,
    std::vector<FormDBInfo> &dbFormInfos)
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (const auto &info : formDBInfos_) {
        if ((bundleName == info.bundleName) && (providerUserId == info.providerUserId)) {
            dbFormInfos.emplace_back(info);
        }
    }
}

void FormDbCache::GetFormDBInfoCacheByUserId(const int32_t providerUserId, std::vector<FormDBInfo> &dbFormInfos)
{
    std::lock_guard<std::mutex> lock(formDBInfosMutex_);
    for (const auto &info : formDBInfos_) {
        if (providerUserId == info.providerUserId) {
            dbFormInfos.emplace_back(info);
        }
    }
}
} // namespace AppExecFwk
} // namespace OHOS
