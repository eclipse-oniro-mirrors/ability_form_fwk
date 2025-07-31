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

#ifndef OHOS_FORM_FWK_FORM_DB_CACHE_H
#define OHOS_FORM_FWK_FORM_DB_CACHE_H

#include <mutex>
#include <set>
#include <singleton.h>
#include <vector>

#include "common/util/form_id_key.h"
#include "data_center/form_record/form_record.h"
#include "data_center/form_info/form_info_rdb_storage_mgr.h"
#ifdef THEME_MGR_ENABLE
#include "theme_manager_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
class FormDbCache final : public DelayedRefSingleton<FormDbCache> {
DECLARE_DELAYED_REF_SINGLETON(FormDbCache)
public:
    DISALLOW_COPY_AND_MOVE(FormDbCache);

    /**
     * @brief Load form data from DB to DbCache when starting.
     */
    void Start();

    /**
     * @brief Get all form data from DbCache.
     * @param formDBInfos Storage all DbCache.
     */
    void GetAllFormInfo(std::vector<FormDBInfo> &formDBInfos);

    /**
     * @brief Get all form data size from DbCache.
     * @return Returns form data size.
     */
    int32_t GetAllFormInfoSize();

    /**
     * @brief Get form counts from DbCache by calling user id.
     * @param currentAccountId current account ID.
     * @param callingUid calling user ID.
     * @return Returns form counts.
     */
    int GetFormCountsByCallingUid(const int32_t currentAccountId, const int callingUid);

    /**
     * @brief Get all form data in DbCache and DB by bundleName.
     * @param bundleName BundleName.
     * @param userId user ID.
     * @param formDBInfos all db form infos
     */
    void GetAllFormDBInfoByBundleName(const std::string &bundleName, const int32_t userId,
        std::vector<FormDBInfo> &formDBInfos);

    /**
     * @brief Save or update form data to DbCache and DB.
     * @param formDBInfo Form data.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode SaveFormInfo(const FormDBInfo &formDBInfo);

    /**
     * @brief Delete form data in DbCache and DB with formId.
     * @param formId form data Id.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteFormInfo(int64_t formId);

    /**
     * @brief Get record from DB cache with formId
     * @param formId Form data Id
     * @param record Form data
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetDBRecord(const int64_t formId, FormRecord &record) const;

    /**
     * @brief Get record from DB cache with formId
     * @param formId Form data Id
     * @param record Form db data
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetDBRecord(const int64_t formId, FormDBInfo &record) const;

    /**
     * @brief Use record save or update DB data and DB cache with formId
     * @param formId Form data Id
     * @param record Form data
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateDBRecord(const int64_t formId, const FormRecord &record) const;

    /**
     * @brief Delete form data in DbCache and DB with formId.
     * @param bundleName BundleName.
     * @param userId user ID.
     * @param removedDBForms Removed db form infos
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteFormInfoByBundleName(const std::string &bundleName, const int32_t userId,
        std::vector<FormDBInfo> &removedDBForms);

    /**
     * @brief Get no host db record.
     * @param uid The caller uid.
     * @param noHostFormDBList no host db record list.
     * @param foundFormsMap Form Id list.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode GetNoHostDBForms(const int uid, std::map<FormIdKey, std::set<int64_t>> &noHostFormDBList,
        std::map<int64_t, bool> &foundFormsMap);

    /**
     * @brief Get match count by bundleName and moduleName.
     * @param bundleName BundleName.
     * @param moduleName ModuleName.
     * @return Returns match count.
     */
    int GetMatchCount(const std::string &bundleName, const std::string &moduleName);

    /**
     * @brief delete forms bu userId.
     * @param userId user ID.
     */
    void DeleteDBFormsByUserId(const int32_t userId);

    /**
     * @brief handle get no host invalid DB forms.
     * @param userId User ID.
     * @param callingUid The UID of the proxy.
     * @param matchedFormIds The set of the valid forms.
     * @param noHostDBFormsMap The map of the no host forms.
     * @param foundFormsMap The map of the found forms.
     */
    void GetNoHostInvalidDBForms(int32_t userId, int32_t callingUid, std::set<int64_t> &matchedFormIds,
                                 std::map<FormIdKey, std::set<int64_t>> &noHostDBFormsMap,
                                 std::map<int64_t, bool> &foundFormsMap);

    /**
     * @brief handle delete no host DB forms.
     * @param callingUid The UID of the proxy.
     * @param noHostDBFormsMap The map of the no host forms.
     * @param foundFormsMap The map of the found forms.
     */
    void BatchDeleteNoHostDBForms(int32_t callingUid, std::map<FormIdKey, std::set<int64_t>> &noHostDBFormsMap,
                                  std::map<int64_t, bool> &foundFormsMap);

    /**
     * @brief handle delete invalid DB forms.
     * @param userId User ID.
     * @param callingUid The UID of the proxy.
     * @param matchedFormIds The set of the valid forms.
     * @param removedFormsMap The map of the removed invalid forms.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode DeleteInvalidDBForms(int32_t userId, int32_t callingUid, std::set<int64_t> &matchedFormIds,
                                 std::map<int64_t, bool> &removedFormsMap);

    bool IsHostOwner(int64_t formId, int32_t hostUid);

    /**
     * @brief Update form location.
     * @param formId The Id of the form.
     * @param formLocation The form location.
     * @return Returns ERR_OK on success, others on failure.
     */
    ErrCode UpdateFormLocation(const int64_t formId, const int32_t formLocation);

    /**
     * @brief Get multi app version code of form from DB.
     * @param bundleName Bundlename.
     * @return Returns version code.
     */
    uint32_t GetMultiAppFormVersionCode(const std::string &bundleName);

    /**
     * @brief Save or update the multi app version code of form in DB.
     * @param bundleName Bundlename.
     * @param versionCode version code.
     */
    void UpdateMultiAppFormVersionCode(const std::string &bundleName, uint32_t versionCode);
private:
    /**
     * @brief Save or update form data to DbCache and DB.
     * @param formDBInfo Form data.
     * @return Returns ERR_OK on success, others on failure.(NoLock)
     */
    ErrCode SaveFormInfoNolock(const FormDBInfo &formDBInfo);

#ifdef THEME_MGR_ENABLE
    /**
     * @brief Call ThemeManager to delete form.
     * @param removedFormsMap Indicates the map of forms to be delete.
     */
    void DeleteThemeForms(std::map<int64_t, bool> &removedFormsMap);
#endif
    mutable std::mutex formDBInfosMutex_;
    std::vector<FormDBInfo> formDBInfos_;
    mutable std::mutex multiAppFormVersionCodeMutex_;
    std::map<std::string, uint32_t> multiAppFormVersionCodeMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_DB_CACHE_H
