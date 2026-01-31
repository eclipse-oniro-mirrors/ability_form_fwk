/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_FORM_CACHE_MGR_H
#define OHOS_FORM_FWK_FORM_CACHE_MGR_H

#include <map>
#include <mutex>
#include <singleton.h>
#include <string>
#include <unordered_set>

#include "form_provider_data.h"
#include "data_center/database/form_rdb_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
enum class CacheState {
    DEFAULT = 0,
    REBOOT = 1,
};
struct FormCache {
    std::string formId;
    std::string dataCache;
    std::string imgCache;
    CacheState cacheState = CacheState::DEFAULT;
};
/**
 * @class FormCacheMgr
 * Form cache data manager.
 */
class FormCacheMgr final : public DelayedRefSingleton<FormCacheMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormCacheMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormCacheMgr);

    void Start();

    bool AddData(int64_t formId, const FormProviderData &formProviderData);

    bool DeleteData(int64_t formId);

    bool GetData(int64_t formId, std::string &data,
        std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap) const;

    bool NeedAcquireProviderData(int64_t formId) const;

    /**
     * @brief Check whether the database has already cleaned dirty data.
     * @return Returns true dirty data has been cleaned, false otherwise.
     */
    bool IsDirtyDataCleaned() const;
    /**
     * @brief Sets the database dirty data cleaned flag.
     */
    void SetIsDirtyDataCleaned();
    /**
     * @brief Get all form IDs from form_cache.
     * @param[out] formIds Output parameter to store form IDs.
     * @return Returns true on success, false otherwise.
     */
    bool GetFormCacheIds(std::unordered_set<int64_t> &formIds);
private:
    void CreateFormCacheTable();
    bool GetDataCacheFromDb(int64_t formId, FormCache &formCache) const;
    bool SaveDataCacheToDb(int64_t formId, const FormCache &formCache);
    bool DeleteDataCacheInDb(int64_t formId);
    bool GetImgCacheFromDb(int64_t rowId, std::vector<uint8_t> &blob, int32_t &size) const;
    bool SaveImgCacheToDb(const std::vector<uint8_t> &value, int32_t size, int64_t &rowId);
    bool DeleteImgCacheInDb(const std::string &rowId);
    bool DeleteImgCachesInDb(const std::vector<std::string> &rowIds);

    bool AddCacheData(const FormProviderData &formProviderData, FormCache &formCache);
    bool AddImgData(const FormProviderData &formProviderData, FormCache &formCache);
    bool AddImgDataToDb(
        const FormProviderData &formProviderData, nlohmann::json &imgDataJson);
    bool GetImageDataFromAshmem(
        const std::string& picName, const sptr<Ashmem> &ashmem, int32_t len, std::vector<uint8_t> &value);
    bool InnerGetImageData(const FormCache &formCache,
        std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap) const;
    void ResetCacheStateAfterReboot();

    mutable std::mutex cacheMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_CACHE_MGR_H
