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

#include "data_center/form_cache_mgr.h"

#include <algorithm>
#include <sstream>

#include "fms_log_wrapper.h"
#include "nlohmann/json.hpp"
#include "json_util_form.h"
#include "common/util/scope_guard.h"
#include "common/util/form_util.h"
#include "common/util/form_report.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *JSON_EMPTY_STRING = "{}";
constexpr const char *JSON_NULL_STRING = "null";

constexpr const char *FORM_CACHE_TABLE = "form_cache";
constexpr const char *FORM_ID = "FORM_ID";
constexpr int32_t FORM_ID_INDEX = 0;
constexpr const char *DATA_CACHE = "DATA_CACHE";
constexpr int32_t DATA_CACHE_INDEX = 1;
constexpr const char *FORM_IMAGES = "FORM_IMAGES";
constexpr int32_t FORM_IMAGES_INDEX = 2;
constexpr const char *CACHE_STATE = "CACHE_STATE";
constexpr int32_t CACHE_STATE_INDEX = 3;

constexpr const char *IMG_CACHE_TABLE = "img_cache";
constexpr const char *IMAGE_ID = "IMAGE_ID";
constexpr int32_t IMAGE_ID_INDEX = 0;
constexpr const char *IMAGE_BIT = "IMAGE_BIT";
constexpr int32_t IMAGE_BIT_INDEX = 1;
constexpr const char *IMAGE_SIZE = "IMAGE_SIZE";
constexpr int32_t IMAGE_SIZE_INDEX = 2;

constexpr int32_t INVALID_INDEX = -1;
constexpr int32_t MAX_IMAGE_DATA_SIZE = 50 * 1024 * 1024; // 50MB, consistent with MAX_IMAGE_BYTE_SIZE
constexpr const char *IS_DIRTY_DATA_CLEANED = "isDirtyDataCleaned";
// DATA_CACHE of the sentinel row stores the finished cleanup version as a decimal string;
// bump CACHE_CLEANUP_VERSION to trigger one more sweep on upgrade. Empty means legacy format.
constexpr int32_t CACHE_CLEANUP_VERSION = 1;
constexpr int32_t CACHE_CLEANUP_INVALID_VERSION = -1;
constexpr int32_t MAX_DELETE_BATCH_SIZE = 500; // rowIds per batch, avoid SQL length limit
constexpr int32_t SINGLE_COLUMN_INDEX = 0; // index of the only column in single-column SELECT

inline bool HasContent(const std::string &str)
{
    return !str.empty() && str != JSON_EMPTY_STRING && str != JSON_NULL_STRING;
}
}

FormCacheMgr::FormCacheMgr()
{
    HILOG_INFO("create");
    CreateFormCacheTable();
}

FormCacheMgr::~FormCacheMgr()
{
    HILOG_INFO("destroy");
}

void FormCacheMgr::CreateFormCacheTable()
{
    FormRdbTableConfig formRdbCacheTableConfig;
    formRdbCacheTableConfig.tableName = FORM_CACHE_TABLE;
    std::stringstream sql;
    sql << "CREATE TABLE IF NOT EXISTS " << FORM_CACHE_TABLE;
    sql << " (FORM_ID TEXT NOT NULL PRIMARY KEY, DATA_CACHE TEXT, FORM_IMAGES TEXT, CACHE_STATE INTEGER);";
    formRdbCacheTableConfig.createTableSql = sql.str();
    if (FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbCacheTableConfig) != ERR_OK) {
        HILOG_ERROR("Form cache mgr init form rdb cache table fail");
    }

    FormRdbTableConfig formRdbImgTableConfig;
    formRdbImgTableConfig.tableName = IMG_CACHE_TABLE;
    sql.str("");
    sql << "CREATE TABLE IF NOT EXISTS " << IMG_CACHE_TABLE;
    sql << " (IMAGE_ID INTEGER PRIMARY KEY AUTOINCREMENT, IMAGE_BIT BLOB, IMAGE_SIZE TEXT);";
    formRdbImgTableConfig.createTableSql = sql.str();
    if (FormRdbDataMgr::GetInstance().InitFormRdbTable(formRdbImgTableConfig) != ERR_OK) {
        HILOG_ERROR("Form cache mgr init form rdb img table fail");
    }
}

void FormCacheMgr::Start()
{
    HILOG_INFO("Start");
    ResetCacheStateAfterReboot();
}

bool FormCacheMgr::GetData(const int64_t formId, std::string &data,
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap) const
{
    HILOG_DEBUG("GetData start");
    FormCache formCache;
    formCache.formId = formId;
    bool ret = GetDataCacheFromDb(formId, formCache);
    if (!ret) {
        HILOG_ERROR("no data in db");
        return false;
    }

    bool hasContent = false;
    if (HasContent(formCache.dataCache)) {
        nlohmann::json dataCacheObj = SafeJsonParse(formCache.dataCache);
        if (dataCacheObj.is_discarded() || !dataCacheObj.is_object()) {
            HILOG_ERROR("GetData failed due to dataCache is discarded");
            return false;
        }

        data = formCache.dataCache;
        hasContent = true;
    }

    if (HasContent(formCache.imgCache)) {
        ret = InnerGetImageData(formCache, imageDataMap);
        if (!ret) {
            HILOG_ERROR("InnerGetImageData failed");
            return false;
        }

        hasContent = true;
    }

    return hasContent;
}

bool FormCacheMgr::InnerGetImageData(
    const FormCache &formCache,
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap) const
{
    HILOG_DEBUG("InnerGetImageData start");
    nlohmann::json imgCacheObj = SafeJsonParse(formCache.imgCache);
    if (imgCacheObj.is_discarded() || !imgCacheObj.is_object()) {
        HILOG_ERROR("imgCacheObj is discarded");
        return false;
    }

    for (auto && [key, value] : imgCacheObj.items()) {
        int64_t rowId = INVALID_INDEX;
        std::stringstream ss;
        ss << value.dump();
        if (!(ss >> rowId) || rowId == INVALID_INDEX) {
            HILOG_ERROR("invalid rowId from imgCache for key:%{public}s", key.c_str());
            continue;
        }
        std::vector<uint8_t> blob;
        int32_t size = 0;
        if (!GetImgCacheFromDb(rowId, blob, size)) {
            HILOG_ERROR("GetImgCacheFromDb failed");
            return false;
        }

        if (blob.size() <= 0) {
            HILOG_ERROR("GetImgCacheFromDb failed due to blob is empty");
            return false;
        }

        sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
        if (formAshmem == nullptr) {
            HILOG_ERROR("Alloc ashmem failed");
            return false;
        }

        if (!formAshmem->WriteToAshmem(key, reinterpret_cast<char *>(blob.data()),
            static_cast<int32_t>(blob.size()))) {
            HILOG_ERROR("Write to ashmem failed");
            return false;
        }

        imageDataMap[key] = std::make_pair(formAshmem, size);
    }

    return true;
}

bool FormCacheMgr::AddData(int64_t formId, const FormProviderData &formProviderData)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    std::lock_guard<std::mutex> lock(cacheMutex_);

    FormCache formCache;
    formCache.formId = formId;
    GetDataCacheFromDb(formId, formCache);

    // Track newly inserted rows for rollback on later failures
    std::vector<std::string> newImgRowIds;
    if (!AddImgData(formProviderData, formCache, newImgRowIds)) {
        HILOG_ERROR("AddImgData failed");
        RollbackNewImgCaches(newImgRowIds);
        return false;
    }

    if (!AddCacheData(formProviderData, formCache)) {
        HILOG_ERROR("AddCacheData failed");
        RollbackNewImgCaches(newImgRowIds);
        return false;
    }

    // Save dataCache and imgCache
    formCache.cacheState = CacheState::DEFAULT;
    FormReport::GetInstance().SetDurationEndTime(formId, FormUtil::GetCurrentSteadyClockMillseconds());
    if (!SaveDataCacheToDb(formId, formCache)) {
        RollbackNewImgCaches(newImgRowIds);
        return false;
    }
    return true;
}

void FormCacheMgr::RollbackNewImgCaches(const std::vector<std::string> &rowIds)
{
    if (rowIds.empty()) {
        return;
    }
    if (!DeleteImgCachesInDb(rowIds)) {
        // Leftover rows are recovered by the version-triggered sweep
        HILOG_ERROR("FormImgRollbackFail, size:%{public}zu", rowIds.size());
    }
}

bool FormCacheMgr::AddImgData(
    const FormProviderData &formProviderData, FormCache &formCache, std::vector<std::string> &newRowIds)
{
    nlohmann::json newImgDbData;
    if (!AddImgDataToDb(formProviderData, newImgDbData, newRowIds)) {
        HILOG_ERROR("AddImgDataToDb failed");
        return false;
    }

    if (newImgDbData.empty()) {
        HILOG_DEBUG("No imgData");
        return true;
    }

    if (HasContent(formCache.imgCache)) {
        nlohmann::json imgCacheObj = SafeJsonParse(formCache.imgCache);
        if (imgCacheObj.is_discarded() || !imgCacheObj.is_object()) {
            HILOG_ERROR("parse data failed");
            return false;
        }
        // delete old images
        std::vector<std::string> rowIds;
        for (auto && [key, value] : imgCacheObj.items()) {
            rowIds.push_back(value.dump());
        }
        if (!DeleteImgCachesInDb(rowIds)) {
            HILOG_ERROR("FormImgDeleteFail, size:%{public}zu", rowIds.size());
        }
    }

    formCache.imgCache = newImgDbData.dump();

    return true;
}

bool FormCacheMgr::AddCacheData(
    const FormProviderData &formProviderData, FormCache &formCache)
{
    auto newDataStr = formProviderData.GetDataString();
    nlohmann::json newDataObj;
    if (HasContent(newDataStr)) {
        newDataObj = SafeJsonParse(newDataStr);
        if (newDataObj.is_discarded() || !newDataObj.is_object()) {
            HILOG_ERROR("parse data failed");
            return false;
        }

        newDataObj.erase("formImages");
    }

    if (newDataObj.empty()) {
        HILOG_INFO("No new cacheData");
        return true;
    }

    if (!HasContent(formCache.dataCache)) {
        // No dataCache in db
        formCache.dataCache = newDataObj.dump();
        return true;
    }

    nlohmann::json dataCacheObj = SafeJsonParse(formCache.dataCache);
    if (dataCacheObj.is_discarded() || !dataCacheObj.is_object()) {
        HILOG_ERROR("parse data failed");
        return false;
    }

    // Update dataCache
    for (auto && [key, value] : newDataObj.items()) {
        dataCacheObj[key] = value;
    }
    formCache.dataCache = dataCacheObj.dump();
    return true;
}

bool FormCacheMgr::AddImgDataToDb(
    const FormProviderData &formProviderData, nlohmann::json &imgDataJson, std::vector<std::string> &newRowIds)
{
    auto imgCache = formProviderData.GetImageDataMap();
    HILOG_DEBUG("AddImgDataToDb imgCache size:%{public}zu", imgCache.size());
    for (const auto &iter : imgCache) {
        int64_t rowId = INVALID_INDEX;
        std::vector<uint8_t> value;
        bool ret = GetImageDataFromAshmem(
            iter.first, iter.second.first->GetAshmem(), iter.second.first->GetAshmemSize(), value);
        if (!ret) {
            HILOG_ERROR("fail get img data imgName:%{public}s", iter.first.c_str());
            return false;
        }

        ret = SaveImgCacheToDb(value, iter.second.second, rowId);
        if (!ret || rowId == INVALID_INDEX) {
            HILOG_ERROR("fail save img data imgName:%{public}s", iter.first.c_str());
            return false;
        }

        imgDataJson[iter.first] = rowId;
        // Record on success for mid-loop rollback
        newRowIds.emplace_back(std::to_string(rowId));
    }

    return true;
}

bool FormCacheMgr::GetImageDataFromAshmem(
    const std::string& picName, const sptr<Ashmem> &ashmem, int32_t len, std::vector<uint8_t> &value)
{
    HILOG_DEBUG("GetImageDataFromAshmem start picName:%{public}s", picName.c_str());
    if (len <= 0 || len > MAX_IMAGE_DATA_SIZE) {
        HILOG_ERROR("invalid len:%{public}d, picName:%{public}s", len, picName.c_str());
        return false;
    }
    if (ashmem == nullptr) {
        HILOG_ERROR("null ashmem when picName:%{public}s", picName.c_str());
        return false;
    }

    bool ret = ashmem->MapReadOnlyAshmem();
    if (!ret) {
        HILOG_ERROR("MapReadOnlyAshmem fail, fail reason:%{public}s, picName:%{public}s",
            strerror(errno), picName.c_str());
        return false;
    }

    ScopeGuard stateGuard([ashmem] {
        if (ashmem) {
            ashmem->UnmapAshmem();
        }
    });
    const uint8_t* imageData = reinterpret_cast<const uint8_t*>(ashmem->ReadFromAshmem(len, 0));
    if (imageData == nullptr) {
        HILOG_ERROR("ReadFromAshmem failed picName:%{public}s", picName.c_str());
        return false;
    }

    value = std::vector<uint8_t>(imageData, imageData + len);
    return true;
}

bool FormCacheMgr::DeleteData(const int64_t formId)
{
    HILOG_INFO("formId:%{public}" PRId64, formId);
    bool isNeedDeleteImgCache = true;
    nlohmann::json imgCacheObj;
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        FormCache formCache;
        bool ret = GetDataCacheFromDb(formId, formCache);
        if (!ret) {
            HILOG_INFO("No DataCache when delete");
            return true;
        }

        if (!HasContent(formCache.imgCache)) {
            HILOG_INFO("Has no imgCache when delete");
            isNeedDeleteImgCache = false;
        }

        imgCacheObj = SafeJsonParse(formCache.imgCache);
        if (imgCacheObj.is_discarded() || !imgCacheObj.is_object()) {
            HILOG_WARN("parse imgCache failed, no image data, formId:%{public}s", formCache.formId.c_str());
            isNeedDeleteImgCache = false;
        }
    }
    if (isNeedDeleteImgCache) {
        std::vector<std::string> rowIds;
        for (auto && [key, value] : imgCacheObj.items()) {
            rowIds.push_back(value.dump());
        }
        if (!DeleteImgCachesInDb(rowIds)) {
            HILOG_ERROR("delete img caches failed");
        }
    }
    return DeleteDataCacheInDb(formId);
}

bool FormCacheMgr::NeedAcquireProviderData(const int64_t formId) const
{
    HILOG_DEBUG("NeedAcquireProviderData");
    FormCache formCache;
    bool ret = GetDataCacheFromDb(formId, formCache);
    if (!ret) {
        HILOG_ERROR("No DataCache");
        return true;
    }

    bool hasContent = HasContent(formCache.dataCache) || HasContent(formCache.imgCache);
    bool isRebootState = formCache.cacheState == CacheState::REBOOT;
    return !hasContent || isRebootState;
}

bool FormCacheMgr::GetDataCacheFromDb(int64_t formId, FormCache &formCache) const
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(FORM_CACHE_TABLE);
    absRdbPredicates.EqualTo(FORM_ID, std::to_string(formId));
    auto absSharedResultSet = FormRdbDataMgr::GetInstance().QueryDataByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("GetDataCacheFromDb failed");
        return false;
    }

    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });

    int ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("GoToFirstRow failed, ret:%{public}d", ret);
        return false;
    }

    ret = absSharedResultSet->GetString(DATA_CACHE_INDEX, formCache.dataCache);
    if (ret != NativeRdb::E_OK) {
        HILOG_DEBUG("GetString dataCache failed, ret:%{public}d", ret);
    }

    ret = absSharedResultSet->GetString(FORM_IMAGES_INDEX, formCache.imgCache);
    if (ret != NativeRdb::E_OK) {
        HILOG_DEBUG("GetString imgCache failed, ret:%{public}d", ret);
    }

    int32_t cacheState = static_cast<int32_t>(CacheState::DEFAULT);
    ret = absSharedResultSet->GetInt(CACHE_STATE_INDEX, cacheState);
    if (ret != NativeRdb::E_OK) {
        HILOG_DEBUG("GetInt cacheState failed, ret:%{public}d", ret);
    }
    formCache.cacheState = static_cast<CacheState>(cacheState);
    return true;
}

bool FormCacheMgr::SaveDataCacheToDb(int64_t formId, const FormCache &formCache)
{
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(FORM_ID, std::to_string(formId));
    valuesBucket.PutString(DATA_CACHE, formCache.dataCache);
    valuesBucket.PutString(FORM_IMAGES, formCache.imgCache);
    valuesBucket.PutInt(CACHE_STATE, static_cast<int>(formCache.cacheState));
    int64_t rowId;
    bool ret = FormRdbDataMgr::GetInstance().InsertData(FORM_CACHE_TABLE, valuesBucket, rowId);
    if (!ret) {
        HILOG_ERROR("SaveDataCacheToDb formId:%{public}s failed.", std::to_string(formId).c_str());
        return false;
    }
    return true;
}

bool FormCacheMgr::DeleteDataCacheInDb(int64_t formId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(FORM_CACHE_TABLE);
    absRdbPredicates.EqualTo(FORM_ID, std::to_string(formId));
    return FormRdbDataMgr::GetInstance().DeleteData(absRdbPredicates);
}

bool FormCacheMgr::GetImgCacheFromDb(
    int64_t rowId, std::vector<uint8_t> &blob, int32_t &size) const
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(IMG_CACHE_TABLE);
    absRdbPredicates.EqualTo(IMAGE_ID, std::to_string(rowId));
    auto absSharedResultSet = FormRdbDataMgr::GetInstance().QueryDataByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("GetImgCacheFromDb failed");
        return false;
    }

    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });
    int ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("GoToFirstRow failed,ret:%{public}d", ret);
        return false;
    }

    ret = absSharedResultSet->GetBlob(IMAGE_BIT_INDEX, blob);
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("GetBlob failed, ret:%{public}d", ret);
        return false;
    }

    ret = absSharedResultSet->GetInt(IMAGE_SIZE_INDEX, size);
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("GetInt size failed, ret:%{public}d", ret);
        return false;
    }

    return true;
}

bool FormCacheMgr::SaveImgCacheToDb(const std::vector<uint8_t> &value, int32_t size, int64_t &rowId)
{
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutBlob(IMAGE_BIT, value);
    valuesBucket.PutInt(IMAGE_SIZE, size);
    bool ret = FormRdbDataMgr::GetInstance().InsertData(IMG_CACHE_TABLE, valuesBucket, rowId);
    if (!ret) {
        HILOG_ERROR("SaveImgCacheToDb failed");
        return false;
    }
    return true;
}

bool FormCacheMgr::DeleteImgCacheInDb(const std::string &rowId)
{
    if (rowId.empty()) {
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(IMG_CACHE_TABLE);
    absRdbPredicates.EqualTo(IMAGE_ID, rowId);
    return FormRdbDataMgr::GetInstance().DeleteData(absRdbPredicates);
}

bool FormCacheMgr::DeleteImgCachesInDb(const std::vector<std::string> &rowIds)
{
    if (rowIds.empty()) {
        return false;
    }
    HILOG_DEBUG("size:%{public}zu", rowIds.size());
    NativeRdb::AbsRdbPredicates predicates(IMG_CACHE_TABLE);
    predicates.In(IMAGE_ID, rowIds);
    return FormRdbDataMgr::GetInstance().DeleteData(predicates) == ERR_OK;
}

void FormCacheMgr::ResetCacheStateAfterReboot()
{
    std::stringstream sql;
    sql << "UPDATE " << FORM_CACHE_TABLE << " SET " << CACHE_STATE << " = 1;";
    FormRdbDataMgr::GetInstance().ExecuteSql(sql.str());
}

bool FormCacheMgr::IsDirtyDataCleaned() const
{
    std::stringstream sql;
    sql << "SELECT " << DATA_CACHE << " FROM " << FORM_CACHE_TABLE << " WHERE " << FORM_ID << " = '"
        << IS_DIRTY_DATA_CLEANED << "'";
    auto absSharedResultSet = FormRdbDataMgr::GetInstance().QuerySql(sql.str());
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("IsDirtyDataCleaned query failed");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });
    if (!absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet has no block");
        return false;
    }
    if (absSharedResultSet->GoToFirstRow() != NativeRdb::E_OK) {
        return false;
    }
    std::string cleanedVersionStr;
    if (absSharedResultSet->GetString(SINGLE_COLUMN_INDEX, cleanedVersionStr) != NativeRdb::E_OK) {
        return false;
    }
    // Empty or non-numeric means legacy format (never cleaned by version mechanism)
    int64_t cleanedVersion = CACHE_CLEANUP_INVALID_VERSION;
    if (cleanedVersionStr.empty() || !FormUtil::ConvertStringToInt64(cleanedVersionStr, cleanedVersion)) {
        return false;
    }
    return cleanedVersion >= CACHE_CLEANUP_VERSION;
}

void FormCacheMgr::SetIsDirtyDataCleaned()
{
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(FORM_ID, IS_DIRTY_DATA_CLEANED);
    valuesBucket.PutString(DATA_CACHE, std::to_string(CACHE_CLEANUP_VERSION));
    valuesBucket.PutString(FORM_IMAGES, "");
    valuesBucket.PutInt(CACHE_STATE, 0);
    int64_t rowId;
    FormRdbDataMgr::GetInstance().InsertData(FORM_CACHE_TABLE, valuesBucket, rowId);
}

bool FormCacheMgr::GetFormCacheIds(std::unordered_set<int64_t> &formIds)
{
    std::stringstream sql;
    sql << "SELECT " << FORM_ID << " FROM " << FORM_CACHE_TABLE;
    auto absSharedResultSet = FormRdbDataMgr::GetInstance().QuerySql(sql.str());
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("GetFormCacheIds failed");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });
    if (!absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet has no block");
        return false;
    }
    while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string formIdStr;
        int ret = absSharedResultSet->GetString(FORM_ID_INDEX, formIdStr);
        if (ret != NativeRdb::E_OK) {
            HILOG_WARN("GetString formId failed,ret:%{public}d", ret);
            continue;
        }
        int64_t formId;
        if (FormUtil::ConvertStringToInt64(formIdStr, formId)) {
            formIds.emplace(formId);
        }
    }
    if (formIds.empty()) {
        HILOG_ERROR("form_cache is empty");
        return false;
    }
    return true;
}

bool FormCacheMgr::GetReferencedImgIds(std::unordered_set<int64_t> &referencedIds) const
{
    std::stringstream sql;
    sql << "SELECT " << FORM_IMAGES << " FROM " << FORM_CACHE_TABLE << " WHERE " << FORM_IMAGES
        << " IS NOT NULL AND " << FORM_IMAGES << " != '' AND " << FORM_IMAGES << " != '{}'";
    auto absSharedResultSet = FormRdbDataMgr::GetInstance().QuerySql(sql.str());
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("GetReferencedImgIds query failed");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });
    if (!absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet has no block");
        return false;
    }
    while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string imgCache;
        if (absSharedResultSet->GetString(SINGLE_COLUMN_INDEX, imgCache) != NativeRdb::E_OK) {
            continue;
        }
        nlohmann::json imgCacheObj = SafeJsonParse(imgCache);
        if (imgCacheObj.is_discarded() || !imgCacheObj.is_object()) {
            continue;
        }
        for (auto && [key, value] : imgCacheObj.items()) {
            if (value.is_number_integer()) {
                referencedIds.emplace(value.get<int64_t>());
            }
        }
    }
    return true;
}

bool FormCacheMgr::GetAllImgIds(std::vector<int64_t> &imgIds) const
{
    std::stringstream sql;
    sql << "SELECT " << IMAGE_ID << " FROM " << IMG_CACHE_TABLE;
    auto absSharedResultSet = FormRdbDataMgr::GetInstance().QuerySql(sql.str());
    if (absSharedResultSet == nullptr) {
        HILOG_ERROR("GetAllImgIds query failed");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] {
        if (absSharedResultSet) {
            absSharedResultSet->Close();
        }
    });
    if (!absSharedResultSet->HasBlock()) {
        HILOG_ERROR("absSharedResultSet has no block");
        return false;
    }
    while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK) {
        int64_t imgId = 0;
        if (absSharedResultSet->GetLong(SINGLE_COLUMN_INDEX, imgId) != NativeRdb::E_OK) {
            continue;
        }
        imgIds.emplace_back(imgId);
    }
    return true;
}

void FormCacheMgr::DeleteInvalidImgCache()
{
    HILOG_INFO("DeleteInvalidImgCache start");
    std::lock_guard<std::mutex> lock(cacheMutex_);
    // Enumerate all ids before collecting references: ids inserted after the snapshot
    // are excluded from the diff, avoiding false-positive deletion of newly added images
    std::vector<int64_t> allImgIds;
    if (!GetAllImgIds(allImgIds)) {
        return;
    }
    std::unordered_set<int64_t> referencedIds;
    if (!GetReferencedImgIds(referencedIds)) {
        return;
    }
    // Orphans = rows not referenced by any FORM_IMAGES mapping
    std::vector<std::string> orphanRowIds;
    for (int64_t imgId : allImgIds) {
        if (referencedIds.find(imgId) == referencedIds.end()) {
            orphanRowIds.emplace_back(std::to_string(imgId));
        }
    }
    if (orphanRowIds.empty()) {
        HILOG_INFO("FormCacheSweepDone, orphan:0, total:%{public}zu", allImgIds.size());
        return;
    }
    size_t orphanCount = orphanRowIds.size();
    for (size_t begin = 0; begin < orphanCount; begin += MAX_DELETE_BATCH_SIZE) {
        size_t end = std::min(begin + static_cast<size_t>(MAX_DELETE_BATCH_SIZE), orphanCount);
        std::vector<std::string> batch(orphanRowIds.begin() + begin, orphanRowIds.begin() + end);
        if (!DeleteImgCachesInDb(batch)) {
            HILOG_ERROR("FormImgDeleteFail, sweep batch failed, batch size:%{public}zu", batch.size());
        }
    }
    HILOG_INFO("FormCacheSweepDone, orphan:%{public}zu, total:%{public}zu", orphanCount, allImgIds.size());
}
}  // namespace AppExecFwk
}  // namespace OHOS
