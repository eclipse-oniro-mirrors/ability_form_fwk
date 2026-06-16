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

#include <sstream>

#include "fms_log_wrapper.h"
#include "nlohmann/json.hpp"
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
constexpr const char *IS_DIRTY_DATA_CLEANED = "isDirtyDataCleaned";

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
        nlohmann::json dataCacheObj = nlohmann::json::parse(formCache.dataCache, nullptr, false);
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
    nlohmann::json imgCacheObj = nlohmann::json::parse(formCache.imgCache, nullptr, false);
    if (imgCacheObj.is_discarded() || !imgCacheObj.is_object()) {
        HILOG_ERROR("imgCacheObj is discarded");
        return false;
    }

    for (auto && [key, value] : imgCacheObj.items()) {
        int64_t rowId;
        std::stringstream ss;
        ss << value.dump();
        ss >> rowId;
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
    if (!AddImgData(formProviderData, formCache)) {
        HILOG_ERROR("AddImgData failed");
        return false;
    }

    if (!AddCacheData(formProviderData, formCache)) {
        HILOG_ERROR("AddCacheData failed");
        return false;
    }

    // Save dataCache and imgCache
    formCache.cacheState = CacheState::DEFAULT;
    FormReport::GetInstance().SetDurationEndTime(formId, FormUtil::GetCurrentSteadyClockMillseconds());
    return SaveDataCacheToDb(formId, formCache);
}

bool FormCacheMgr::AddImgData(
    const FormProviderData &formProviderData, FormCache &formCache)
{
    nlohmann::json newImgDbData;
    if (!AddImgDataToDb(formProviderData, newImgDbData)) {
        HILOG_ERROR("AddImgDataToDb failed");
        return false;
    }

    if (newImgDbData.empty()) {
        HILOG_INFO("No new imgData");
        return true;
    }

    if (HasContent(formCache.imgCache)) {
        nlohmann::json imgCacheObj = nlohmann::json::parse(formCache.imgCache, nullptr, false);
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
            HILOG_ERROR("delete img caches failed");
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
        newDataObj = nlohmann::json::parse(newDataStr, nullptr, false);
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

    nlohmann::json dataCacheObj = nlohmann::json::parse(formCache.dataCache, nullptr, false);
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
    const FormProviderData &formProviderData, nlohmann::json &imgDataJson)
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
    }

    return true;
}

bool FormCacheMgr::GetImageDataFromAshmem(
    const std::string& picName, const sptr<Ashmem> &ashmem, int32_t len, std::vector<uint8_t> &value)
{
    HILOG_DEBUG("GetImageDataFromAshmem start picName:%{public}s", picName.c_str());
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

        imgCacheObj = nlohmann::json::parse(formCache.imgCache, nullptr, false);
        if (imgCacheObj.is_discarded() || !imgCacheObj.is_object()) {
            HILOG_ERROR("parse data failed");
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

    int32_t cacheState;
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
    HILOG_INFO("size:%{public}zu", rowIds.size());
    std::stringstream sql;
    sql << "DELETE FROM " << IMG_CACHE_TABLE << " WHERE " << IMAGE_ID << " IN (";
    for (auto iter = rowIds.begin(); iter != rowIds.end(); ++iter) {
        sql << "\'" << *iter << "\',";
    }
    sql.seekp(-1, std::ios::end);
    sql << ");";
    return FormRdbDataMgr::GetInstance().ExecuteSql(sql.str()) == ERR_OK;
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
    sql << "SELECT " << FORM_ID << " FROM " << FORM_CACHE_TABLE << " WHERE " << FORM_ID << " = \'";
    sql << IS_DIRTY_DATA_CLEANED << "\'";
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
    int ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        HILOG_ERROR("GoToFirstRow failed, ret:%{public}d", ret);
        return false;
    }
    std::string isDirtyDataCleaned;
    ret = absSharedResultSet->GetString(FORM_ID_INDEX, isDirtyDataCleaned);
    if (ret != NativeRdb::E_OK) {
        HILOG_DEBUG("GetString isDirtyDataCleaned failed, ret:%{public}d", ret);
        return false;
    }
    return true;
}

void FormCacheMgr::SetIsDirtyDataCleaned()
{
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(FORM_ID, IS_DIRTY_DATA_CLEANED);
    valuesBucket.PutString(DATA_CACHE, "");
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
}  // namespace AppExecFwk
}  // namespace OHOS
