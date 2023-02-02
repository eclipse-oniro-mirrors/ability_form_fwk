/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#include "form_info_storage_mgr.h"

#include <cinttypes>
#include <thread>
#include <unistd.h>
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t CHECK_TIMES = 300;
constexpr int32_t CHECK_INTERVAL = 100000; // 100ms
constexpr int32_t MAX_TIMES = 600; // 600 * 100ms = 1min
constexpr int32_t SLEEP_INTERVAL = 100 * 1000; // 100ms
constexpr const char* FORM_STORAGE_DIR = "/data/service/el1/public/database/form_storage";
const std::string FORM_INFO_PREFIX = "formInfo_";
const std::string FORM_ID_PREFIX = "formId_";
} // namespace

KvStoreDeathRecipientCallbackFormInfoStorage::KvStoreDeathRecipientCallbackFormInfoStorage()
{
    HILOG_INFO("create kv store death recipient callback instance");
}

KvStoreDeathRecipientCallbackFormInfoStorage::~KvStoreDeathRecipientCallbackFormInfoStorage()
{
    HILOG_INFO("destroy kv store death recipient callback instance");
}

void KvStoreDeathRecipientCallbackFormInfoStorage::OnRemoteDied()
{
    HILOG_INFO("OnRemoteDied, register data change listener begin");
    std::thread([] {
        int32_t times = 0;
        FormInfoStorageMgr &formInfoStorageMgr = FormInfoStorageMgr::GetInstance();
        while (times < CHECK_TIMES) {
            times++;
            // init kvStore.
            if (formInfoStorageMgr.ResetKvStore()) {
                // register data change listener again.
                HILOG_INFO("current times is %{public}d", times);
                break;
            }
            usleep(CHECK_INTERVAL);
        }
    }).detach();

    HILOG_INFO("OnRemoteDied, register data change listener end");
}

FormInfoStorageMgr::FormInfoStorageMgr()
{
    TryTwice([this] { return GetKvStore(); });
    RegisterKvStoreDeathListener();
    HILOG_INFO("FormInfoStorageMgr is created");
}

FormInfoStorageMgr::~FormInfoStorageMgr()
{
    dataManager_.CloseKvStore(appId_, kvStorePtr_);
}

ErrCode FormInfoStorageMgr::LoadFormInfos(std::vector<std::pair<std::string, std::string>> &formInfoStorages)
{
    HILOG_INFO("FormInfoStorageMgr load all form infos");
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            HILOG_ERROR("kvStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }

    DistributedKv::Status status;
    std::vector<DistributedKv::Entry> allEntries;
    TryTwice([this, &status, &allEntries] {
        status = GetEntries(FORM_INFO_PREFIX, allEntries);
        return status;
    });

    if (status != DistributedKv::Status::SUCCESS) {
        HILOG_ERROR("get entries error: %{public}d", status);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    for (const auto &item: allEntries) {
        formInfoStorages.emplace_back(item.key.ToString().substr(FORM_INFO_PREFIX.length()), item.value.ToString());
    }

    return ERR_OK;
}

ErrCode FormInfoStorageMgr::RemoveBundleFormInfos(const std::string &bundleName)
{
    if (bundleName.empty()) {
        HILOG_ERROR("bundleName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    HILOG_INFO("FormInfoStorageMgr remove form info, bundleName=%{public}s", bundleName.c_str());
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            HILOG_ERROR("kvStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }

    DistributedKv::Key key(FORM_INFO_PREFIX + bundleName);
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        TryTwice([this, &status, &key] {
            status = kvStorePtr_->Delete(key);
            return status;
        });
    }

    if (status != DistributedKv::Status::SUCCESS) {
        HILOG_ERROR("remove formInfoStorages from kvStore error: %{public}d", status);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

ErrCode FormInfoStorageMgr::UpdateBundleFormInfos(const std::string &bundleName, const std::string &formInfoStorages)
{
    if (bundleName.empty()) {
        HILOG_ERROR("bundleName is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    HILOG_INFO("FormInfoStorageMgr update form info, bundleName=%{public}s", bundleName.c_str());
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            HILOG_ERROR("kvStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    DistributedKv::Key key(FORM_INFO_PREFIX + bundleName);
    DistributedKv::Status status;
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    TryTwice([this, &status, &key] {
        status = kvStorePtr_->Delete(key);
        return status;
    });
    if (status != DistributedKv::Status::SUCCESS && status != DistributedKv::Status::KEY_NOT_FOUND) {
        HILOG_ERROR("update formInfoStorages to kvStore error: %{public}d", status);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    DistributedKv::Value value(formInfoStorages);
    TryTwice([this, &status, &key, &value] {
        status = kvStorePtr_->Put(key, value);
        return status;
    });
    if (status != DistributedKv::Status::SUCCESS) {
        HILOG_ERROR("update formInfoStorages to kvStore error: %{public}d", status);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

DistributedKv::Status FormInfoStorageMgr::GetKvStore()
{
    DistributedKv::Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = true,
        .kvStoreType = DistributedKv::KvStoreType::SINGLE_VERSION,
        .area = DistributedKv::EL1,
        .baseDir = FORM_STORAGE_DIR
    };

    DistributedKv::Status status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    if (status != DistributedKv::Status::SUCCESS) {
        HILOG_ERROR("return error: %{public}d", status);
    } else {
        HILOG_INFO("get kvStore success");
    }
    return status;
}

bool FormInfoStorageMgr::CheckKvStore()
{
    if (kvStorePtr_ != nullptr) {
        return true;
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        DistributedKv::Status status = GetKvStore();
        if (status == DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
            return true;
        }
        HILOG_INFO("CheckKvStore, Times: %{public}d", tryTimes);
        usleep(SLEEP_INTERVAL);
        tryTimes--;
    }
    return kvStorePtr_ != nullptr;
}

void FormInfoStorageMgr::RegisterKvStoreDeathListener()
{
    HILOG_INFO("register kvStore death listener");
    std::shared_ptr<DistributedKv::KvStoreDeathRecipient> callback =
        std::make_shared<KvStoreDeathRecipientCallbackFormInfoStorage>();
    dataManager_.RegisterKvStoreServiceDeathRecipient(callback);
}

bool FormInfoStorageMgr::ResetKvStore()
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    kvStorePtr_ = nullptr;
    DistributedKv::Status status = GetKvStore();
    if (status == DistributedKv::Status::SUCCESS && kvStorePtr_ != nullptr) {
        return true;
    }
    HILOG_WARN("ResetKvStore failed");
    return false;
}

DistributedKv::Status FormInfoStorageMgr::GetEntries(const std::string &keyPrefix,
    std::vector<DistributedKv::Entry> &allEntries)
{
    DistributedKv::Status status = DistributedKv::Status::ERROR;
    // if prefix is empty, get all entries.
    DistributedKv::Key key(keyPrefix);
    if (kvStorePtr_) {
        // sync call GetEntries, the callback will be trigger at once
        status = kvStorePtr_->GetEntries(key, allEntries);
    }
    HILOG_INFO("get all entries status: %{public}d", status);
    return status;
}

void FormInfoStorageMgr::SaveEntries(
    const std::vector<DistributedKv::Entry> &allEntries, std::vector<InnerFormInfo> &innerFormInfos)
{
    for (const auto &item : allEntries) {
        InnerFormInfo innerFormInfo;
        nlohmann::json jsonObject = nlohmann::json::parse(item.value.ToString(), nullptr, false);
        if (jsonObject.is_discarded()) {
            HILOG_ERROR("error key: %{private}s", item.key.ToString().c_str());
            // it's an bad json, delete it
            {
                std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
                if (!CheckKvStore()) {
                    HILOG_ERROR("kvStore is nullptr");
                    return;
                }
                kvStorePtr_->Delete(item.key);
            }
            continue;
        }
        if (innerFormInfo.FromJson(jsonObject) != true) {
            HILOG_ERROR("error key: %{private}s", item.key.ToString().c_str());
            // it's an error value, delete it
            {
                std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
                if (!CheckKvStore()) {
                    HILOG_ERROR("kvStore is nullptr");
                    return;
                }
                kvStorePtr_->Delete(item.key);
            }
            continue;
        }

        if (std::find(innerFormInfos.begin(), innerFormInfos.end(), innerFormInfo) == innerFormInfos.end()) {
            innerFormInfos.emplace_back(innerFormInfo);
        }
    }
    HILOG_DEBUG("SaveEntries end");
}

ErrCode FormInfoStorageMgr::LoadFormData(std::vector<InnerFormInfo> &innerFormInfos)
{
    HILOG_INFO("%{public}s called.", __func__);
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            HILOG_ERROR("kvStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    DistributedKv::Status status;
    std::vector<DistributedKv::Entry> allEntries;
    TryTwice([this, &status, &allEntries] {
        status = GetEntries(FORM_ID_PREFIX, allEntries);
        return status;
    });

    bool ret = ERR_OK;
    if (status != DistributedKv::Status::SUCCESS) {
        HILOG_ERROR("get entries error: %{public}d", status);
        ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
    } else {
        SaveEntries(allEntries, innerFormInfos);
    }

    HILOG_INFO("%{public}s end", __func__);
    return ret;
}

ErrCode FormInfoStorageMgr::GetStorageFormInfoById(const std::string &formId, InnerFormInfo &innerFormInfo)
{
    HILOG_INFO("%{public}s called, formId[%{public}s]", __func__, formId.c_str());
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            HILOG_ERROR("kvStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }

    DistributedKv::Status status = DistributedKv::Status::ERROR;
    std::vector<DistributedKv::Entry> allEntries;
    DistributedKv::Key key(FORM_ID_PREFIX + formId);
    if (kvStorePtr_) {
        // sync call GetEntries, the callback will be trigger at once
        status = kvStorePtr_->GetEntries(key, allEntries);
    }

    ErrCode ret = ERR_OK;
    if (status != DistributedKv::Status::SUCCESS) {
        HILOG_ERROR("get entries error: %{public}d", status);
        ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
    } else {
        if (allEntries.empty()) {
            HILOG_ERROR("%{public}s not match any FormInfo", formId.c_str());
            ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
        } else {
            nlohmann::json jsonObject = nlohmann::json::parse(allEntries.front().value.ToString(), nullptr, false);
            if (jsonObject.is_discarded()) {
                HILOG_ERROR("error key: %{private}s", allEntries.front().key.ToString().c_str());
                ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
            }
            if (!innerFormInfo.FromJson(jsonObject)) {
                HILOG_ERROR("error key: %{private}s", allEntries.front().key.ToString().c_str());
                ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
            }
        }
    }
    return ret;
}

ErrCode FormInfoStorageMgr::SaveStorageFormInfo(const InnerFormInfo &innerFormInfo)
{
    HILOG_INFO("%{public}s called, formId[%{public}" PRId64 "]", __func__, innerFormInfo.GetFormId());
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            HILOG_ERROR("kvStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }

    std::string formId = std::to_string(innerFormInfo.GetFormId());
    DistributedKv::Key key(FORM_ID_PREFIX + formId);
    DistributedKv::Value value(innerFormInfo.ToString());
    DistributedKv::Status status;
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        TryTwice([this, &status, &key, &value] {
            status = kvStorePtr_->Put(key, value);
            return status;
        });
    }
    ErrCode ret = ERR_OK;
    if (status != DistributedKv::Status::SUCCESS) {
        HILOG_ERROR("put innerFormInfo to kvStore error: %{public}d", status);
        ret = ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ret;
}

ErrCode FormInfoStorageMgr::ModifyStorageFormInfo(const InnerFormInfo &innerFormInfo)
{
    HILOG_INFO("%{public}s called, formId[%{public}" PRId64 "]", __func__, innerFormInfo.GetFormId());
    std::string formId = std::to_string(innerFormInfo.GetFormId());
    ErrCode ret = DeleteStorageFormInfo(formId);
    if (ret == ERR_OK) {
        SaveStorageFormInfo(innerFormInfo);
    }

    return ret;
}

ErrCode FormInfoStorageMgr::DeleteStorageFormInfo(const std::string &formId)
{
    HILOG_INFO("%{public}s called, formId[%{public}s]", __func__, formId.c_str());
    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        if (!CheckKvStore()) {
            HILOG_ERROR("kvStore is nullptr");
            return ERR_APPEXECFWK_FORM_COMMON_CODE;
        }
    }
    DistributedKv::Key key(FORM_ID_PREFIX + formId);
    DistributedKv::Status status;

    {
        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        TryTwice([this, &status, &key] {
            status = kvStorePtr_->Delete(key);
            return status;
        });
    }

    if (status != DistributedKv::Status::SUCCESS) {
        HILOG_ERROR("delete key error: %{public}d", status);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    HILOG_INFO("delete value to kvStore success");
    return ERR_OK;
}

void FormInfoStorageMgr::TryTwice(const std::function<DistributedKv::Status()> &func)
{
    DistributedKv::Status status = func();
    if (status == DistributedKv::Status::IPC_ERROR) {
        status = func();
        HILOG_WARN("distribute database ipc error and try to call again, result = %{public}d", status);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
