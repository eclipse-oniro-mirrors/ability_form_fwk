/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "data_center/form_info/bundle_form_info.h"

#include "bms_mgr/form_bms_helper.h"
#include "common/util/form_util.h"
#include "data_center/database/form_db_cache.h"
#include "data_center/form_info/form_info_helper.h"
#include "feature/bundle_distributed/form_distributed_mgr.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "in_process_call_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::uint32_t ERR_VERSION_CODE = 0;
constexpr int DISTRIBUTED_BUNDLE_MODULE_LENGTH = 2;
}

BundleFormInfo::BundleFormInfo(const std::string &bundleName) : bundleName_(bundleName)
{
}

ErrCode BundleFormInfo::InitFromJson(const std::string &formInfoStoragesJson)
{
    nlohmann::json jsonObject = nlohmann::json::parse(formInfoStoragesJson, nullptr, false);
    if (jsonObject.is_discarded() || !jsonObject.is_array()) {
        HILOG_ERROR("bad profile");
        return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
    }
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    auto formInfoStorages = jsonObject.get<std::vector<AAFwk::FormInfoStorage>>();
    formInfoStorages_.insert(formInfoStorages_.end(), formInfoStorages.begin(), formInfoStorages.end());
    return ERR_OK;
}

ErrCode BundleFormInfo::UpdateStaticFormInfos(int32_t userId)
{
    HILOG_DEBUG("Update static form infos, userId is %{public}d", userId);
    std::vector<FormInfo> formInfos;
    ErrCode errCode = FormInfoHelper::LoadFormConfigInfoByBundleName(bundleName_, formInfos, userId);
    if (errCode != ERR_OK) {
        HILOG_ERROR("LoadFormConfigInfoByBundleName failed, errCode:%{public}d", errCode);
        return errCode;
    }

    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    if (!formInfos.empty()) {
        std::vector<FormDBInfo> formDBInfos;
        std::vector<FormInfo> finalFormInfos;
        FormDbCache::GetInstance().GetAllFormDBInfoByBundleName(bundleName_, userId, formDBInfos);
        HandleFormInfosMaxLimit(formInfos, finalFormInfos, formDBInfos);
        bool findUser = false;
        for (auto item = formInfoStorages_.begin(); item != formInfoStorages_.end(); ++item) {
            // Update all user's formInfos
            HILOG_DEBUG("Update formInfos, user:%{public}d", item->userId);
            item->formInfos = finalFormInfos;
            findUser = findUser || (item->userId == userId);
        }
        if (!findUser) {
            HILOG_DEBUG("Add new userId, user:%{public}d", userId);
            formInfoStorages_.emplace_back(userId, finalFormInfos);
        }
        return UpdateFormInfoStorageLocked();
    }

    bool IsBundleDistributed = FormDistributedMgr::GetInstance().IsBundleDistributed(bundleName_, userId);
    HILOG_INFO("The new package of %{public}s does not contain a card, IsBundleDistributed:%{public}d.",
        bundleName_.c_str(), IsBundleDistributed);
    if (IsBundleDistributed) {
        ClearDistributedFormInfos(userId);
    } else {
        HILOG_INFO("clear normal app formInfos, bundleName: %{public}s", bundleName_.c_str());
        formInfoStorages_.clear();
    }
    return UpdateFormInfoStorageLocked();
}

ErrCode BundleFormInfo::Remove(int32_t userId)
{
    HILOG_INFO("userId is %{public}d", userId);
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    for (auto item = formInfoStorages_.begin(); item != formInfoStorages_.end();) {
        if (item->userId == userId) {
            item = formInfoStorages_.erase(item);
        } else {
            ++item;
        }
    }
    return UpdateFormInfoStorageLocked();
}

ErrCode BundleFormInfo::AddDynamicFormInfo(const FormInfo &formInfo, int32_t userId)
{
    HILOG_INFO("userId is %{public}d", userId);
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    for (auto &formInfoStorage : formInfoStorages_) {
        if (formInfoStorage.userId != userId) {
            continue;
        }
        bool isSame = false;
        for (const auto &item : formInfoStorage.formInfos) {
            if (item.name == formInfo.name && item.moduleName == formInfo.moduleName) {
                isSame = true;
                break;
            }
        }

        if (isSame) {
            HILOG_ERROR("The same form already exists");
            return ERR_APPEXECFWK_FORM_INVALID_PARAM;
        }
        formInfoStorage.formInfos.push_back(formInfo);
        return UpdateFormInfoStorageLocked();
    }
    // no match user id
    std::vector<FormInfo> formInfos;
    formInfos.push_back(formInfo);
    formInfoStorages_.emplace_back(userId, formInfos);
    return UpdateFormInfoStorageLocked();
}

ErrCode BundleFormInfo::RemoveDynamicFormInfo(const std::string &moduleName, const std::string &formName,
                                              int32_t userId)
{
    HILOG_INFO("userId is %{public}d", userId);
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    for (auto &formInfoStorage : formInfoStorages_) {
        if (formInfoStorage.userId != userId) {
            continue;
        }
        for (auto item = formInfoStorage.formInfos.begin(); item != formInfoStorage.formInfos.end();) {
            if (item->name != formName || item->moduleName != moduleName) {
                ++item;
                continue;
            }
            // form found
            if (item->isStatic) {
                HILOG_ERROR("the specifiedFormInfo is static,can't be removed");
                return ERR_APPEXECFWK_FORM_INVALID_PARAM;
            }
            item = formInfoStorage.formInfos.erase(item);
            return UpdateFormInfoStorageLocked();
        }
    }
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

ErrCode BundleFormInfo::RemoveAllDynamicFormsInfo(int32_t userId)
{
    HILOG_INFO("userId is %{public}d", userId);
    std::unique_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    int32_t numRemoved = 0;
    for (auto &formInfoStorage : formInfoStorages_) {
        if (formInfoStorage.userId != userId) {
            continue;
        }
        for (auto item = formInfoStorage.formInfos.begin(); item != formInfoStorage.formInfos.end();) {
            if (!item->isStatic) {
                ++numRemoved;
                item = formInfoStorage.formInfos.erase(item);
            } else {
                ++item;
            }
        }
        break;
    }
    if (numRemoved > 0) {
        HILOG_ERROR("%{public}d dynamic forms info removed.", numRemoved);
        return UpdateFormInfoStorageLocked();
    }
    return ERR_OK;
}

bool BundleFormInfo::Empty() const
{
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    return formInfoStorages_.empty();
}

ErrCode BundleFormInfo::GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId)
{
    HILOG_DEBUG("begin");
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    userId = (userId == Constants::INVALID_USER_ID) ? FormUtil::GetCurrentAccountId() : userId;
    for (const auto &item : formInfoStorages_) {
        item.GetAllFormsInfo(userId, formInfos);
    }
    return ERR_OK;
}

uint32_t BundleFormInfo::GetVersionCode(int32_t userId)
{
    HILOG_DEBUG("begin");
    std::vector<FormInfo> formInfos;
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    userId = (userId == Constants::INVALID_USER_ID) ? FormUtil::GetCurrentAccountId() : userId;
    for (const auto &item : formInfoStorages_) {
        item.GetAllFormsInfo(userId, formInfos);
        for (const auto &info : formInfos) {
            if (info.versionCode != ERR_VERSION_CODE) {
                return info.versionCode;
            }
        }
    }
    return ERR_VERSION_CODE;
}

ErrCode BundleFormInfo::GetFormsInfoByModule(const std::string &moduleName, std::vector<FormInfo> &formInfos,
    int32_t userId)
{
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    userId = (userId == Constants::INVALID_USER_ID) ? FormUtil::GetCurrentAccountId() : userId;
    for (const auto &item : formInfoStorages_) {
        item.GetFormsInfoByModule(userId, moduleName, formInfos);
    }
    return ERR_OK;
}

ErrCode BundleFormInfo::GetFormsInfoByFilter(
    const FormInfoFilter &filter, std::vector<FormInfo> &formInfos, int32_t userId)
{
    HILOG_DEBUG("begin");
    std::shared_lock<std::shared_timed_mutex> guard(formInfosMutex_);
    auto newUserId = (userId == Constants::INVALID_USER_ID) ? FormUtil::GetCurrentAccountId() : userId;

    for (const auto &item : formInfoStorages_) {
        item.GetFormsInfoByFilter(newUserId, filter, formInfos);
    }
    return ERR_OK;
}

ErrCode BundleFormInfo::UpdateFormInfoStorageLocked()
{
    ErrCode errCode;
    if (formInfoStorages_.empty()) {
        errCode = FormInfoRdbStorageMgr::GetInstance().RemoveBundleFormInfos(bundleName_);
    } else {
        nlohmann::json jsonObject = formInfoStorages_;
        if (jsonObject.is_discarded()) {
            HILOG_ERROR("bad form infos");
            return ERR_APPEXECFWK_PARSE_BAD_PROFILE;
        }
        std::string formInfoStoragesStr = jsonObject.dump(Constants::DUMP_INDENT);
        errCode = FormInfoRdbStorageMgr::GetInstance().UpdateBundleFormInfos(bundleName_, formInfoStoragesStr);
    }
    return errCode;
}

void BundleFormInfo::HandleFormInfosMaxLimit(std::vector<FormInfo> &inFormInfos,
    std::vector<FormInfo> &outFormInfos, const std::vector<FormDBInfo> &formDBInfos)
{
    HILOG_INFO("formInfo num: %{public}zu,formDBInfo num: %{public}zu",
        inFormInfos.size(), formDBInfos.size());
    std::set<std::string> formDBNames;
    GetAllUsedFormName(formDBInfos, inFormInfos, formDBNames);
    if (formDBNames.empty() || inFormInfos.size() <= Constants::FORM_INFO_MAX_NUM) {
        if (inFormInfos.size() > Constants::FORM_INFO_MAX_NUM) {
            inFormInfos.resize(Constants::FORM_INFO_MAX_NUM);
        }
        outFormInfos = inFormInfos;
        return;
    }
    int32_t addFormNum = 0;
    unsigned int formNum = formDBNames.size();
    if (formDBNames.size() < Constants::FORM_INFO_MAX_NUM) {
        addFormNum = Constants::FORM_INFO_MAX_NUM - static_cast<int32_t>(formDBNames.size());
        formNum = Constants::FORM_INFO_MAX_NUM;
    }
    for (const auto &formInfo : inFormInfos) {
        bool isUsed = formDBNames.find(formInfo.name) != formDBNames.end();
        if (isUsed) {
            outFormInfos.push_back(formInfo);
        } else if (!isUsed && addFormNum > 0) {
            outFormInfos.push_back(formInfo);
            addFormNum--;
        }
        if (outFormInfos.size() == formNum) {
            break;
        }
    }
}

void BundleFormInfo::GetAllUsedFormName(const std::vector<FormDBInfo> &formDBInfos,
    const std::vector<FormInfo> &formInfos, std::set<std::string> &formDBNames)
{
    if (formDBInfos.empty() || formInfos.empty()) {
        return;
    }
    for (const auto &formDBInfo : formDBInfos) {
        if (formDBNames.count(formDBInfo.formName) > 0) {
            continue;
        }
        for (const auto &formInfo : formInfos) {
            if (formInfo.name == formDBInfo.formName) {
                formDBNames.insert(formDBInfo.formName);
                break;
            }
        }
    }
    HILOG_INFO("used form num: %{public}zu", formDBNames.size());
}

void BundleFormInfo::ClearDistributedFormInfos(int32_t userId)
{
    sptr<IBundleMgr> iBundleMgr = FormBmsHelper::GetInstance().GetBundleMgr();
    if (iBundleMgr == nullptr) {
        HILOG_ERROR("get IBundleMgr failed");
        return;
    }

    BundleInfo bundleInfo;
    int32_t flag = GET_BUNDLE_WITH_EXTENSION_INFO | GET_BUNDLE_WITH_ABILITIES;
    if (!IN_PROCESS_CALL(iBundleMgr->GetBundleInfo(bundleName_, flag, bundleInfo, userId))) {
        HILOG_ERROR("get bundleInfo failed");
        return;
    }

    if (bundleInfo.hapModuleInfos.size() < DISTRIBUTED_BUNDLE_MODULE_LENGTH) {
        // install a part of distributed app package, do not clear for now
        return;
    }
    HILOG_INFO("clear distributed app formInfos, bundleName: %{public}s", bundleName_.c_str());
    formInfoStorages_.clear();
}
}  // namespace AppExecFwk
}  // namespace OHOS