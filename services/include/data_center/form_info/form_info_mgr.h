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

#ifndef OHOS_FORM_FWK_FORM_INFO_MGR_H
#define OHOS_FORM_FWK_FORM_INFO_MGR_H

#include <shared_mutex>
#include <singleton.h>
#include <unordered_map>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "data_center/database/form_db_info.h"
#include "form_info.h"
#include "form_info_filter.h"
#include "data_center/form_info/form_info_storage.h"
#include "data_center/form_record/form_record.h"
#include "resource_manager.h"

namespace OHOS {
namespace AppExecFwk {
class FormInfoHelper {
public:
    static ErrCode LoadFormConfigInfoByBundleName(const std::string &bundleName, std::vector<FormInfo> &formInfos,
        int32_t userId);

private:
    static ErrCode LoadAbilityFormConfigInfo(const BundleInfo &bundleInfo, std::vector<FormInfo> &formInfos);

    static ErrCode LoadStageFormConfigInfo(const BundleInfo &bundleInfo, std::vector<FormInfo> &formInfos);

    static std::shared_ptr<Global::Resource::ResourceManager> GetResourceManager(const BundleInfo &bundleInfo);

    static ErrCode GetFormInfoDescription(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager,
        FormInfo &formInfo);

    static ErrCode GetFormInfoDisplayName(std::shared_ptr<Global::Resource::ResourceManager> &resourceManager,
        FormInfo &formInfo);

    static bool LoadSharedModuleInfo(const BundleInfo &bundleInfo, HapModuleInfo &shared);
};

class BundleFormInfo {
public:
    explicit BundleFormInfo(const std::string &bundleName);

    ErrCode InitFromJson(const std::string &formInfoStoragesJson);

    ErrCode UpdateStaticFormInfos(int32_t userId);

    ErrCode Remove(int32_t userId);

    ErrCode AddDynamicFormInfo(const FormInfo &formInfo, int32_t userId);

    ErrCode RemoveDynamicFormInfo(const std::string &moduleName, const std::string &formName, int32_t userId);

    ErrCode RemoveAllDynamicFormsInfo(int32_t userId);

    bool Empty() const;

    ErrCode GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    uint32_t GetVersionCode(int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByModule(const std::string &moduleName, std::vector<FormInfo> &formInfos,
        int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByFilter(
        const FormInfoFilter &filter, std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

private:
    ErrCode UpdateFormInfoStorageLocked();

    void HandleFormInfosMaxLimit(std::vector<FormInfo> &inFormInfos,
        std::vector<FormInfo> &outFormInfos, const std::vector<FormDBInfo> &formDBInfos);

    void GetAllUsedFormName(const std::vector<FormDBInfo> &formDBInfos,
        const std::vector<FormInfo> &formInfos, std::set<std::string> &formDBNames);

    std::string bundleName_ {};
    mutable std::shared_timed_mutex formInfosMutex_ {};
    std::vector<AAFwk::FormInfoStorage> formInfoStorages_ {};
};

class FormInfoMgr final : public DelayedRefSingleton<FormInfoMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormInfoMgr)

public:
    DISALLOW_COPY_AND_MOVE(FormInfoMgr);

    ErrCode Start();

    ErrCode UpdateStaticFormInfos(const std::string &bundleName, int32_t userId);

    ErrCode Remove(const std::string &bundleName, int32_t userId);

    ErrCode GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByBundle(
        const std::string &bundleName, std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByFilter(
        const FormInfoFilter &filter, std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode GetFormsInfoByRecord(const FormRecord &formRecord, FormInfo &formInfo);

    ErrCode GetFormsInfoByModuleWithoutCheck(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos, int32_t userId = Constants::INVALID_USER_ID);

    ErrCode AddDynamicFormInfo(FormInfo &formInfo, int32_t userId);

    ErrCode RemoveDynamicFormInfo(const std::string &bundleName, const std::string &moduleName,
                                  const std::string &formName, int32_t userId);

    ErrCode RemoveAllDynamicFormsInfo(const std::string &bundleName, int32_t userId);

    ErrCode ReloadFormInfos(int32_t userId);

    bool PublishFmsReadyEvent();

    bool HasReloadedFormInfos();

    ErrCode GetAppFormVisibleNotifyByBundleName(const std::string &bundleName,
        int32_t providerUserId, bool &appFormVisibleNofify);
    bool IsMultiAppForm(const FormInfo &formInfo);

private:
    std::shared_ptr<BundleFormInfo> GetOrCreateBundleFromInfo(const std::string &bundleName);
    static bool IsCaller(const std::string& bundleName);
    static bool CheckBundlePermission();
    static ErrCode CheckDynamicFormInfo(FormInfo &formInfo, const BundleInfo &bundleInfo);
    static ErrCode GetBundleVersionMap(std::map<std::string, std::uint32_t> &bundleVersionMap, int32_t userId);
    void UpdateBundleFormInfos(std::map<std::string, std::uint32_t> &bundleVersionMap, int32_t userId);

    mutable std::shared_timed_mutex bundleFormInfoMapMutex_ {};
    std::unordered_map<std::string, std::shared_ptr<BundleFormInfo>> bundleFormInfoMap_ {};
    bool hasReloadedFormInfosState_ = false;
    std::map<std::string, bool> appFormVisibleNotifyMap_;
    std::mutex appFormVisibleNotifyMapMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_INFO_MGR_H
