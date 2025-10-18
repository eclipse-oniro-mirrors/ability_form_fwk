/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_BUNDLE_FORM_INFO_H
#define OHOS_FORM_FWK_BUNDLE_FORM_INFO_H

#include <shared_mutex>
#include <singleton.h>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "data_center/database/form_db_info.h"
#include "data_center/form_info/form_info_storage.h"
#include "form_constants.h"
#include "form_info.h"

namespace OHOS {
namespace AppExecFwk {
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

    void ClearDistributedFormInfos(int32_t userId);

    std::string bundleName_ {};
    mutable std::shared_timed_mutex formInfosMutex_ {};
    std::vector<AAFwk::FormInfoStorage> formInfoStorages_ {};
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_BUNDLE_FORM_INFO_H
