/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_FORM_EVENT_UTIL_H
#define OHOS_FORM_FWK_FORM_EVENT_UTIL_H

#include <memory>
#include <set>
#include <string>

#include "bundle_pack_info.h"
#include "form_record.h"
#include "form_info.h"
#include "form_id_key.h"
#include "form_timer.h"

namespace OHOS {
namespace AppExecFwk {
const std::string KEY_UID = "uid";
const std::string KEY_USER_ID = "userId";
class FormEventUtil {
public:
    static void HandleBundleFormInfoChanged(const std::string &bundleName, int32_t userId);
    static void HandleUpdateFormCloud(const std::string &bundleName);
    static void HandleProviderUpdated(const std::string &bundleName, const int userId);
    static void HandleBundleFormInfoRemoved(const std::string &bundleName, int32_t userId);
    static void HandleProviderRemoved(const std::string &bundleName, const int32_t userId);
    static void HandleBundleDataCleared(const std::string &bundleName, int32_t userId);
    static void HandleFormHostDataCleared(const int uid);
    static bool ProviderFormUpdated(const int64_t formId, FormRecord &formRecord,
        const std::vector<FormInfo> &targetForms);
    static bool ProviderFormUpdated(int64_t formId, FormRecord &formRecord, const BundlePackInfo &bundlePackInfo);
    static void ClearFormDBRecordData(const int uid, std::map<int64_t, bool> &removedFormsMap);
    static void ClearTempFormRecordData(const int uid, std::map<int64_t, bool> &removedFormsMap);
    static void BatchDeleteNoHostTempForms(const int uid, std::map<FormIdKey, std::set<int64_t>> &noHostTempFormsMap,
        std::map<int64_t, bool> &foundFormsMap);
    static void GetTimerCfg(const bool updateEnabled, const int updateDuration, const std::string &configUpdateAt,
        FormTimerCfg &cfg);
    static void HandleTimerUpdate(const int64_t formId, const FormRecord &record, const FormTimerCfg &timerCfg);
    static void ReCreateForm(const int64_t formId);
    static void BatchDeleteNoHostDBForms(const int uid, std::map<FormIdKey, std::set<int64_t>> &noHostFormDbMap,
        std::map<int64_t, bool> &removedFormsMap);
    static void HandleOnUnlock();
    static bool HandleAdditionalInfoChanged(const std::string &bundleName);

private:
    static void UpdateFormRecord(const FormInfo &formInfo, FormRecord &formRecord);
    static void UpdateFormRecord(const AbilityFormInfo &formInfo, FormRecord &formRecord);
    static UpdateType GetUpdateType(const FormRecord &record, const FormTimerCfg &timerCfg);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_EVENT_UTIL_H