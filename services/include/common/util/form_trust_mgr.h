/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_TRUST_MGR_H
#define OHOS_FORM_FWK_FORM_TRUST_MGR_H

#include <map>
#include <singleton.h>
#include <string>

#include "data_center/database/form_rdb_data_mgr.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormTrustMgr
 * Form info storage.
 */
class FormTrustMgr final : public DelayedRefSingleton<FormTrustMgr> {
DECLARE_DELAYED_REF_SINGLETON(FormTrustMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormTrustMgr);

    /**
     * @brief IsTrust or not.
     * @param bundleName Storage all form info.
     * @return Returns result.
     */
    bool IsTrust(const std::string &bundleName);

    /**
     * @brief MarkTrust.
     * @param bundleName bundleName.
     * @param isTrust isTrust.
     * @return Returns result.
     */
    void MarkTrustFlag(const std::string &bundleName, bool isTrust);

    /**
     * @brief Get the Untrust App Name List object
     *
     * @param result
     */
    void GetUntrustAppNameList(std::string &result);

    /**
     * @brief Handle untrust application connect failed.
     * @param updatedForms Need connect forms.
     * @param userId Current active userId.
     */
    void HandleConnectFailed(const std::vector<FormRecord> &updatedForms, int32_t userId);
private:
    std::map<std::string, int32_t> unTrustList_;
    mutable std::mutex unTrustListMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_TRUST_MGR_H
