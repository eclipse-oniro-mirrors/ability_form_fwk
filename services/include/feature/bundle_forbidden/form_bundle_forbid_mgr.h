/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_FORM_BUNDLE_FORBID_MGR_H
#define OHOS_FORM_FWK_FORM_BUNDLE_FORBID_MGR_H

#include <map>
#include <shared_mutex>
#include <singleton.h>
#include <string>

#include "want.h"
#include "data_center/database/form_rdb_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormBundleForbidMgr
 * Form bundle forbid manager.
 */
class FormBundleForbidMgr final : public DelayedRefSingleton<FormBundleForbidMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormBundleForbidMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormBundleForbidMgr);

    /**
     * @brief Get whether bundle is forbidden.
     * @param bundleName Bundle name to be check.
     * @return True for forbidden, false for not forbidden.
     */
    bool IsBundleForbidden(const std::string &bundleName);

    /**
     * @brief Set whether bundle is forbidden.
     * @param bundleName Bundle name to be set.
     * @param isForbidden True fot forbidden, false for not forbidden.
     */
    void SetBundleForbiddenStatus(const std::string &bundleName, bool isForbidden);

private:
    /**
     * @brief Init form bundle forbid mgr.
     * @return True for sucessful init, false for failed init.
     */
    bool Init();

private:
    bool isInitialized_ = false;
    std::set<std::string> formBundleForbiddenSet_;
    mutable std::shared_mutex bundleForbiddenSetMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_BUNDLE_FORBID_MGR_H
