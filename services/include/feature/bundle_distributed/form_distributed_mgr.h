/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_DISTRIBUTED_MGR_H
#define OHOS_FORM_FWK_FORM_DISTRIBUTED_MGR_H

#include <map>
#include <shared_mutex>
#include <singleton.h>
#include <string>

#include "data_center/database/form_rdb_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormDistributedMgr
 * Form distributed manager.
 */
class FormDistributedMgr final : public DelayedRefSingleton<FormDistributedMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormDistributedMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormDistributedMgr);

    /**
     * @brief Init form bundle distributed mgr.
     * @return True for sucessful init, false for failed init.
     */
    bool Init();

    /**
     * @brief Get whether bundle is distributed.
     * @param bundleName Bundle name to be check.
     * @return True for distributed, false for not distributed.
     */
    bool IsBundleDistributed(const std::string &bundleName);

    /**
     * @brief Set whether bundle is distributed.
     * @param bundleName Bundle name to be set.
     * @param isDistributed True fot distributed, false for not distributed.
     */
    void SetBundleDistributedStatus(const std::string &bundleName, bool isDistributed);

private:
    /**
     * @brief check whether bundle distributed mgr is init.
     * @return True for inited, false for not init.
     */
    bool IsBundleDistributedInit();

private:
    bool isInitialized_ = false;
    std::set<std::string> formBundleDistributedSet_;
    mutable std::shared_mutex bundleDistributedSetMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_DISTRIBUTED_MGR_H