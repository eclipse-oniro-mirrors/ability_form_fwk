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
#ifndef OHOS_FORM_FWK_FORM_BUNDLE_LOCK_MGR_H
#define OHOS_FORM_FWK_FORM_BUNDLE_LOCK_MGR_H

#include <map>
#include <shared_mutex>
#include <singleton.h>
#include <string>

#include "want.h"
#include "data_center/database/form_rdb_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormBundleLockMgr
 * Form bundle lock manager.
 */
class FormBundleLockMgr final : public DelayedRefSingleton<FormBundleLockMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormBundleLockMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormBundleLockMgr);

    /**
     * @brief Get whether bundle is lock.
     * @param bundleName Bundle name to be check.
     * @return True for lock, false for not lock.
     */
    bool IsBundleLock(const std::string &bundleName, int64_t formId = 0);

    /**
     * @brief Set whether bundle is lock.
     * @param bundleName Bundle name to be set.
     * @param isLock True fot lock, false for not lock.
     */
    void SetBundleLockStatus(const std::string &bundleName, bool isLock);

    /**
     * @brief Get whether bundle is protect.
     * @param bundleName Bundle name to be check.
     * @return True for protect, false for not protect.
     */
    bool IsBundleProtect(const std::string &bundleName, int64_t formId = 0);

    /**
     * @brief Set whether bundle is protect.
     * @param bundleName Bundle name to be set.
     * @param isProtect True for protect, false for not protect.
     */
    void SetBundleProtectStatus(const std::string &bundleName, bool isProtect);

private:
    /**
     * @brief Init form bundle lock mgr.
     * @return True for sucessful init, false for failed init.
     */
    bool Init();

private:
    bool isInitialized_ = false;
    std::set<std::string> formBundleLockSet_;
    mutable std::shared_mutex bundleLockSetMutex_;
    std::set<std::string> formBundleProtectSet_;
    mutable std::shared_mutex bundleProtectSetMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_BUNDLE_LOCK_MGR_H
