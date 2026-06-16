/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_FORM_EXEMPT_LOCK_MGR_H
#define OHOS_FORM_FWK_FORM_EXEMPT_LOCK_MGR_H

#include <map>
#include <shared_mutex>
#include <singleton.h>
#include <string>

#include "want.h"
#include "data_center/database/form_rdb_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormExemptLockMgr
 * Form bundle exempt manager.
 */
class FormExemptLockMgr final : public DelayedRefSingleton<FormExemptLockMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormExemptLockMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormExemptLockMgr);

    /**
     * @brief Get whether bundle is exempt.
     * @param formId The Id of the forms.
     * @return True for exempt, false for not exempt.
     */
    bool IsExemptLock(int64_t formId);

    /**
     * @brief Set whether form is exempt.
     * @param formId The Id of the forms.
     * @param isExempt True for exempt, false for not exempt.
     */
    void SetExemptLockStatus(int64_t formId, bool isExempt);

private:
    /**
     * @brief Init form bundle exempt mgr.
     * @return True for sucessful init, false for failed init.
     */
    bool Init();

private:
    bool isInitialized_ = false;
    std::set<std::string> formExemptLockSet_;
    mutable std::shared_mutex exemptLockSetMutex_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_EXEMPT_LOCK_MGR_H
