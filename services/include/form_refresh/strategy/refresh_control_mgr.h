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

#ifndef OHOS_FORM_FWK_REFRESH_CONTROL_MGR_H
#define OHOS_FORM_FWK_REFRESH_CONTROL_MGR_H

#include <singleton.h>

#include "data_center/form_record/form_record.h"
#include "form_constants.h"

namespace OHOS {
namespace AppExecFwk {
/**
* @class RefreshControlMgr
* RefreshControlMgr is used to check form refresh be controlled.
*/
class RefreshControlMgr : public DelayedRefSingleton<RefreshControlMgr> {
    DECLARE_DELAYED_REF_SINGLETON(RefreshControlMgr);
public:
    DISALLOW_COPY_AND_MOVE(RefreshControlMgr);

#ifdef RES_SCHEDULE_ENABLE
    /**
     * @brief Set the system load exceeding the refresh limit flag.
     * @param flag The value of whether Refresh Timer task should be controlled.
     */
    void SetSystemOverloadFlag(bool flag);
#endif

    /**
     * @brief Whether the system load exceeding the refresh limit.
     */
    bool IsSystemOverload();

    /**
     * @brief Whether the refresh form is invisible.
     */
    bool IsFormInvisible(const FormRecord &record);

    /**
     * @brief Whether the device screen off.
     */
    bool IsScreenOff(const FormRecord &record);

    /**
     * @brief Whether The application corresponding to the form is under health control.
     */
    bool IsHealthyControl(const FormRecord &record);

    /**
     * @brief Whether the form need fresh.
     */
    bool IsNeedToFresh(FormRecord &record, bool isVisibleToFresh);

    /**
     * @brief Whether the form add finish.
     */
    bool IsAddFormFinish(const int64_t formId);

private:
#ifdef RES_SCHEDULE_ENABLE
    std::atomic<bool> isSystemOverload_{false};
#endif
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_REFRESH_CONTROL_MGR_H