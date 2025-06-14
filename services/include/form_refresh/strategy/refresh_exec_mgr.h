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

#ifndef OHOS_FORM_FWK_REFRESH_EXEC_MGR_H
#define OHOS_FORM_FWK_REFRESH_EXEC_MGR_H

#include "data_center/form_record/form_record.h"
#include "form_constants.h"
#include "form_provider_data.h"

namespace OHOS {
namespace AppExecFwk {
/**
* @class RefreshExecMgr
* RefreshExecMgr is used to execute form refresh task.
*/
class RefreshExecMgr {
public:
    /**
     * @brief Ask for provider data to refresh form.
     * @param formId The formId.
     * @param record The form record.
     * @param want The want of the form to refresh.
     */
    static ErrCode AskForProviderData(const int64_t formId, const FormRecord &record, const Want &want);

    /**
     * @brief update provider data to form page.
     * @param formId The formId.
     * @param formProviderData The form refresh data.
     * @param mergeData Whether to merge record data and new data.
     */
    static ErrCode UpdateByProviderData(const int64_t formId, const FormProviderData &formProviderData, bool mergeData);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif