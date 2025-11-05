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

#ifndef OHOS_FORM_FWK_FORM_ABNORMAL_REPORTER_H
#define OHOS_FORM_FWK_FORM_ABNORMAL_REPORTER_H

#include <singleton.h>
#include <mutex>
#include <map>
#include <set>
#include <vector>

#include "data_center/form_record/form_record.h"
#include "feature/form_check/form_abnormal_info.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * Periodically check whether the form layout complies with the specifications.
 * And periodically report the abnormal forms.
 */
class FormAbnormalReporter final : public DelayedRefSingleton<FormAbnormalReporter> {
    DECLARE_DELAYED_REF_SINGLETON(FormAbnormalReporter)
public:
    DISALLOW_COPY_AND_MOVE(FormAbnormalReporter);

    void CheckForms();
    void ReportAbnormalForms();
    void MarkUpdateRender(int64_t formId);
    void AddRecord(int64_t formId, int32_t ratio);

private:
    void AddRecord(int64_t formId, const FormAbnormalInfo &info);
    void ClearRecords();

    mutable std::mutex lastUpdateTimeSetMutex_;
    std::set<int64_t> lastUpdateTimeSet_;
    mutable std::mutex formRecorderTimerMutex_;
    int32_t recorderTimerId_;
    mutable std::mutex formAbnormalInfoMapMutex_;
    std::map<int64_t, FormAbnormalInfo> formAbnormalInfoMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_ABNORMAL_REPORTER_H