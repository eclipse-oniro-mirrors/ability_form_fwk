/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_REPORT_H
#define OHOS_FORM_FWK_FORM_REPORT_H

#include <queue>
#include <singleton.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "form_render/form_render_mgr.h"

namespace OHOS {
namespace AppExecFwk {
struct FormStatistic {
public:
    std::string bundleName_;
    std::string moduleName_;
    std::string abilityName_;
    std::string formName_;
    int32_t specificationId_;
    int32_t dimensionId_;
    int64_t formId_;
    int64_t startAquireTime_;
    int64_t endAquireTime_;
    int64_t startBindTime_;
    int64_t endBindTime_;
    int64_t startGetTime_;
    int64_t endGetTime_;
    int64_t durationStartTime_;
    int64_t durationEndTime_;
};

class FormReport final : public DelayedRefSingleton<FormReport> {
DECLARE_DELAYED_REF_SINGLETON(FormReport)
public:
    DISALLOW_COPY_AND_MOVE(FormReport);
public:
    void SetFormRecordInfo(int64_t formId, const Want &want);
    void SetStartAquireTime(int64_t formId, int64_t startTime);
    void SetEndAquireTime(int64_t formId, int64_t endTime);
    void GetEndAquireTime(int64_t formId, int64_t &endTime);
    void SetStartBindTime(int64_t formId, int64_t startTime);
    void SetEndBindTime(int64_t formId, int64_t endBindTime_);
    void SetStartGetTime(int64_t formId, int64_t startTime);
    void SetEndGetTime(int64_t formId, int64_t endTime);
    void SetDurationStartTime(int64_t formId, int64_t startTime);
    void SetDurationEndTime(int64_t formId, int64_t endTime);
    void HandleAddFormStatistic(int64_t formId);
    void HandleFirstUpdateStatistic(int64_t formId);
    void InsertFormId(int64_t formId);
    void RemoveFormId(int64_t formId);
    bool HasFormId(int64_t formId);
    std::unordered_map<int64_t, FormStatistic>& GetStatistic();

private:
    mutable std::mutex formReport_;
    mutable std::mutex formIdsMutex_;
    std::unordered_map<int64_t, FormStatistic> formStatisticMap_;
    std::set<int64_t> formIds_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_REPORT_H