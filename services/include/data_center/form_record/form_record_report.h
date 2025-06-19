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

#ifndef OHOS_FORM_FWK_FORM_RECORD_REPORT_H
#define OHOS_FORM_FWK_FORM_RECORD_REPORT_H

#include <singleton.h>
#include <string>
#include <mutex>
#include <map>
#include "form_render/form_render_mgr.h"

namespace OHOS {
namespace AppExecFwk {
enum HiSysEventPointType {
    TYPE_DAILY_REFRESH,
    TYPE_INVISIBLE_UPDATE,
    TYPE_HIGH_FREQUENCY,
    TYPE_INVISIBLE_INTERCEPT,
    TYPE_HIGH_LOAD,
    TYPE_ACTIVE_RECVOER_UPDATE,
    TYPE_PASSIVE_RECOVER_UPDATE,
    TYPE_HF_RECOVER_UPDATE,
    TYPE_OFFLOAD_RECOVER_UPDATE,
    TYPE_DISABLE_FORM_INTERCEPT,
};

struct FormRecordReportInfo {
    int32_t dailyRefreshTimes;
    int32_t invisibleRefreshTimes;
    int32_t hfRefreshBlockTimes;
    int32_t invisibleRefreshBlockTimes;
    int32_t highLoadRefreshBlockTimes;
    int32_t activeRecoverRefreshTimes;
    int32_t passiveRecoverRefreshTimes;
    int32_t hfRecoverRefreshTimes;
    int32_t offloadRecoverRefreshTimes;
    int32_t disableFormRefreshTimes;
};

class FormRecordReport final : public DelayedRefSingleton<FormRecordReport> {
DECLARE_DELAYED_REF_SINGLETON(FormRecordReport)
public:
    DISALLOW_COPY_AND_MOVE(FormRecordReport);
public:
    void ClearReportInfo();
    void IncreaseUpdateTimes(int64_t formId, HiSysEventPointType type);
    std::map<int64_t, std::queue<FormRecordReportInfo>> &GetFormRecords();
    void SetFormRecordRecordInfo(int64_t formId, const Want &want);
    void HandleFormRefreshCount();
    void AddNewDayReportInfo();
private:
    mutable std::mutex formRecordReportMutex_;
    std::map<int64_t, std::queue<FormRecordReportInfo>> formRecordReportMap_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_RECORD_REPORT_H