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

#include "data_center/form_record/form_record_report.h"
#include "fms_log_wrapper.h"
#include "form_event_report.h"
#include "data_center/form_basic_info_mgr.h"
#include "data_center/form_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t REPORT_INFO_QUEUE_MAX_LEN = 2;
constexpr size_t REPORT_INFO_QUEUE_MIN_LEN = 1;
}

FormRecordReport::FormRecordReport()
{
}

FormRecordReport::~FormRecordReport()
{
    ClearReportInfo();
}

std::map<int64_t, std::queue<FormRecordReportInfo>>& FormRecordReport::GetFormRecords()
{
    return formRecordReportMap_;
}

void FormRecordReport::SetFormRecordRecordInfo(int64_t formId, const Want &want)
{
    FormRecordReportInfo info;
    std::lock_guard<std::mutex> guard(formRecordReportMutex_);
    if (formRecordReportMap_.find(formId) == formRecordReportMap_.end()) {
        std::queue<FormRecordReportInfo> queue;
        queue.push(info);
        formRecordReportMap_[formId] = queue;
    }
}

void FormRecordReport::IncreaseUpdateTimes(int64_t formId, HiSysEventPointType type)
{
    HILOG_DEBUG("formId:%{public}" PRId64, formId);
    std::lock_guard<std::mutex> guard(formRecordReportMutex_);
    if (formRecordReportMap_.find(formId) != formRecordReportMap_.end()) {
        auto &queue = formRecordReportMap_[formId];
        if (queue.empty()) {
            queue.push(FormRecordReportInfo());
        }
        FormRecordReportInfo &info = formRecordReportMap_[formId].back();
        switch (type) {
            case TYPE_DAILY_REFRESH:
                info.dailyRefreshTimes++;
                break;
            case TYPE_INVISIBLE_UPDATE:
                info.invisibleRefreshTimes++;
                break;
            case TYPE_HIGH_FREQUENCY:
                info.hfRefreshBlockTimes++;
                break;
            case TYPE_INVISIBLE_INTERCEPT:
                info.invisibleRefreshBlockTimes++;
                break;
            case TYPE_HIGH_LOAD:
                info.highLoadRefreshBlockTimes = 0;
                break;
            case TYPE_ACTIVE_RECVOER_UPDATE:
                info.activeRecoverRefreshTimes = 0;
                break;
            case TYPE_PASSIVE_RECOVER_UPDATE:
                info.passiveRecoverRefreshTimes++;
                break;
            case TYPE_HF_RECOVER_UPDATE:
                info.hfRecoverRefreshTimes++;
                break;
            case TYPE_OFFLOAD_RECOVER_UPDATE:
                info.offloadRecoverRefreshTimes = 0;
                break;
            case TYPE_DISABLE_FORM_INTERCEPT:
                info.disableFormRefreshTimes++;
                break;
            default:
                break;
        }
    }
}

// Reports the form refresh statistics for the previous day.
// After the report is successfully submitted, the data will be deleted.
void FormRecordReport::HandleFormRefreshCount()
{
    std::lock_guard<std::mutex> guard(formRecordReportMutex_);
    for (auto& entry : formRecordReportMap_) {
        int64_t formId = entry.first;
        auto &queue = entry.second;
        if (formId <= 0 || queue.empty()) {
            return;
        }
        FormRecord formRecord;
        (void)FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
        FormRecordReportInfo record = queue.front();
        NewFormEventInfo eventInfo;
        eventInfo.formId = formId;
        eventInfo.bundleName = FormBasicInfoMgr::GetInstance().GetFormBundleName(formId);
        eventInfo.moduleName = FormBasicInfoMgr::GetInstance().GetFormModuleName(formId);
        eventInfo.formName = FormBasicInfoMgr::GetInstance().GetFormName(formId);
        eventInfo.dailyRefreshTimes = record.dailyRefreshTimes;
        eventInfo.invisibleRefreshTimes = record.invisibleRefreshTimes;
        eventInfo.hfRefreshBlockTimes = record.hfRefreshBlockTimes;
        eventInfo.invisibleRefreshBlockTimes = record.invisibleRefreshBlockTimes;
        eventInfo.highLoadRefreshBlockTimes = record.highLoadRefreshBlockTimes;
        eventInfo.activeRecoverRefreshTimes = record.activeRecoverRefreshTimes;
        eventInfo.passiveRecoverRefreshTimes = record.passiveRecoverRefreshTimes;
        eventInfo.hfRecoverRefreshTimes = record.hfRecoverRefreshTimes;
        eventInfo.offloadRecoverRefreshTimes = record.offloadRecoverRefreshTimes;
        eventInfo.disableFormRefreshTimes = record.disableFormRefreshTimes;
        eventInfo.formDimension = formRecord.specification;
        eventInfo.isDistributedForm = formRecord.isDistributedForm;
        FormEventReport::SendFormRefreshCountEvent(FormEventName::UPDATE_FORM_REFRESH_TIMES,
            HiSysEventType::STATISTIC, eventInfo);
        while (queue.size() > REPORT_INFO_QUEUE_MIN_LEN) {
            queue.pop();
        }
    }
}

void FormRecordReport::ClearReportInfo()
{
    std::lock_guard<std::mutex> guard(formRecordReportMutex_);
    formRecordReportMap_.clear();
}

void FormRecordReport::AddNewDayReportInfo()
{
    std::lock_guard<std::mutex> guard(formRecordReportMutex_);
    for (auto &entry : formRecordReportMap_) {
        auto &queue = entry.second;
        if (queue.size() < REPORT_INFO_QUEUE_MAX_LEN) {
            FormRecordReportInfo record;
            queue.push(record);
        }
    }
}

}  // namespace AppExecFwk
}  // namespace OHOS