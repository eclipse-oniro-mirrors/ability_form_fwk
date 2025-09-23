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

#include "feature/memory_mgr/form_render_report.h"
#include "form_event_report.h"
#include "common/util/form_util.h"
#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"
#include "form_render/form_render_mgr_inner.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
    constexpr int8_t FRS_DEAD = 0;
    constexpr int8_t FRS_START = 1;
    constexpr int8_t FRS_STATUS_MAX_COUNT = 20;
}

/**
 * @class FormRenderReady
 * FormRenderReady is used to call frs report.
 */
FormRenderReport::FormRenderReport() {}

FormRenderReport::~FormRenderReport() {}

void FormRenderReport::RecordFRSStart()
{
    HILOG_INFO("call");
    if (isFRSFirstLoaded_.load()) {
        isFRSFirstLoaded_.store(false);
        RecordFRSStatus(FRS_START);
    }
}

void FormRenderReport::RecordFRSDead()
{
    HILOG_INFO("call");
    if (!isFRSFirstLoaded_.load()) {
        isFRSFirstLoaded_.store(true);
    }
    RecordFRSStatus(FRS_DEAD);
}

void FormRenderReport::RecordFRSStatus(uint8_t status)
{
    std::unique_lock<std::mutex> lock(frsStatusRecordsMutex_);
    if (frsStatusRecords_.size() < FRS_STATUS_MAX_COUNT) {
        int64_t formCount = GetAllFormsCount();
        bool isLowMemory = FormDataMgr::GetInstance().IsLowMemory();
        HILOG_INFO("formCount:  %{public}" PRId64 ", isLowMemory: %{public}d", formCount, isLowMemory);
        FormRenderStatusRecord record = {
            .isLowMemory = isLowMemory,
            .status = status,
            .formCount = formCount,
            .occurrenceTime = FormUtil::GetNowMillisecond()
        };
        frsStatusRecords_.push_back(record);
    }
}

void FormRenderReport::ReportFRSStatus()
{
    HILOG_INFO("call");
    {
        std::unique_lock<std::mutex> lock(frsStatusRecordsMutex_);
        if (frsStatusRecords_.empty()) {
            return;
        }
    }
    std::vector<bool> isLowMemoryList;
    std::vector<uint8_t> statusList;
    std::vector<int32_t> formCountList;
    std::vector<int64_t> occurrenceTimeList;
    {
        std::unique_lock<std::mutex> lock(frsStatusRecordsMutex_);
        for (const auto &iter : frsStatusRecords_) {
            isLowMemoryList.push_back(iter.isLowMemory);
            statusList.push_back(iter.status);
            formCountList.push_back(iter.formCount);
            occurrenceTimeList.push_back(iter.occurrenceTime);
        }
        frsStatusRecords_.clear();
    }
    FormEventReport::SendFRSStatusEvent(isLowMemoryList, statusList, formCountList, occurrenceTimeList);
}

int32_t FormRenderReport::GetAllFormsCount()
{
    int32_t tempFormsCount;
    FormDataMgr::GetInstance().GetTempFormsCount(tempFormsCount);
    int32_t castFormsCount;
    FormDataMgr::GetInstance().GetCastFormsCount(castFormsCount);
    return tempFormsCount + castFormsCount;
}
}
}
