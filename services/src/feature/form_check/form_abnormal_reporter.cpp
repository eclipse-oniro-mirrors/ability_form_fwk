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

#include "feature/form_check/form_abnormal_reporter.h"

#include "fms_log_wrapper.h"
#include "form_event_report_define.h"
#include "form_event_report.h"
#include "common/util/form_timer_util.h"
#include "data_center/form_data_mgr.h"
#include "feature/param_update/param_control.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t PARAMS_SIZE_MAX = 50;
constexpr int32_t THRESHOLD_FOR_NONTRANSPARENCY_RATIO = 10;

inline void FillEventParams(FormAbnormalReportParams &params, const FormAbnormalInfo &info)
{
    params.bundleNames.emplace_back(info.bundleName);
    params.moduleNames.emplace_back(info.moduleName);
    params.abilityNames.emplace_back(info.abilityName);
    params.formNames.emplace_back(info.formName);
    params.formDimensions.emplace_back(info.formDimension);
    params.formLocations.emplace_back(info.formLocation);
    params.appVersions.emplace_back(info.appVersion);
    params.nonTransparencyRateList.emplace_back(info.nonTransparentRatio);
}

inline void ClearEventParams(FormAbnormalReportParams &params)
{
    params.bundleNames.clear();
    params.moduleNames.clear();
    params.abilityNames.clear();
    params.formNames.clear();
    params.formDimensions.clear();
    params.formLocations.clear();
    params.appVersions.clear();
    params.nonTransparencyRateList.clear();
}
}  // namespace

FormAbnormalReporter::FormAbnormalReporter()
{
}

FormAbnormalReporter::~FormAbnormalReporter()
{
}

void FormAbnormalReporter::CheckForms()
{
    std::set<int64_t> formIdSet;
    {
        std::lock_guard<std::mutex> lock(lastUpdateTimeSetMutex_);
        formIdSet.swap(lastUpdateTimeSet_);
    }

    ParamControl &paramControl = ParamControl::GetInstance();
    FormDataMgr &formDataMgr = FormDataMgr::GetInstance();
    std::vector<int64_t> formIds;
    FormRecord formRecord;
    for (const int64_t &formId : formIdSet) {
        bool found = formDataMgr.GetFormRecord(formId, formRecord);
        if (!found) {
            HILOG_WARN("form not found, formId:%{public}" PRId64, formId);
            continue;
        }
        if (formRecord.isSystemApp || !formRecord.transparencyEnabled) {
            continue;
        }
        if (formRecord.lockForm && formRecord.protectForm) {
            continue;
        }
        if (!formRecord.enableForm) {
            continue;
        }
        if (paramControl.IsFormDisable(formRecord) || paramControl.IsFormRemove(formRecord)) {
            continue;
        }
        formIds.emplace_back(formId);
    }

    HILOG_INFO("total:%{public}" PRIu32 " checkSize:%{public}d" PRIu32, formIdSet.size(), formIds.size());
    if (formIds.empty()) {
        return;
    }
    FormDataMgr::GetInstance().CheckForms(formIds);
}

void FormAbnormalReporter::ReportAbnormalForms()
{
    HILOG_INFO("report start");
    std::map<int64_t, FormAbnormalInfo> map;
    {
        std::lock_guard<std::mutex> lock(formAbnormalInfoMapMutex_);
        if (formAbnormalInfoMap_.empty()) {
            return;
        }
        map.swap(formAbnormalInfoMap_);
    }

    FormAbnormalReportParams params;
    int32_t total = 0;
    int32_t count = 0;
    for (const auto &mapIter : map) {
        count++;
        FillEventParams(params, mapIter.second);
        if (count >= PARAMS_SIZE_MAX) {
            FormEventReport::SendFormAbnormalEvent(params);
            ClearEventParams(params);
            total += count;
            count = 0;
        }
    }
    total += count;
    HILOG_INFO("map size:%{public}" PRIu32 " total:%{public}d remained:%{public}d", map.size(), total, count);
    if (count > 0) {
        FormEventReport::SendFormAbnormalEvent(params);
    }
}

void FormAbnormalReporter::MarkUpdateRender(int64_t formId)
{
    FormRecord formRecord;
    bool found = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!found) {
        HILOG_WARN("form not found, formId:%{public}" PRId64, formId);
        return;
    }
    if (formRecord.isSystemApp || !formRecord.transparencyEnabled) {
        return;
    }
    std::lock_guard<std::mutex> lock(lastUpdateTimeSetMutex_);
    lastUpdateTimeSet_.insert(formId);
}

void FormAbnormalReporter::AddRecord(int64_t formId, int32_t ratio)
{
    if (ratio >= THRESHOLD_FOR_NONTRANSPARENCY_RATIO) {
        return;
    }
    HILOG_INFO("formId:%{public}" PRId64 " ratio:%{public}d", formId, ratio);
    FormRecord formRecord;
    bool found = FormDataMgr::GetInstance().GetFormRecord(formId, formRecord);
    if (!found) {
        HILOG_ERROR("add record failed, form record not exist, formId:%{public}" PRId64, formId);
        return;
    }
    auto info = FormAbnormalInfo::Create(formRecord);
    info.nonTransparentRatio = ratio;
    AddRecord(formId, info);
}

void FormAbnormalReporter::AddRecord(int64_t formId, const FormAbnormalInfo &info)
{
    std::lock_guard<std::mutex> lock(formAbnormalInfoMapMutex_);
    formAbnormalInfoMap_.emplace(formId, info);
}

void FormAbnormalReporter::ClearRecords()
{
    std::lock_guard<std::mutex> lock(formAbnormalInfoMapMutex_);
    formAbnormalInfoMap_.clear();
}
}  // namespace AppExecFwk
}  // namespace OHOS