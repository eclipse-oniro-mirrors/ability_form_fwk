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

#include "form_report.h"
#include "form_record_report.h"

#include "fms_log_wrapper.h"
#include "form_event_report.h"
#include "form_render_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int64_t DELAY_TIME_MICROSECONDS = 10 * 1000000;
}

FormReport::FormReport()
{
    HILOG_INFO("FormReport begin");
}

FormReport::~FormReport()
{
}

void FormReport::SetFormRecordInfo(int64_t formId, const Want &want)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        formStatisticMap_[formId].bundleName_ = want.GetElement().GetBundleName();
        formStatisticMap_[formId].moduleName_ = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
        formStatisticMap_[formId].abilityName_ = want.GetElement().GetAbilityName();
        formStatisticMap_[formId].formName_ = want.GetStringParam(Constants::PARAM_FORM_NAME_KEY);
        formStatisticMap_[formId].dimensionId_ = want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0);
        return;
    }
    FormStatistic info;
    info.bundleName_ = want.GetElement().GetBundleName();
    info.moduleName_ = want.GetStringParam(Constants::PARAM_MODULE_NAME_KEY);
    info.abilityName_ = want.GetElement().GetAbilityName();
    info.formName_ = want.GetStringParam(Constants::PARAM_FORM_NAME_KEY);
    info.dimensionId_ = want.GetIntParam(Constants::PARAM_FORM_DIMENSION_KEY, 0);
    formStatisticMap_[formId] = info;
}

void FormReport::SetStartAquireTime(int64_t formId, int64_t startTime)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        formStatisticMap_[formId].startAquireTime_ = startTime;
        return;
    }
    FormStatistic tmp;
    tmp.startAquireTime_ = startTime;
    formStatisticMap_[formId] = tmp;
}

void FormReport::SetEndAquireTime(int64_t formId, int64_t endTime)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        formStatisticMap_[formId].endAquireTime_ = endTime;
    }
}

void FormReport::SetStartBindTime(int64_t formId, int64_t startTime)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        formStatisticMap_[formId].startBindTime_ = startTime;
        return;
    }
    FormStatistic tmp;
    tmp.startBindTime_ = startTime;
    formStatisticMap_[formId] = tmp;
}

void FormReport::SetEndBindTime(int64_t formId, int64_t endTime)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        formStatisticMap_[formId].endBindTime_ = endTime;
        return;
    }
}

void FormReport::SetStartGetTime(int64_t formId, int64_t startTime)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        formStatisticMap_[formId].startGetTime_ = startTime;
        return;
    }
    FormStatistic tmp;
    tmp.startGetTime_ = startTime;
    formStatisticMap_[formId] = tmp;
}

void FormReport::SetEndGetTime(int64_t formId, int64_t endTime)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        formStatisticMap_[formId].endGetTime_ = endTime;
        return;
    }
}

void FormReport::SetDurationStartTime(int64_t formId, int64_t startTime)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        formStatisticMap_[formId].durationStartTime_ = startTime;
        return;
    }
    FormStatistic tmp;
    tmp.durationStartTime_ = startTime;
    formStatisticMap_[formId] = tmp;
}

void FormReport::SetDurationEndTime(int64_t formId, int64_t endTime)
{
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        formStatisticMap_[formId].durationEndTime_ = endTime;
        HandleFirstUpdateStatistic(formId);
    }
}

void FormReport::HandleAddFormStatistic(int64_t formId)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto &record = formStatisticMap_[formId];
    if (formStatisticMap_.count(formId) == 0) {
        HILOG_INFO("Form ID not found in formStatisticMap_: %lld", formId);
        return;
    }
    NewFormEventInfo eventInfo;
    eventInfo.sessionId = 0;
    eventInfo.formId = formId;
    eventInfo.bundleName = record.bundleName_;
    eventInfo.moduleName = record.moduleName_;
    eventInfo.abilityName = record.abilityName_;
    eventInfo.formName = record.formName_;
    eventInfo.formDimension = record.dimensionId_;
    eventInfo.bindDuration = (record.endBindTime_ - record.startBindTime_);
    eventInfo.getDuration = (record.endGetTime_ - record.startGetTime_);
    eventInfo.acquireDuration = (record.endAquireTime_ - record.startAquireTime_);
    FormEventReport::SendFirstAddFormEvent(FormEventName::FIRST_ADD_FORM_DURATION,
        HiSysEventType::STATISTIC, eventInfo);
}

void FormReport::HandleFirstUpdateStatistic(int64_t formId)
{
    if (formId <= 0) {
        return;
    }
    std::lock_guard<std::mutex> guard(formReport_);
    for (auto iter = formStatisticMap_.begin(); iter != formStatisticMap_.end(); ++iter) {
        const int64_t formId = iter->first;
        FormStatistic& record = iter->second;
        float durationNow = (record.durationEndTime_ - record.durationStartTime_);
        NewFormEventInfo eventInfo;
        eventInfo.sessionId = 0;
        eventInfo.formId = formId;
        if (durationNow >= DELAY_TIME_MICROSECONDS) {
            eventInfo.durationType = 1;
        } else {
            eventInfo.durationType = 0;
        }
        eventInfo.duration = durationNow;
        FormEventReport::SendFirstUpdateFormEvent(FormEventName::FIRST_UPDATE_FORM_DURATION,
            HiSysEventType::STATISTIC, eventInfo);
    }
}

std::unordered_map<int64_t, FormStatistic>& FormReport::GetStatistic()
{
    return formStatisticMap_;
}
}  // namespace AppExecFwk
}  // namespace OHOS