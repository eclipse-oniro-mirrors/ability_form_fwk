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

#include "common/util/form_report.h"
#include "data_center/form_record/form_record_report.h"

#include "fms_log_wrapper.h"
#include "form_event_report.h"
#include "form_render/form_render_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int64_t DELAY_TIME_MICROSECONDS = 10 * 1000;
}

FormReport::FormReport()
{
    HILOG_INFO("begin");
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

void FormReport::GetEndAquireTime(int64_t formId, int64_t &endTime)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        endTime = formStatisticMap_[formId].endAquireTime_;
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
    tmp.durationEndTime_ = 0;
    formStatisticMap_[formId] = tmp;
}

void FormReport::SetDurationEndTime(int64_t formId, int64_t endTime)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        if (!formStatisticMap_[formId].durationEndTime_) {
            formStatisticMap_[formId].durationEndTime_ = endTime;
            HandleFirstUpdateStatistic(formId);
        }
    }
}

void FormReport::GetAddFormFinish(int64_t formId, bool &addFormFinish)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        addFormFinish = formStatisticMap_[formId].addFormFinish;
    }
}

void FormReport::SetAddFormFinish(int64_t formId)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto it = formStatisticMap_.find(formId);
    if (it != formStatisticMap_.end()) {
        if (!formStatisticMap_[formId].addFormFinish) {
            formStatisticMap_[formId].addFormFinish = true;
        }
    }
}

void FormReport::InsertFormId(int64_t formId)
{
    std::lock_guard<std::mutex> guard(formIdsMutex_);
    formIds_.insert(formId);
}

void FormReport::RemoveFormId(int64_t formId)
{
    std::lock_guard<std::mutex> guard(formIdsMutex_);
    if (formIds_.find(formId) != formIds_.end()) {
        formIds_.erase(formId);
    }
}

bool FormReport::HasFormId(int64_t formId)
{
    std::lock_guard<std::mutex> guard(formIdsMutex_);
    return formIds_.find(formId) != formIds_.end();
}

void FormReport::HandleAddFormStatistic(int64_t formId)
{
    std::lock_guard<std::mutex> guard(formReport_);
    auto &record = formStatisticMap_[formId];
    if (formStatisticMap_.count(formId) == 0) {
        HILOG_INFO("invalid formId:%{public}" PRId64, formId);
        return;
    }
    if (HasFormId(formId)) {
        HILOG_ERROR("hisysevent yet formid:%{public}" PRId64, formId);
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
    if (record.endBindTime_ > record.startBindTime_) {
        eventInfo.bindDuration = (record.endBindTime_ - record.startBindTime_);
    } else {
        eventInfo.bindDuration = 0;
        HILOG_ERROR("bindDuration error formid:%{public}" PRId64, formId);
    }
    if (record.endGetTime_ > record.startGetTime_) {
        eventInfo.getDuration = (record.endGetTime_ - record.startGetTime_);
    } else {
        eventInfo.bindDuration = 0;
        HILOG_ERROR("getDuration error formid:%{public}" PRId64, formId);
    }
    eventInfo.acquireDuration = (record.endAquireTime_ - record.startAquireTime_);
    FormEventReport::SendFirstAddFormEvent(FormEventName::FIRST_ADD_FORM_DURATION,
        HiSysEventType::STATISTIC, eventInfo);
    InsertFormId(formId);
}

void FormReport::HandleFirstUpdateStatistic(int64_t formId)
{
    if (formId <= 0) {
        return;
    }
    NewFormEventInfo eventInfo;
    for (auto iter = formStatisticMap_.begin(); iter != formStatisticMap_.end(); ++iter) {
        if (formId == iter->first) {
            FormStatistic& record = iter->second;
            if (!record.durationStartTime_) {
                return;
            }
            int64_t durationNow = (record.durationEndTime_ - record.durationStartTime_);
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
            iter->second.durationStartTime_ = 0;
        }
    }
}

std::unordered_map<int64_t, FormStatistic>& FormReport::GetStatistic()
{
    return formStatisticMap_;
}
}  // namespace AppExecFwk
}  // namespace OHOS