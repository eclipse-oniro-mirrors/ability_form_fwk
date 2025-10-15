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

#include "feature/param_update/param_control.h"

#include "fms_log_wrapper.h"
#include "json_serializer.h"
#include "data_center/form_data_mgr.h"
#include "common/timer_mgr/form_timer_mgr.h"
#include "form_refresh/strategy/refresh_cache_mgr.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string DUE_PARAM_UPDATE_CTRL = "formUpdateDurationCtrl";
const std::string DUE_PARAM_DISABLE_CTRL = "formDisableCtrl";
const std::string DUE_PARAM_BUNDLENAME = "bundleName";
const std::string DUE_PARAM_MODULENAME = "moduleName";
const std::string DUE_PARAM_ABILITYNAME = "abilityName";
const std::string DUE_PARAM_FORMNAME = "formName";
const std::string DUE_PARAM_DIMENSION = "dimension";
const std::string DUE_PARAM_APP_VERSION_START = "appVersionStart";
const std::string DUE_PARAM_APP_VERSION_END = "appVersionEnd";
const std::string DUE_PARAM_UPDATE_DURATION = "updateDuration";
const std::string DUE_PARAM_POLICY = "policy";
const std::string DUE_POLICY_DISABLE = "disable";
const std::string DUE_POLICY_REMOVE = "remove";
}

ParamControl::ParamControl() {}
ParamControl::~ParamControl() {}

void ParamControl::DealDueParam(const std::string &jsonStr)
{
    if (jsonStr.empty()) {
        HILOG_WARN("due control param empty.");
        return;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(jsonStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        HILOG_ERROR("fail parse jsonStr: %{public}s.", jsonStr.c_str());
        return;
    }
    if (!jsonObject.is_object()) {
        HILOG_ERROR("jsonStr not object");
        return;
    }

    ParamTransfer();
    ParseJsonToObj(jsonObject);

    // Restore old configuration
    ExecUpdateDurationCtrl(false, preUpdateDurationCtrl_);
    ExecDisableCtrl(false, preDisableCtrl_);

    // Apply new configuration
    ExecUpdateDurationCtrl(true, nextUpdateDurationCtrl_);
    ExecDisableCtrl(true, nextDisableCtrl_);
}

int32_t ParamControl::GetDueUpdateDuration(const FormRecord &formRecord)
{
    if (nextUpdateDurationCtrl_.empty()) {
        // due update duration not configured
        return Constants::DUE_INVALID_UPDATE_DURATION;
    }

    for (const auto &item : nextUpdateDurationCtrl_) {
        if (!IsFormInfoMatch(formRecord, item)) {
            continue;
        }

        HILOG_INFO("updateDuration:%{public}d, formId:%{public}" PRId64, item.updateDuration, formRecord.formId);
        return item.updateDuration;
    }
    // no matching the application control found.
    return Constants::DUE_INVALID_UPDATE_DURATION;
}

bool ParamControl::IsFormDisable(const FormRecord &formRecord)
{
    for (const auto &item : nextDisableCtrl_) {
        if (item.policy != DUE_POLICY_DISABLE) {
            continue;
        }
        if (IsFormInfoMatch(formRecord, item)) {
            HILOG_INFO("due form disable, %{public}" PRId64, formRecord.formId);
            return true;
        }
    }
    return false;
}

bool ParamControl::IsFormRemove(const FormRecord &formRecord)
{
    for (const auto &item : nextDisableCtrl_) {
        if (item.policy != DUE_POLICY_REMOVE) {
            continue;
        }
        if (IsFormInfoMatch(formRecord, item)) {
            HILOG_INFO("due form remove, %{public}" PRId64, formRecord.formId);
            return true;
        }
    }
    return false;
}

void ParamControl::ReloadDueControlByAppUpgrade(const std::vector<FormRecord> &formRecords)
{
    if (formRecords.size() == 0) {
        HILOG_DEBUG("formRecords empty");
        return;
    }

    // Restore old formrecord
    ExecUpdateDurationCtrl(false, nextUpdateDurationCtrl_, true);
    ExecDisableCtrl(false, nextDisableCtrl_, true);

    // Apply new formrecord
    ExecUpdateDurationCtrl(true, nextUpdateDurationCtrl_);
    ExecDisableCtrl(true, nextDisableCtrl_);
}

void ParamControl::ParamTransfer()
{
    HILOG_INFO("call");
    preUpdateDurationCtrl_.clear();
    preDisableCtrl_.clear();
    preUpdateDurationCtrl_.swap(nextUpdateDurationCtrl_);
    preDisableCtrl_.swap(nextDisableCtrl_);
    nextUpdateDurationCtrl_.clear();
    nextDisableCtrl_.clear();
}

void ParamControl::ParseJsonToObj(const nlohmann::json &jsonObject)
{
    if (jsonObject.contains(DUE_PARAM_UPDATE_CTRL) && !jsonObject.at(DUE_PARAM_UPDATE_CTRL).is_null() &&
        jsonObject.at(DUE_PARAM_UPDATE_CTRL).is_array()) {
        auto formUpdateCtrls = jsonObject.at(DUE_PARAM_UPDATE_CTRL).get<std::vector<ParamCtrl>>();
        for (auto &item : formUpdateCtrls) {
            if (IsParamValid(item, false)) {
                nextUpdateDurationCtrl_.push_back(item);
            }
        }
    }

    if (jsonObject.contains(DUE_PARAM_DISABLE_CTRL) && !jsonObject.at(DUE_PARAM_DISABLE_CTRL).is_null() &&
        jsonObject.at(DUE_PARAM_DISABLE_CTRL).is_array()) {
        auto formDisableCtrls = jsonObject.at(DUE_PARAM_DISABLE_CTRL).get<std::vector<ParamCtrl>>();
        for (auto &item : formDisableCtrls) {
            if (IsParamValid(item, true)) {
                nextDisableCtrl_.push_back(item);
            }
        }
    }

    HILOG_INFO("nextUpdateDurationCtrl_ size:%{public}zu, nextDisableCtrl_ size:%{public}zu",
        nextUpdateDurationCtrl_.size(), nextDisableCtrl_.size());
}

bool ParamControl::IsParamValid(ParamCtrl &paramCtrl, bool isDisableCtrl)
{
    if (paramCtrl.bundleName.empty() || paramCtrl.moduleName.empty()) {
        HILOG_ERROR("due param bundleName or moduleName empty");
        return false;
    }

    if (paramCtrl.appVersionStart > paramCtrl.appVersionEnd) {
        HILOG_ERROR("due param appVersionStart exceeds appVersionEnd");
        return false;
    }

    if (!isDisableCtrl && !(paramCtrl.updateDuration >= 0 &&
        paramCtrl.updateDuration <= Constants::MAX_CONFIG_DURATION)) {
        HILOG_WARN("due param updateDuration invalid: %{public}d", paramCtrl.updateDuration);
        paramCtrl.updateDuration = 0;
        return true;
    }

    if (isDisableCtrl && paramCtrl.policy != DUE_POLICY_DISABLE && paramCtrl.policy != DUE_POLICY_REMOVE) {
        HILOG_ERROR("due param policy invalid: %{public}s", paramCtrl.policy.c_str());
        return false;
    }
    return true;
}

bool ParamControl::IsFormInfoMatch(const FormRecord &formRecord, const ParamCtrl &paramCtrl, const bool isNewVersion)
{
    if (formRecord.bundleName != paramCtrl.bundleName) {
        return false;
    }

    if (formRecord.moduleName != paramCtrl.moduleName) {
        return false;
    }

    if (!paramCtrl.abilityName.empty() && formRecord.abilityName != paramCtrl.abilityName) {
        return false;
    }

    if (!paramCtrl.formName.empty() && formRecord.formName != paramCtrl.formName) {
        return false;
    }

    auto it = std::find(paramCtrl.dimensions.begin(), paramCtrl.dimensions.end(), formRecord.specification);
    if (!paramCtrl.dimensions.empty() && it == paramCtrl.dimensions.end()) {
        return false;
    }

    if (paramCtrl.appVersionStart == 0 && paramCtrl.appVersionEnd == 0) {
        return true;
    }

    if (formRecord.lastVersionCode == 0 || formRecord.versionCode == formRecord.lastVersionCode) {
        return formRecord.versionCode >= paramCtrl.appVersionStart && formRecord.versionCode <= paramCtrl.appVersionEnd;
    }

    uint32_t compareVersion = isNewVersion ? formRecord.versionCode : formRecord.lastVersionCode;
    return compareVersion >= paramCtrl.appVersionStart && compareVersion <= paramCtrl.appVersionEnd;
}

bool ParamControl::IsSameUpdateDuration(const FormRecord &formRecord,
    const ParamCtrl &paramCtrl, const std::vector<ParamCtrl> &compareCtrls)
{
    for (const auto &item : compareCtrls) {
        if (IsFormInfoMatch(formRecord, item) && paramCtrl.updateDuration == item.updateDuration) {
            return true;
        }
    }

    return false;
}

bool ParamControl::IsSamePolicy(const FormRecord &formRecord,
    const ParamCtrl &paramCtrl, const std::vector<ParamCtrl> &compareCtrls)
{
    for (const auto &item : compareCtrls) {
        if (IsFormInfoMatch(formRecord, item) && paramCtrl.policy == item.policy) {
            return true;
        }
    }

    return false;
}

void ParamControl::ExecUpdateDurationCtrl(const bool isApply, const std::vector<ParamCtrl> &paramCtrls,
    const bool isAppUpgrade)
{
    HILOG_INFO("call, isApply:%{public}d, isAppUpgrade:%{public}d", isApply, isAppUpgrade);
    for (const auto &item : paramCtrls) {
        std::vector<FormRecord> formRecords;
        if (!FormDataMgr::GetInstance().GetFormRecord(item.bundleName, item.moduleName, formRecords)) {
            HILOG_WARN("can not find form record");
            continue;
        }

        for (const auto &formRecord : formRecords) {
            if (!ShouldProcessForm(formRecord, item, isApply, isAppUpgrade)) {
                continue;
            }

            FormTimerCfg timerCfg;
            timerCfg.enableUpdate = true;
            timerCfg.updateDuration =
                isApply ? (item.updateDuration * Constants::TIME_CONVERSION) : formRecord.updateDuration;
            if (!isApply && item.updateDuration == 0) {
                FormTimerMgr::GetInstance().AddFormTimer(
                    formRecord.formId, timerCfg.updateDuration, formRecord.providerUserId);
            } else {
                FormTimerMgr::GetInstance().UpdateFormTimer(formRecord.formId, TYPE_INTERVAL_CHANGE, timerCfg);
            }
            HILOG_INFO("update interval period to %{public}" PRId64 ", formId:%{public}" PRId64,
                timerCfg.updateDuration, formRecord.formId);
        }
    }
}

void ParamControl::ExecDisableCtrl(const bool isApply, const std::vector<ParamCtrl> &paramCtrls,
    const bool isAppUpgrade)
{
    HILOG_INFO("call, isApply:%{public}d, isAppUpgrade:%{public}d", isApply, isAppUpgrade);
    std::vector<FormRecord> disableFormRecords;
    std::vector<FormRecord> removeFormRecords;
    for (const auto &item : paramCtrls) {
        std::vector<FormRecord> formRecords;
        if (!FormDataMgr::GetInstance().GetFormRecord(item.bundleName, item.moduleName, formRecords)) {
            HILOG_WARN("can not find form record");
            continue;
        }

        for (const auto &formRecord : formRecords) {
            if (!IsFormInfoMatch(formRecord, item, isApply)) {
                continue;
            }

            if (isAppUpgrade && IsFormInfoMatch(formRecord, item)) {
                continue;
            }

            if (item.policy == DUE_POLICY_DISABLE &&
                (isAppUpgrade || !IsSamePolicy(formRecord, item, (isApply ? preDisableCtrl_ : nextDisableCtrl_)))) {
                HILOG_INFO("exec disable ctrl, formId:%{public}" PRId64, formRecord.formId);
                disableFormRecords.push_back(formRecord);
                continue;
            }

            if (item.policy == DUE_POLICY_REMOVE &&
                (isAppUpgrade || !IsSamePolicy(formRecord, item, (isApply ? preDisableCtrl_ : nextDisableCtrl_)))) {
                HILOG_INFO("exec remove ctrl, formId:%{public}" PRId64, formRecord.formId);
                removeFormRecords.push_back(formRecord);
                continue;
            }
        }
    }

    if (!isApply) {
        RefreshCacheMgr::GetInstance().CosumeRefreshByDueControl(disableFormRecords);
    }
    FormDataMgr::GetInstance().DueControlForms(std::move(disableFormRecords), true, isApply);
    FormDataMgr::GetInstance().DueControlForms(std::move(removeFormRecords), false, isApply);
}

bool ParamControl::ShouldProcessForm(const FormRecord &formRecord, const ParamCtrl &item,
    const bool isApply, const bool isAppUpgrade)
{
    if (!formRecord.isEnableUpdate || formRecord.updateDuration == 0) {
        // interval refresh not configured
        return false;
    }

    if (!IsFormInfoMatch(formRecord, item, isApply)) {
        return false;
    }

    if (!isAppUpgrade &&
        IsSameUpdateDuration(formRecord, item, (isApply ? preUpdateDurationCtrl_ : nextUpdateDurationCtrl_))) {
        return false;
    }

    if (isAppUpgrade && IsFormInfoMatch(formRecord, item)) {
        return false;
    }

    if (isApply && item.updateDuration == 0) {
        HILOG_INFO("disable interval refresh, formId:%{public}" PRId64, formRecord.formId);
        FormTimerMgr::GetInstance().DeleteIntervalTimer(formRecord.formId);
        return false;
    }

    if (isApply && formRecord.updateDuration >= (item.updateDuration * Constants::TIME_CONVERSION)) {
        // interval period need not change
        return false;
    }

    return true;
}

void from_json(const nlohmann::json &jsonObject, ParamCtrl &paramCtrl)
{
    paramCtrl.bundleName = jsonObject.value(DUE_PARAM_BUNDLENAME, "");
    paramCtrl.moduleName = jsonObject.value(DUE_PARAM_MODULENAME, "");
    paramCtrl.abilityName = jsonObject.value(DUE_PARAM_ABILITYNAME, "");
    paramCtrl.formName = jsonObject.value(DUE_PARAM_FORMNAME, "");
    paramCtrl.dimensions = jsonObject.value(DUE_PARAM_DIMENSION, std::vector<int32_t>());
    paramCtrl.appVersionStart = jsonObject.value(DUE_PARAM_APP_VERSION_START, 0);
    paramCtrl.appVersionEnd = jsonObject.value(DUE_PARAM_APP_VERSION_END, 0);
    paramCtrl.updateDuration = jsonObject.value(DUE_PARAM_UPDATE_DURATION, Constants::DUE_INVALID_UPDATE_DURATION);
    paramCtrl.policy = jsonObject.value(DUE_PARAM_POLICY, "");
}
} // namespace AppExecFwk
} // namespace OHOS