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

#include "form_refresh/strategy/refresh_cache_mgr.h"

#include "form_refresh/strategy/refresh_exec_mgr.h"
#include "common/util/form_util.h"
#include "data_center/form_data_mgr.h"
#include "data_center/form_record/form_record_report.h"
#include "fms_log_wrapper.h"
#include "form_refresh/form_refresh_mgr.h"

namespace OHOS {
namespace AppExecFwk {

RefreshCacheMgr::RefreshCacheMgr() {}
RefreshCacheMgr::~RefreshCacheMgr() {}

void RefreshCacheMgr::AddToOverloadTaskQueue(const FormTimer &task)
{
    HILOG_WARN("add overload formId:%{public} " PRId64 ", userId:%{public}d", task.formId, task.userId);
    std::lock_guard<std::mutex> lock(overloadTaskMutex_);
    for (auto &item : overloadTask_) {
        if (item.formId == task.formId && item.userId == task.userId) {
            item = task;
            HILOG_INFO("already exists, update task");
            return;
        }
    }
    overloadTask_.emplace_back(task);
    return;
}

void RefreshCacheMgr::ConsumeOverloadTaskQueue()
{
    std::vector<FormTimer> tasksToProcess;
    {
        std::lock_guard<std::mutex> lock(overloadTaskMutex_);
        tasksToProcess.swap(overloadTask_);
    }
    for (const auto &item : tasksToProcess) {
        HILOG_INFO("cosume overload task(formId:%{public}" PRId64 ", userId:%{public}d)", item.formId, item.userId);
        RefreshData data;
        data.formId = item.formId;
        data.formTimer = item;
        FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_TIMER);
    }
}

void RefreshCacheMgr::AddFlagByHealthyControl(const int64_t formId, bool isAskForProviderData)
{
    HILOG_WARN("healthy control formId:%{public}" PRId64", ask for data:%{public}d", formId, isAskForProviderData);
    if (isAskForProviderData) {
        FormDataMgr::GetInstance().SetRefreshDuringDisableForm(formId, true);
    } else {
        FormDataMgr::GetInstance().SetUpdateDuringDisableForm(formId, true);
    }
}

void RefreshCacheMgr::ConsumeHealthyControlFlag(std::vector<FormRecord>::iterator &record, const int32_t userId)
{
    HILOG_INFO("formId:%{public}" PRId64  ",isRefresh: %{public}d ,isUpdate: %{public}d", record->formId,
        record->isRefreshDuringDisableForm, record->isUpdateDuringDisableForm);
    if (record->isRefreshDuringDisableForm) {
        FormDataMgr::GetInstance().SetRefreshDuringDisableForm(record->formId, false);
        Want want = CreateWant(record, userId);
        RefreshData data;
        data.formId = record->formId;
        data.record = *record;
        data.want = want;
        FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_UNCONTROL);
    }
    if (record->isUpdateDuringDisableForm) {
        FormDataMgr::GetInstance().SetUpdateDuringDisableForm(record->formId, false);
        FormProviderData data = record->formProviderInfo.GetFormData();
        RefreshExecMgr::UpdateByProviderData(record->formId, data, true);
    }
}

void RefreshCacheMgr::AddFlagByInvisible(const int64_t formId, int refreshType)
{
    HILOG_WARN("add invisible form:%{public}" PRId64", refreshType:%{public}d", formId, refreshType);
    FormDataMgr::GetInstance().SetNeedRefresh(formId, true);
    FormDataMgr::GetInstance().SetRefreshType(formId, refreshType);
    FormRecordReport::GetInstance().IncreaseUpdateTimes(formId, HiSysEventPointType::TYPE_INVISIBLE_INTERCEPT);
}

void RefreshCacheMgr::ConsumeInvisibleFlag(const int64_t formId, const int32_t userId)
{
    FormRecord record;
    bool flag = FormDataMgr::GetInstance().GetFormRecord(formId, record);
    if (!flag) {
        HILOG_ERROR("not exist such, formId:%{public}" PRId64 ", visible refresh", formId);
        return;
    }

    HILOG_INFO("formId:%{public}" PRId64", userId:%{public}d, isTimerRefresh:%{public}d, isHostRefresh:%{public}d",
        formId, userId, record.isTimerRefresh, record.isHostRefresh);
    Want want;
    if (record.isTimerRefresh) {
        want.SetParam(Constants::KEY_IS_TIMER, true);
        want.SetParam(Constants::KEY_TIMER_REFRESH, true);
        want.SetParam(Constants::PARAM_FORM_REFRESH_TYPE, Constants::REFRESHTYPE_VISIABLE);
    }
    // multi user
    if (FormUtil::IsActiveUser(userId)) {
        HILOG_INFO("userId is current user, formId:%{public}" PRId64, formId);
        want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
    }
    if (record.isHostRefresh && record.wantCacheMap.find(formId) != record.wantCacheMap.end()) {
        FormDataMgr::GetInstance().MergeFormWant(record.wantCacheMap[formId], want);
    }
    RefreshData data;
    data.formId = formId;
    data.record = record;
    data.want = want;
    FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_UNCONTROL);
}

void RefreshCacheMgr::AddFlagByScreenOff(const int64_t formId, const Want &want, FormRecord &record)
{
    HILOG_WARN("add screen off formId:%{public}" PRId64, formId);
    FormDataMgr::GetInstance().UpdateFormWant(formId, want, record);
    FormDataMgr::GetInstance().UpdateFormRecord(formId, record);
    FormDataMgr::GetInstance().SetHostRefresh(formId, true);
    FormDataMgr::GetInstance().SetNeedRefresh(formId, true);
}

void RefreshCacheMgr::ConsumeScreenOffFlag()
{
    const int32_t currUserId = FormUtil::GetCurrentAccountId();
    HILOG_INFO("screen on and refresh forms, currUserId:%{public}d", currUserId);
    std::vector<FormRecord> formRecords;
    FormDataMgr::GetInstance().GetFormRecordsByUserId(currUserId, formRecords);
    for (const FormRecord& formRecord : formRecords) {
        if (!formRecord.needRefresh) {
            continue;
        }
        if (formRecord.formVisibleNotifyState == Constants::FORM_INVISIBLE) {
            continue;
        }
        ConsumeInvisibleFlag(formRecord.formId, currUserId);
    }
}

void RefreshCacheMgr::AddRenderTask(int64_t formId, std::function<void()> task)
{
    std::lock_guard<std::mutex> lock(renderTaskMapMutex_);
    auto search = renderTaskMap_.find(formId);
    if (search == renderTaskMap_.end()) {
        renderTaskMap_.emplace(formId, task);
    } else {
        search->second = task;
    }
    HILOG_WARN("add render task, formId:%{public}" PRId64, formId);
}

void RefreshCacheMgr::ConsumeRenderTask(int64_t formId)
{
    std::function<void()> task;
    bool findTask = false;
    {
        std::lock_guard<std::mutex> lock(renderTaskMapMutex_);
        auto search = renderTaskMap_.find(formId);
        if (search != renderTaskMap_.end()) {
            task = search->second;
            findTask = true;
            renderTaskMap_.erase(search);
        }
    }
    if (findTask) {
        HILOG_INFO("cosume render task, formId:%{public}" PRId64, formId);
        task();
    }
}

void RefreshCacheMgr::DelRenderTask(int64_t formId)
{
    std::lock_guard<std::mutex> lock(renderTaskMapMutex_);
    auto search = renderTaskMap_.find(formId);
    if (search != renderTaskMap_.end()) {
        renderTaskMap_.erase(search);
        HILOG_INFO("delete render task, formId:%{public}" PRId64, formId);
    }
}

void RefreshCacheMgr::CosumeRefreshByDueControl(const std::vector<FormRecord> &disableFormRecords)
{
    HILOG_INFO("call, formRecord size:%{public}zu", disableFormRecords.size());
    for (const auto &formRecord : disableFormRecords) {
        RefreshData data;
        data.formId = formRecord.formId;
        data.record = formRecord;
        Want reqWant;
        reqWant.SetParam(Constants::PARAM_FORM_USER_ID, FormUtil::GetCurrentAccountId());
        data.want = reqWant;
        FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_UNCONTROL);
    }
}

Want RefreshCacheMgr::CreateWant(const std::vector<FormRecord>::iterator &record, const int32_t userId)
{
    Want want;
    want.SetElementName(record->bundleName, record->abilityName);
    want.SetParam(Constants::PARAM_FORM_USER_ID, userId);
    want.SetParam(Constants::PARAM_MODULE_NAME_KEY, record->moduleName);
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, record->formName);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, record->specification);
    want.SetParam(Constants::PARAM_FORM_RENDERINGMODE_KEY, static_cast<int32_t>(record->renderingMode));
    want.SetParam(Constants::PARAM_DYNAMIC_NAME_KEY, record->isDynamic);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, record->formTempFlag);
    auto it = record->wantCacheMap.find(record->formId);
    if (it == record->wantCacheMap.end()) {
        return want;
    }
    WantParams cacheWantParams = it->second.GetParams();
    WantParams wantParams = want.GetParams();
    if (cacheWantParams.HasParam(Constants::PARAM_HOST_BG_INVERSE_COLOR_KEY)) {
        auto paramValue = cacheWantParams.GetParam(Constants::PARAM_HOST_BG_INVERSE_COLOR_KEY);
        if (paramValue != nullptr) {
            wantParams.SetParam(Constants::PARAM_HOST_BG_INVERSE_COLOR_KEY, paramValue);
        }
    }
    if (cacheWantParams.HasParam(Constants::PARAM_VISUAL_EFFECT_TYPE_KEY)) {
        auto paramValue = cacheWantParams.GetParam(Constants::PARAM_VISUAL_EFFECT_TYPE_KEY);
        if (paramValue != nullptr) {
            wantParams.SetParam(Constants::PARAM_VISUAL_EFFECT_TYPE_KEY, paramValue);
        }
    }
    want.SetParams(wantParams);
    return want;
}

void RefreshCacheMgr::ConsumeAddUnfinishFlag(const int64_t formId)
{
    FormRecord record;
    bool isNeedUpdate = FormDataMgr::GetInstance().GetIsNeedUpdateOnAddFinish(formId, record);
    if (!isNeedUpdate) {
        return;
    }

    HILOG_INFO("formId:%{public}" PRId64", isHostRefresh:%{public}d", formId, record.isHostRefresh);
    Want want;
    want.SetParam(Constants::PARAM_FORM_USER_ID, FormUtil::GetCurrentAccountId());
    if (record.isHostRefresh && record.wantCacheMap.find(formId) != record.wantCacheMap.end()) {
        FormDataMgr::GetInstance().MergeFormWant(record.wantCacheMap[formId], want);
    }
    RefreshData data;
    data.formId = formId;
    data.record = record;
    data.want = want;
    FormRefreshMgr::GetInstance().RequestRefresh(data, TYPE_UNCONTROL);
}
} // namespace AppExecFwk
} // namespace OHOS