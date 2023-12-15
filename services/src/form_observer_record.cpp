/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "form_observer_record.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_task_mgr.h"
#include "running_form_info.h"

namespace OHOS {
namespace AppExecFwk {
void FormObserverRecord::SetDeathRecipient(const sptr<IRemoteObject> &callerToken,
    const sptr<IRemoteObject::DeathRecipient> &deathRecipient)
{
    HILOG_DEBUG("start");
    if (callerToken == nullptr || deathRecipient == nullptr) {
        HILOG_ERROR("The callerToken or the deathRecipient is empty");
        return;
    }
    std::lock_guard<std::mutex> lock(deathRecipientsMutex_);
    auto iter = deathRecipients_.find(callerToken);
    if (iter == deathRecipients_.end()) {
        deathRecipients_.emplace(callerToken, deathRecipient);
        callerToken->AddDeathRecipient(deathRecipient);
    } else {
        HILOG_DEBUG("The deathRecipient has been added.");
    }
}

ErrCode FormObserverRecord::SetFormAddObserver(const std::string bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::mutex> lock(formAddObserverMutex_);
    auto iter = formAddObservers_.find(bundleName);
    if (iter == formAddObservers_.end()) {
        std::vector<sptr<IRemoteObject>> observers;
        observers.emplace_back(callerToken);
        formAddObservers_.emplace(bundleName, observers);
    } else {
        if (std::find(iter->second.begin(), iter->second.end(), callerToken) != iter->second.end()) {
            HILOG_DEBUG("observer added.");
            return ERR_OK;
        } else {
            iter->second.emplace_back(callerToken);
        }
    }
    SetDeathRecipient(callerToken, new (std::nothrow) FormObserverRecord::ClientDeathRecipient());
    return ERR_OK;
}

ErrCode FormObserverRecord::SetFormRemoveObserver(const std::string bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::mutex> lock(formRemoveObserverMutex_);
    auto iter = formRemoveObservers_.find(bundleName);
    if (iter == formRemoveObservers_.end()) {
        std::vector<sptr<IRemoteObject>> observers;
        observers.emplace_back(callerToken);
        formRemoveObservers_.emplace(bundleName, observers);
    } else {
        if (std::find(iter->second.begin(), iter->second.end(), callerToken) != iter->second.end()) {
            HILOG_DEBUG("The observer has been added.");
            return ERR_OK;
        } else {
            iter->second.emplace_back(callerToken);
        }
    }
    SetDeathRecipient(callerToken, new (std::nothrow) FormObserverRecord::ClientDeathRecipient());
    return ERR_OK;
}

void FormObserverRecord::onFormAdd(const std::string bundleName, RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("start");
    if (formAddObservers_.empty()) {
        HILOG_DEBUG("No observer has been added.");
        return;
    }
    std::lock_guard<std::mutex> lock(formAddObserverMutex_);
    auto iter = formAddObservers_.find(bundleName);
    if (iter != formAddObservers_.end()) {
        for (auto callerToken : iter->second) {
            FormTaskMgr::GetInstance().PostAddTaskToHost(bundleName, callerToken, runningFormInfo);
        }
    }
}

void FormObserverRecord::onFormRemove(const std::string bundleName, const RunningFormInfo runningFormInfo)
{
    HILOG_DEBUG("start");
    if (formRemoveObservers_.empty()) {
        HILOG_DEBUG("No observer has been added.");
        return;
    }

    std::lock_guard<std::mutex> lock(formRemoveObserverMutex_);
    auto iter = formRemoveObservers_.find(bundleName);
    if (iter != formRemoveObservers_.end()) {
        for (auto callerToken : iter->second) {
            FormTaskMgr::GetInstance().PostRemoveTaskToHost(bundleName, callerToken, runningFormInfo);
        }
    }
}

void FormObserverRecord::CleanResource(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("start");

    // Clean the formAddObservers_.
    auto object = remote.promote();
    if (object == nullptr) {
        HILOG_ERROR("remote object is nullptr");
        return;
    }
    std::lock_guard<std::mutex> lock(formAddObserverMutex_);
    for (auto it = formAddObservers_.begin(); it != formAddObservers_.end();) {
        auto& observer = it->second;
        auto iter = std::find(observer.begin(), observer.end(), object);
        if (iter != observer.end()) {
            observer.erase(iter);
        }
        if (observer.empty()) {
            it = formAddObservers_.erase(it);
        } else {
            ++it;
        }
    }

    // Clean the formRemoveObservers_.
    std::lock_guard<std::mutex> observerLock(formRemoveObserverMutex_);
    for (auto it = formRemoveObservers_.begin(); it != formRemoveObservers_.end();) {
        auto& observer = it->second;
        auto iter = std::find(observer.begin(), observer.end(), object);
        if (iter != observer.end()) {
            observer.erase(iter);
        }
        if (observer.empty()) {
            it = formRemoveObservers_.erase(it);
        } else {
            ++it;
        }
    }

    // Clean the formEventObservers_.
    ClearDeathRemoteObserver(remote);

    std::lock_guard<std::mutex> deathLock(deathRecipientsMutex_);
    auto iter = deathRecipients_.find(object);
    if (iter != deathRecipients_.end()) {
        auto deathRecipient = iter->second;
        deathRecipients_.erase(iter);
        object->RemoveDeathRecipient(deathRecipient);
    }
    HILOG_DEBUG("end");
}

void FormObserverRecord::ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("remote died");
    FormObserverRecord::GetInstance().CleanResource(remote);
}
void FormObserverRecord::HandleFormEvent(
    const std::string &bundleName, const std::string &formEventType, RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("Called.");
    if (formEventType.empty()) {
        HILOG_ERROR("Input string is empty.");
        return;
    }

    auto eventId = ConvertToFormEventId(formEventType);
    if (eventId == FormEventId::FORM_EVENT_NON) {
        HILOG_ERROR("Input event type error.");
        return;
    }

    std::unique_lock<std::mutex> lock(formEventObserversMutex_);
    auto observerVec = formEventObservers_.find(bundleName);
    if (observerVec == formEventObservers_.end()) {
        HILOG_ERROR("The current package does not have an observer");
        return;
    }

    for (const auto &iter : observerVec->second) {
        if (iter.IsFollowEvents(eventId) && iter.GetRemote() != nullptr) {
            NotifyFormEvent(iter, eventId, runningFormInfo, formEventType);
        }
    }
}

FormEventId FormObserverRecord::ConvertToFormEventId(const std::string &formEventType)
{
    HILOG_DEBUG("Called.");

    auto iter = formEventMap.find(formEventType);
    if (iter != formEventMap.end()) {
        return iter->second;
    }

    return FormEventId::FORM_EVENT_NON;
}

void FormObserverRecord::NotifyFormEvent(const FormObserverRecordInner &recordInner,
    FormEventId formEventId, RunningFormInfo &runningFormInfo, const std::string &formEventType)
{
    HILOG_DEBUG("Called.");
    switch (formEventId) {
        case FormEventId::FORM_EVENT_CALL :
        case FormEventId::FORM_EVENT_MESSAGE :
        case FormEventId::FORM_EVENT_ROUTER :
            FormTaskMgr::GetInstance().PostFormClickEventToHost(
                recordInner.BindHostBundle(), formEventType, recordInner.GetRemote(), runningFormInfo);
            break;
        case FormEventId::FORM_EVENT_FORM_ADD :
            break;
        case FormEventId::FORM_EVENT_FORM_REMOVE :
            break;
        default :
            HILOG_ERROR("Type mismatchy.");
            break;
    }
}

ErrCode FormObserverRecord::SetFormEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("Called.");
    if (callerToken == nullptr) {
        HILOG_ERROR("Caller token is null.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    // Bundle name allows empty input, representing listening to all applications.
    if (formEventType.empty()) {
        HILOG_ERROR("Input string is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    auto eventId = ConvertToFormEventId(formEventType);
    if (eventId == FormEventId::FORM_EVENT_NON) {
        HILOG_ERROR("Input event type error.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return SetFormEventObserverLocked(bundleName, eventId, callerToken);
}

ErrCode FormObserverRecord::RemoveFormEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("Called.");
    if (formEventType.empty()) {
        HILOG_ERROR("Input string is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (callerToken == nullptr) {
        HILOG_ERROR("Caller token parameter is empty.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    auto eventId = ConvertToFormEventId(formEventType);
    if (eventId == FormEventId::FORM_EVENT_NON) {
        HILOG_ERROR("Input event type error.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    return RemoveFormEventObserverLocked(bundleName, eventId, callerToken);
}

ErrCode FormObserverRecord::SetFormEventObserverLocked(
    const std::string &bundleName, FormEventId eventId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("Called.");
    FormObserverRecordInner recordInner(callerToken);
    recordInner.PushEvent(eventId);
    recordInner.SetBindHostBundle(bundleName);

    sptr<IRemoteObject::DeathRecipient> deathRecipient = new (std::nothrow) FormObserverRecord::ClientDeathRecipient();
    if (deathRecipient == nullptr) {
        HILOG_ERROR("Create death recipient error.");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    // Place parameter verification on the previous layer.
    std::unique_lock<std::mutex> formLock(formEventObserversMutex_);
    auto observerVec = formEventObservers_.find(bundleName);
    if (observerVec == formEventObservers_.end()) {
        std::vector<FormObserverRecordInner> observerVec {recordInner};
        formEventObservers_.emplace(bundleName, observerVec);
        SetDeathRecipient(recordInner.GetRemote(), deathRecipient);
        return ERR_OK;
    }

    auto recordInnerIter = std::find(observerVec->second.begin(), observerVec->second.end(), recordInner);
    if (recordInnerIter != observerVec->second.end()) {
        recordInnerIter->PushEvent(eventId);
        return ERR_OK;
    }

    // Not find
    observerVec->second.emplace_back(recordInner);
    SetDeathRecipient(recordInner.GetRemote(), deathRecipient);
    return ERR_OK;
}

ErrCode FormObserverRecord::RemoveFormEventObserverLocked(
    const std::string &bundleName, FormEventId formEventType, const sptr<IRemoteObject> &callerToken)
{
    // Place parameter verification on the previous layer.
    HILOG_DEBUG("Called.");
    std::unique_lock<std::mutex> formLock(formEventObserversMutex_);
    auto observerVec = formEventObservers_.find(bundleName);
    if (observerVec == formEventObservers_.end()) {
        HILOG_ERROR("Not found bundle key.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    FormObserverRecordInner recordInner(callerToken);
    recordInner.PushEvent(formEventType);
    recordInner.SetBindHostBundle(bundleName);

    auto recordInnerIter = std::find(observerVec->second.begin(), observerVec->second.end(), recordInner);
    if (recordInnerIter == observerVec->second.end()) {
        HILOG_ERROR("Caller not found.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (recordInnerIter->IsFollowEvents(formEventType)) {
        recordInnerIter->RemoveEvent(formEventType);
    }

    // Check if the event container is empty
    if (recordInnerIter->NonFollowEvents()) {
        observerVec->second.erase(recordInnerIter);
    }

    return ERR_OK;
}

void FormObserverRecord::ClearDeathRemoteObserver(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("Called.");
    auto object = remote.promote();
    if (object == nullptr) {
        HILOG_ERROR("remote object is nullptr");
        return;
    }
    std::lock_guard<std::mutex> formEventLock(formEventObserversMutex_);
    for (auto it = formEventObservers_.begin(); it != formEventObservers_.end();) {
        auto& observer = it->second;
        auto iter = std::find_if(observer.begin(), observer.end(), [remote, object](auto &item) {
            return object == item.GetRemote();
        });
        if (iter != observer.end()) {
            observer.erase(iter);
        }
        if (observer.empty()) {
            it = formEventObservers_.erase(it);
        } else {
            ++it;
        }
    }
}

bool FormObserverRecordInner::IsFollowEvents(FormEventId type) const
{
    return std::find(eventGroup_.begin(), eventGroup_.end(), type) != eventGroup_.end();
}

void FormObserverRecordInner::PushEvent(FormEventId type)
{
    if (!IsFollowEvents(type)) {
        eventGroup_.emplace_back(type);
    }
}

void FormObserverRecordInner::RemoveEvent(FormEventId type)
{
    auto iter = std::find(eventGroup_.begin(), eventGroup_.end(), type);
    if (iter != eventGroup_.end()) {
        eventGroup_.erase(iter);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
