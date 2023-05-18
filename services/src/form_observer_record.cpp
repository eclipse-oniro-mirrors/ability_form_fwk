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

#include "form_task_mgr.h"
#include "hilog_wrapper.h"
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
    std::lock_guard<std::recursive_mutex> lock(deathRecipientsMutex_);
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
    std::lock_guard<std::recursive_mutex> lock(formAddObserverMutex_);
    auto iter = formAddObservers_.find(bundleName);
    if (iter == formAddObservers_.end()) {
        std::vector<sptr<IRemoteObject>> observers;
        observers.emplace_back(callerToken);
        formAddObservers_.emplace(bundleName, observers);
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

ErrCode FormObserverRecord::SetFormRemoveObserver(const std::string bundleName, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("start");
    std::lock_guard<std::recursive_mutex> lock(formRemoveObserverMutex_);
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
    std::lock_guard<std::recursive_mutex> lock(formAddObserverMutex_);
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

    std::lock_guard<std::recursive_mutex> lock(formRemoveObserverMutex_);
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
    std::lock_guard<std::recursive_mutex> lock(formAddObserverMutex_);
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
    std::lock_guard<std::recursive_mutex> observerLock(formRemoveObserverMutex_);
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

    std::lock_guard<std::recursive_mutex> deathLock(deathRecipientsMutex_);
    auto iter = deathRecipients_.find(object);
    if (iter != deathRecipients_.end()) {
        auto deathRecipient = iter->second;
        deathRecipients_.erase(iter);
        object->RemoveDeathRecipient(deathRecipient);
    }
}

void FormObserverRecord::ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("remote died");
    FormObserverRecord::GetInstance().CleanResource(remote);
}
}  // namespace AppExecFwk
}  // namespace OHOS
