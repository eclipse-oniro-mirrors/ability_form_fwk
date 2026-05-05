/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "form_observer/form_observer_record.h"

namespace OHOS {
namespace AppExecFwk {

bool FormObserverRecordInner::IsFollowEvents(FormEventId type) const
{
    return false;
}

void FormObserverRecordInner::PushEvent(FormEventId type) {}
void FormObserverRecordInner::RemoveEvent(FormEventId type) {}

void FormObserverRecord::SetDeathRecipient(const sptr<IRemoteObject> &callerToken,
    const sptr<IRemoteObject::DeathRecipient> &deathRecipient) {}

ErrCode FormObserverRecord::SetFormAddObserver(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    return 0;
}

ErrCode FormObserverRecord::SetFormRemoveObserver(const std::string bundleName,
    const sptr<IRemoteObject> &callerToken)
{
    return 0;
}

void FormObserverRecord::onFormAdd(const std::string bundleName, RunningFormInfo &runningFormInfo) {}

void FormObserverRecord::onFormRemove(const std::string bundleName, const RunningFormInfo runningFormInfo) {}

void FormObserverRecord::CleanResource(const wptr<IRemoteObject> &remote) {}

void FormObserverRecord::HandleFormEvent(
    const std::string &bundleName, const std::string &formEventType, RunningFormInfo &runningFormInfo) {}

ErrCode FormObserverRecord::SetFormEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &callerToken)
{
    return 0;
}

ErrCode FormObserverRecord::RemoveFormEventObserver(
    const std::string &bundleName, const std::string &formEventType, const sptr<IRemoteObject> &callerToken)
{
    return 0;
}

FormEventId FormObserverRecord::ConvertToFormEventId(const std::string &formEventType)
{
    return FormEventId::FORM_EVENT_NON;
}

void FormObserverRecord::NotifyFormEvent(
    const FormObserverRecordInner &recordInner, FormEventId formEventId, RunningFormInfo &runningFormInfo,
    const std::string &formEventType) {}

ErrCode FormObserverRecord::SetFormEventObserverLocked(
    const std::string &bundleName, FormEventId formEventType, const sptr<IRemoteObject> &callerToken)
{
    return 0;
}

ErrCode FormObserverRecord::RemoveFormEventObserverLocked(
    const std::string &bundleName, FormEventId formEventType, const sptr<IRemoteObject> &callerToken)
{
    return 0;
}

void FormObserverRecord::ClearDeathRemoteObserver(const wptr<IRemoteObject> &remote) {}

void FormObserverRecord::ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote) {}

} // namespace AppExecFwk
} // namespace OHOS
