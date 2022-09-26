/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "form_caller_mgr.h"

#include "form_js_info.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr int32_t FORM_TASK_DELAY_TIME = 20; // ms
    const std::string NAME_FORM_CALLER_MGR = "FormCallerMgr";
}
FormCallerMgr::FormCallerMgr() {}

FormCallerMgr::~FormCallerMgr() {}

void FormCallerMgr::AddFormHostCaller(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formHostCallerMutex_);
    std::shared_ptr<FormHostCaller> caller = std::make_shared<FormHostCaller>(formJsInfo, callerToken);
    formHostCallers_[formJsInfo.formId] = caller;

    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new (std::nothrow) FormHostCallerRecipient([](const wptr<IRemoteObject> &remote) {
            FormCallerMgr::GetInstance().OnHostCallBackDied(remote);
        });
    if (deathRecipient == nullptr) {
        HILOG_ERROR("%{public}s fail, create FormHostCallerRecipient error", __func__);
    } else {
        caller->AddDeathRecipient(deathRecipient);
    }
}

std::shared_ptr<FormHostCaller> FormCallerMgr::GetFormHostCaller(int64_t formId)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formHostCallerMutex_);
    auto iter = formHostCallers_.find(formId);
    if (iter == formHostCallers_.end()) {
        return nullptr;
    }
    return iter->second;
}

void FormCallerMgr::RemoveFormHostCaller(int64_t formId)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formHostCallerMutex_);
    formHostCallers_.erase(formId);
}


void FormCallerMgr::RemoveFormHostCaller(const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formHostCallerMutex_);
    for (auto iter = formHostCallers_.begin(); iter != formHostCallers_.end();) {
        if (iter->second != nullptr && iter->second->IsSameToken(callerToken)) {
            iter = formHostCallers_.erase(iter);
        } else {
            ++iter;
        }
    }
}

void FormCallerMgr::OnHostCallBackDied(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("%{public}s called", __func__);
    auto object = remote.promote();
    if (object == nullptr) {
        HILOG_ERROR("remote object is nullptr");
        return;
    }
    auto hostCallBackDiedFunc = [object]() {
        FormCallerMgr::GetInstance().HandleHostCallBackDiedTask(object);
    };

    auto handler = GetEventHandler();
    handler->PostTask(hostCallBackDiedFunc, FORM_TASK_DELAY_TIME);
}

void FormCallerMgr::HandleHostCallBackDiedTask(const sptr<IRemoteObject> &remote)
{
    RemoveFormHostCaller(remote);
}

void FormCallerMgr::AddFormProviderCaller(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formProviderCallerMutex_);
    for (const auto &formProviderCaller : formProviderCallers_) {
        if (formProviderCaller->IsSameToken(callerToken)) {
            formProviderCaller->AddForm(formJsInfo);
            return;
        }
    }

    std::shared_ptr<FormProviderCaller> caller = std::make_shared<FormProviderCaller>(callerToken);
    caller->AddForm(formJsInfo);
    formProviderCallers_.emplace_back(caller);

    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        new (std::nothrow) FormProviderCallerRecipient([](const wptr<IRemoteObject> &remote) {
            FormCallerMgr::GetInstance().OnProviderCallBackDied(remote);
        });
    if (deathRecipient == nullptr) {
        HILOG_ERROR("%{public}s fail, create FormProviderCallerRecipient error", __func__);
    } else {
        caller->AddDeathRecipient(deathRecipient);
    }
}

void FormCallerMgr::GetFormProviderCaller(int64_t formId,
    std::vector<std::shared_ptr<FormProviderCaller>> &formProviderCallers)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formProviderCallerMutex_);
    for (const auto &formProviderCaller : formProviderCallers_) {
        if (formProviderCaller->HasForm(formId)) {
            formProviderCallers.emplace_back(formProviderCaller);
        }
    }
}

void FormCallerMgr::RemoveFormProviderCaller(int64_t formId, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formProviderCallerMutex_);
    for (auto iter = formProviderCallers_.begin(); iter != formProviderCallers_.end(); ++iter) {
        if ((*iter)->IsSameToken(callerToken)) {
            continue;
        }
        (*iter)->DeleteForm(formId);
        if ((*iter)->IsFormEmpty()) {
            iter = formProviderCallers_.erase(iter);
        }
        break;
    }
}

void FormCallerMgr::RemoveFormProviderCaller(const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formProviderCallerMutex_);
    for (auto iter = formProviderCallers_.begin(); iter != formProviderCallers_.end();) {
        if ((*iter)->IsSameToken(callerToken)) {
            ++iter;
        } else {
            iter = formProviderCallers_.erase(iter);
        }
    }
}

void FormCallerMgr::OnProviderCallBackDied(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("%{public}s called", __func__);
    auto object = remote.promote();
    if (object == nullptr) {
        HILOG_ERROR("remote object is nullptr");
        return;
    }
    auto providerCallBackDiedFunc = [object]() {
        FormCallerMgr::GetInstance().HandleProviderCallBackDiedTask(object);
    };

    auto handler = GetEventHandler();
    handler->PostTask(providerCallBackDiedFunc, FORM_TASK_DELAY_TIME);
}

void FormCallerMgr::HandleProviderCallBackDiedTask(const sptr<IRemoteObject> &remote)
{
    RemoveFormProviderCaller(remote);
}

std::shared_ptr<EventHandler> FormCallerMgr::GetEventHandler()
{
    HILOG_DEBUG("%{public}s called", __func__);
    if (eventHandler_ == nullptr) {
        auto runner = EventRunner::Create(NAME_FORM_CALLER_MGR);
        if (runner == nullptr) {
            HILOG_ERROR("%{public}s fail, create runner error", __func__);
            return nullptr;
        }

        eventHandler_ = std::make_shared<EventHandler>(runner);
        if (eventHandler_ == nullptr) {
            HILOG_ERROR("%{public}s fail, create event handler error", __func__);
            return nullptr;
        }
    }

    return eventHandler_;
}
} // namespace AppExecFwk
} // namespace OHOS
