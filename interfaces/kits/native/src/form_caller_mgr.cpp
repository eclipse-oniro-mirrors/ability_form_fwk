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
FormCallerMgr::FormCallerMgr() {}

FormCallerMgr::~FormCallerMgr() {}

void FormCallerMgr::AddFormHostCaller(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formHostCallerMutex_);
    std::shared_ptr<FormHostCaller> caller = std::make_shared<FormHostCaller>(formJsInfo, callerToken);
    formHostCallers_[formJsInfo.formId] = caller;
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

void FormCallerMgr::DeleteFormHostCaller(int64_t formId)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formHostCallerMutex_);
    formHostCallers_.erase(formId);
}

void FormCallerMgr::AddFormProviderCaller(const FormJsInfo &formJsInfo, const sptr<IRemoteObject> &callerToken)
{
    HILOG_DEBUG("%{public}s called", __func__);
    std::lock_guard<std::recursive_mutex> lock(formProviderCallerMutex_);
    for (const auto &formProviderCaller : formProviderCallers_) {
        if (callerToken == formProviderCaller->GetCallerToken()) {
            formProviderCaller->AddForm(formJsInfo);
            return;
        }
    }

    std::shared_ptr<FormProviderCaller> caller = std::make_shared<FormProviderCaller>(callerToken);
    caller->AddForm(formJsInfo);
    formProviderCallers_.emplace_back(caller);
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
    std::shared_ptr<FormProviderCaller> providerCaller = nullptr;
    std::lock_guard<std::recursive_mutex> lock(formProviderCallerMutex_);
    for (auto iter = formProviderCallers_.begin(); iter != formProviderCallers_.end(); ++iter) {
        if (callerToken != (*iter)->GetCallerToken()) {
            continue;
        }
        (*iter)->DeleteForm(formId);
        if ((*iter)->IsFormEmpty()) {
            iter = formProviderCallers_.erase(iter);
        }
        break;
    }
}
} // namespace AppExecFwk
} // namespace OHOS
