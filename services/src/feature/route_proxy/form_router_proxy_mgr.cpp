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

#include "feature/route_proxy/form_router_proxy_mgr.h"

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "status_mgr_center/form_task_mgr.h"
#include "running_form_info.h"

namespace OHOS {
namespace AppExecFwk {

void FormRouterProxyMgr::SetDeathRecipient(const sptr<IRemoteObject> &callerToken,
    const sptr<IRemoteObject::DeathRecipient> &deathRecipient)
{
#ifndef WATCH_API_DISABLE
    HILOG_DEBUG("Start");
    std::lock_guard<std::mutex> lock(deathRecipientsMutex_);
    auto iter = deathRecipients_.find(callerToken);
    if (iter == deathRecipients_.end()) {
        deathRecipients_.emplace(callerToken, deathRecipient);
        callerToken->AddDeathRecipient(deathRecipient);
    } else {
        HILOG_DEBUG("The deathRecipient has been added");
    }
#endif
}

ErrCode FormRouterProxyMgr::SetFormRouterProxy(const std::vector<int64_t> &formIds,
    const sptr<IRemoteObject> &callerToken)
{
#ifndef WATCH_API_DISABLE
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formRouterProxyMutex_);
    for (const auto &formId : formIds) {
        auto iter = formRouterProxyMap_.find(formId);
        if (iter != formRouterProxyMap_.end()) {
            iter->second = callerToken;
            continue;
        }
        formRouterProxyMap_.emplace(formId, callerToken);
    }
    auto dealthRecipient = new (std::nothrow) FormRouterProxyMgr::ClientDeathRecipient();
    if (dealthRecipient == nullptr) {
        HILOG_ERROR("create ClientDealthRecipient failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    SetDeathRecipient(callerToken, dealthRecipient);
    return ERR_OK;
#else
    return ERR_OK;
#endif
}

ErrCode FormRouterProxyMgr::RemoveFormRouterProxy(const std::vector<int64_t> &formIds)
{
    HILOG_DEBUG("call");
    for (int64_t formId : formIds) {
        std::lock_guard<std::mutex> lock(formRouterProxyMutex_);
        auto formRouterProxys = formRouterProxyMap_.find(formId);
        if (formRouterProxys == formRouterProxyMap_.end()) {
            HILOG_INFO("no formRouterProxy has been register");
        } else {
            formRouterProxyMap_.erase(formId);
        }
    }
    return ERR_OK;
}

bool FormRouterProxyMgr::HasRouterProxy(int64_t formId)
{
    HILOG_DEBUG("call");
    std::lock_guard<std::mutex> lock(formRouterProxyMutex_);
    return formRouterProxyMap_.find(formId) != formRouterProxyMap_.end();
}

void FormRouterProxyMgr::OnFormRouterEvent(int64_t formId, const Want &want)
{
    HILOG_DEBUG("call");
    if (!HasRouterProxy(formId)) {
        HILOG_WARN("This form no formRouterProxy has been register");
        return;
    }
    std::lock_guard<std::mutex> lock(formRouterProxyMutex_);
    auto routerProxy = formRouterProxyMap_[formId];
    if (routerProxy == nullptr) {
        return;
    }
    FormTaskMgr::GetInstance().PostRouterProxyToHost(formId, routerProxy, want);
}

void FormRouterProxyMgr::CleanResource(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("Start");

    // Clean the formRouterProxyMap_.
    auto object = remote.promote();
    if (object == nullptr) {
        HILOG_ERROR("null remoteObject");
        return;
    }
    std::lock_guard<std::mutex> lock(formRouterProxyMutex_);
    for (auto it = formRouterProxyMap_.begin(); it != formRouterProxyMap_.end();) {
        if (it->second == object) {
            formRouterProxyMap_.erase(it++);
        } else {
            it++;
        }
    }

    std::lock_guard<std::mutex> deathLock(deathRecipientsMutex_);
    auto iter = deathRecipients_.find(object);
    if (iter != deathRecipients_.end()) {
        auto deathRecipient = iter->second;
        deathRecipients_.erase(iter);
        object->RemoveDeathRecipient(deathRecipient);
    }
    HILOG_DEBUG("End");
}

void FormRouterProxyMgr::ClientDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_DEBUG("Remote died");
    FormRouterProxyMgr::GetInstance().CleanResource(remote);
}

}  // namespace AppExecFwk
}  // namespace OHOS
