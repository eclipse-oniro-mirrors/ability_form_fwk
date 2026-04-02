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

#include "common/util/form_proxy_registry.h"

#include "fms_log_wrapper.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {

FormProxyDeathRecipient::FormProxyDeathRecipient(int32_t uid, CleanupCallback callback)
    : uid_(uid), callback_(std::move(callback))
{}

void FormProxyDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_WARN("Proxy died for uid=%{public}d, auto cleaning", uid_);
    if (callback_) {
        callback_(uid_);
    }
}

FormProxyRegistry::FormProxyRegistry(const std::string &tag) : tag_(tag) {}

ErrCode FormProxyRegistry::Register(int32_t callingUid, const sptr<IRemoteObject> &proxy)
{
    if (proxy == nullptr) {
        HILOG_ERROR("%{public}s: proxy is null", tag_.c_str());
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = proxies_.find(callingUid);
    if (it != proxies_.end()) {
        RemoveDeathRecipient(callingUid, it->second);
        HILOG_WARN("%{public}s: overwriting existing proxy for uid=%{public}d", tag_.c_str(), callingUid);
    }

    if (!AddDeathRecipient(callingUid, proxy)) {
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    proxies_[callingUid] = proxy;
    HILOG_INFO("%{public}s: registered for uid=%{public}d, total=%{public}zu",
        tag_.c_str(), callingUid, proxies_.size());
    return ERR_OK;
}

ErrCode FormProxyRegistry::Unregister(int32_t callingUid)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = proxies_.find(callingUid);
    if (it == proxies_.end()) {
        HILOG_WARN("%{public}s: no proxy registered for uid=%{public}d", tag_.c_str(), callingUid);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    RemoveDeathRecipient(callingUid, it->second);
    proxies_.erase(it);
    HILOG_INFO("%{public}s: unregistered for uid=%{public}d, remaining=%{public}zu",
        tag_.c_str(), callingUid, proxies_.size());
    return ERR_OK;
}

ErrCode FormProxyRegistry::Get(int32_t key, sptr<IRemoteObject> &proxy)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = proxies_.find(key);
    if (it == proxies_.end()) {
        HILOG_ERROR("%{public}s: no proxy for key=%{public}d", tag_.c_str(), key);
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    proxy = it->second;
    return ERR_OK;
}

ErrCode FormProxyRegistry::GetAll(std::vector<sptr<IRemoteObject>> &proxies)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (auto &pair : proxies_) {
        proxies.push_back(pair.second);
    }
    if (proxies.empty()) {
        HILOG_ERROR("%{public}s: no proxies registered", tag_.c_str());
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    return ERR_OK;
}

ErrCode FormProxyRegistry::GetByUserId(int32_t userId, std::vector<sptr<IRemoteObject>> &proxies)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    for (auto &pair : proxies_) {
        int32_t uidUserId = FormUtil::GetCallerUserId(pair.first);
        if (uidUserId == userId) {
            proxies.push_back(pair.second);
        }
    }
    if (proxies.empty()) {
        HILOG_ERROR("%{public}s: no proxies for userId=%{public}d", tag_.c_str(), userId);
        return ERR_APPEXECFWK_FORM_GET_HOST_FAILED;
    }
    return ERR_OK;
}

void FormProxyRegistry::Clear()
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    for (auto &pair : proxies_) {
        RemoveDeathRecipient(pair.first, pair.second);
    }
    proxies_.clear();
    HILOG_INFO("%{public}s: cleared all proxies", tag_.c_str());
}

size_t FormProxyRegistry::Size() const
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return proxies_.size();
}

bool FormProxyRegistry::AddDeathRecipient(int32_t uid, const sptr<IRemoteObject> &proxy)
{
    auto callback = [this](int32_t diedUid) {
        std::unique_lock<std::shared_mutex> lock(mutex_);
        deathRecipients_.erase(diedUid);
        proxies_.erase(diedUid);
        HILOG_INFO("%{public}s: auto cleaned died proxy for uid=%{public}d", tag_.c_str(), diedUid);
    };

    auto recipient = sptr<FormProxyDeathRecipient>::MakeSptr(uid, std::move(callback));
    if (recipient == nullptr) {
        HILOG_ERROR("%{public}s: failed to create DeathRecipient for uid=%{public}d", tag_.c_str(), uid);
        return false;
    }
    proxy->AddDeathRecipient(recipient);
    deathRecipients_[uid] = recipient;
    return true;
}

void FormProxyRegistry::RemoveDeathRecipient(int32_t uid, const sptr<IRemoteObject> &proxy)
{
    auto it = deathRecipients_.find(uid);
    if (it != deathRecipients_.end()) {
        proxy->RemoveDeathRecipient(it->second);
        deathRecipients_.erase(it);
    }
}

} // namespace AppExecFwk
} // namespace OHOS
