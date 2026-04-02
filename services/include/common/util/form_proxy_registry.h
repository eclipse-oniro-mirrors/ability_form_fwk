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

#ifndef OHOS_FORM_FWK_FORM_PROXY_REGISTRY_H
#define OHOS_FORM_FWK_FORM_PROXY_REGISTRY_H

#include <shared_mutex>
#include <string>

#include "form_mgr_errors.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @brief Death recipient that auto-cleans stale proxy entries when the remote process dies.
 */
class FormProxyDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    using CleanupCallback = std::function<void(int32_t)>;

    FormProxyDeathRecipient(int32_t uid, CleanupCallback callback);
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override;

private:
    int32_t uid_;
    CleanupCallback callback_;
};

/**
 * @brief Proxy registry that manages sptr<IRemoteObject> entries keyed by int32_t.
 *
 * The key can be a UID or a userId depending on usage context.
 * Encapsulates register, unregister, lookup and death-recipient logic to eliminate
 * duplicated code across multiple callback registration interfaces.
 * Uses std::shared_mutex for read-write lock optimization.
 */
class FormProxyRegistry {
public:
    /**
     * @brief Constructor.
     * @param tag Log tag to distinguish different registries.
     */
    explicit FormProxyRegistry(const std::string &tag);

    ~FormProxyRegistry() { Clear(); }

    /**
     * @brief Register a proxy by caller UID.
     * @param callingUid Caller UID.
     * @param proxy Proxy object.
     * @return ERR_OK on success, ERR_APPEXECFWK_FORM_COMMON_CODE if proxy is null.
     */
    ErrCode Register(int32_t callingUid, const sptr<IRemoteObject> &proxy);

    /**
     * @brief Unregister a proxy by caller UID.
     * @param callingUid Caller UID.
     * @return ERR_OK on success, ERR_APPEXECFWK_FORM_COMMON_CODE if not found.
     */
    ErrCode Unregister(int32_t callingUid);

    /**
     * @brief Look up a proxy by key (uid or userId depending on usage).
     * @param key Registry key.
     * @param[out] proxy Found proxy object.
     * @return ERR_OK on success, ERR_APPEXECFWK_FORM_GET_HOST_FAILED if not found.
     */
    ErrCode Get(int32_t key, sptr<IRemoteObject> &proxy);

    /**
     * @brief Get all registered proxies.
     * @param[out] proxies All registered proxy objects.
     * @return ERR_OK on success, ERR_APPEXECFWK_FORM_GET_HOST_FAILED if none registered.
     */
    ErrCode GetAll(std::vector<sptr<IRemoteObject>> &proxies);

    /**
     * @brief Get all proxies matching a given userId by iterating all UIDs.
     * UIDs are system callingUids (e.g. 20000001). userId = callingUid / CALLING_UID_TRANSFORM_DIVISOR.
     * @param userId Target userId.
     * @param[out] proxies Matching proxy objects.
     * @return ERR_OK on success, ERR_APPEXECFWK_FORM_GET_HOST_FAILED if none found.
     */
    ErrCode GetByUserId(int32_t userId, std::vector<sptr<IRemoteObject>> &proxies);

    /**
     * @brief Clear all registered proxies.
     */
    void Clear();

    /**
     * @brief Get the current number of registered proxies.
     */
    size_t Size() const;

private:
    bool AddDeathRecipient(int32_t uid, const sptr<IRemoteObject> &proxy);
    void RemoveDeathRecipient(int32_t uid, const sptr<IRemoteObject> &proxy);

    std::string tag_;
    std::unordered_map<int32_t, sptr<IRemoteObject>> proxies_;
    std::unordered_map<int32_t, sptr<IRemoteObject::DeathRecipient>> deathRecipients_;
    mutable std::shared_mutex mutex_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_PROXY_REGISTRY_H
