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

#ifndef OHOS_FORM_FWK_ACCOUNT_COMMON_EVENT_MANAGER_H
#define OHOS_FORM_FWK_ACCOUNT_COMMON_EVENT_MANAGER_H

#include <atomic>
#include <memory>
#include <singleton.h>

#include "form_observer/account_common_event_observer.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Account common event manager for FormMgrService.
 * Manages account LOGIN/LOGOUT CommonEvent subscription lifecycle.
 */
class AccountCommonEventManager final : public DelayedRefSingleton<AccountCommonEventManager> {
    DECLARE_DELAYED_REF_SINGLETON(AccountCommonEventManager);

public:
    DISALLOW_COPY_AND_MOVE(AccountCommonEventManager);

    /**
     * @brief Register account common event subscription.
     *        Called when first account-condition form is allotted.
     */
    void RegisterAccountCallback();

    /**
     * @brief Unregister account common event subscription.
     * Called when last account-condition form is deleted.
     */
    void UnregisterAccountCallback();

private:
    void RegisterAccountCallbackInternal();
    void UnregisterAccountCallbackInternal();
    void PostRetryRegister();

    std::atomic<bool> isShutdown_{false};
    std::atomic<bool> isRegistered_{false};
    std::atomic<int32_t> retryCount_{0};
    std::shared_ptr<AccountCommonEventObserver> observer_ = nullptr;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_ACCOUNT_COMMON_EVENT_MANAGER_H
