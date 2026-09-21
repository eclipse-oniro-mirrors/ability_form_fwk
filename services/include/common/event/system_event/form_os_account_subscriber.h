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

#ifndef OHOS_FORM_FWK_FORM_OS_ACCOUNT_SUBSCRIBER_H
#define OHOS_FORM_FWK_FORM_OS_ACCOUNT_SUBSCRIBER_H

#include "os_account_subscriber.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Subscribes to os account creation events to trigger reload earlier than
 * the BUNDLE_SCAN_FINISHED broadcast (direct callback vs CES relay).
 * The CREATED event fires after BMS has synchronously installed all haps for
 * the new account (WaitForAllTasksExecute), so data completeness is guaranteed.
 */
class FormOsAccountSubscriber : public AccountSA::OsAccountSubscriber {
public:
    explicit FormOsAccountSubscriber(const AccountSA::OsAccountSubscribeInfo &subscribeInfo)
        : AccountSA::OsAccountSubscriber(subscribeInfo) {}

    void OnStateChanged(const AccountSA::OsAccountStateData &data) override;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_OS_ACCOUNT_SUBSCRIBER_H
