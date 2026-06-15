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

#ifndef OHOS_FORM_FWK_PROVIDER_ACQUIRE_ERROR_HANDLER_H
#define OHOS_FORM_FWK_PROVIDER_ACQUIRE_ERROR_HANDLER_H

#include "form_provider/error_handler/provider_connection_error_handler.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormProviderAcquireErrorHandler
 * Acquire (form creation) error handler for dual-signal confirmed delayed retry.
 *
 * Handles SendRequest failure after successful connect (reuses the base common algorithm,
 * customizes via hooks):
 *  - GetRetryTaskType: ACQUIRE_RETRY_TASK (distinct from refresh).
 *  - OnPrepareRetryConnect: set CONNECTING before AMS connect (acquire-only, completes state machine).
 *  - OnRetryLimitReached: erase + SendFormFailedEvent (aligns with ReAcquire exhaustion).
 *
 * Connect failure (state != CONNECTED) is NOT handled here — it stays in
 * FormAcquireConnection::OnAbilityDisconnectDone -> ReAcquireProviderFormInfoAsync.
 */
class FormProviderAcquireErrorHandler : public FormProviderConnectionErrorHandler {
public:
    FormProviderAcquireErrorHandler() = default;
    DISALLOW_COPY_AND_MOVE(FormProviderAcquireErrorHandler);

protected:
    TaskType GetRetryTaskType() const override;
    void OnRetryLimitReached(int64_t formId) override;
    void OnPrepareRetryConnect(sptr<FormAbilityConnection> &connection) override;
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_PROVIDER_ACQUIRE_ERROR_HANDLER_H
