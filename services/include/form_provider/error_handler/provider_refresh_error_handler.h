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

#ifndef OHOS_FORM_FWK_PROVIDER_REFRESH_ERROR_HANDLER_H
#define OHOS_FORM_FWK_PROVIDER_REFRESH_ERROR_HANDLER_H

#include "form_provider/error_handler/provider_connection_error_handler.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormProviderRefreshErrorHandler
 * Refresh-specific error handler for dual-signal confirmed delayed retry.
 * Implements HandleSendRequestFailed and HandleDisconnectError for refresh scenario.
 */
class FormProviderRefreshErrorHandler : public FormProviderConnectionErrorHandler {
public:
    FormProviderRefreshErrorHandler() = default;
    DISALLOW_COPY_AND_MOVE(FormProviderRefreshErrorHandler);

    /**
     * @brief Handle send request failed error for refresh scenario (first signal in dual-signal mechanism).
     *        Marks sendRequestFailed signal and triggers retry if dual-signal confirmed.
     * @param formId Form ID.
     * @param errorCode IPC error code (must be remote-dead error: 32 or 29189).
     * @param want Want parameter for retry.
     * @return true if waiting for disconnect callback (first signal only),
     *         false if non-dead-error/dual-signal-confirmed/retry-limit-reached.
     */
    bool HandleSendRequestFailed(int64_t formId, int errorCode, const Want &want) override;

    /**
     * @brief Handle disconnect error for refresh scenario.
     *        Checks dual-signal condition and triggers retry if confirmed.
     * @param formId Form ID.
     * @param connection Form ability connection object (for Clone).
     * @return true if dual-signal confirmed and retry scheduled, false otherwise.
     */
    bool HandleDisconnectError(int64_t formId, const sptr<FormAbilityConnection> &connection) override;

private:
    /**
     * @brief Execute refresh retry by cloning connection and reconnecting.
     * @param formId Form ID.
     * @param originalConnection Original connection to clone.
     */
    void ExecuteRefreshRetry(int64_t formId, sptr<FormAbilityConnection> originalConnection);

    /**
     * @brief Schedule refresh retry with common retry logic.
     *        Increments retry count, resets signals, and schedules retry task.
     *        Called when dual-signal confirmed and retry limit not reached.
     * @param formId Form ID.
     * @param policy Retry policy (must be already locked by caller).
     * @param connection Connection to use for retry.
     */
    void ScheduleRefreshRetry(int64_t formId, RetryPolicy &policy,
                              sptr<FormAbilityConnection> connection);
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_PROVIDER_REFRESH_ERROR_HANDLER_H