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

#include <memory>

#include "form_provider/error_handler/provider_connection_error_handler.h"

namespace OHOS {
namespace AppExecFwk {

class FormProviderRefreshErrorHandler : public FormProviderConnectionErrorHandler,
    public std::enable_shared_from_this<FormProviderRefreshErrorHandler> {
public:
    DISALLOW_COPY_AND_MOVE(FormProviderRefreshErrorHandler);

    static std::shared_ptr<FormProviderRefreshErrorHandler> Create();

    bool HandleSendRequestFailed(int64_t formId, int errorCode, const Want &want) override;

    bool HandleDisconnectError(int64_t formId, const sptr<IRemoteObject> &remoteObject, const Want &want,
        ConnectState state) override;

private:
    FormProviderRefreshErrorHandler() = default;
    void ExecuteRefreshRetry(int64_t formId, const Want &want);
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_PROVIDER_REFRESH_ERROR_HANDLER_H