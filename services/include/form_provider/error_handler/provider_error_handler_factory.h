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

#ifndef OHOS_FORM_FWK_PROVIDER_ERROR_HANDLER_FACTORY_H
#define OHOS_FORM_FWK_PROVIDER_ERROR_HANDLER_FACTORY_H

#include <memory>

#include "form_provider/error_handler/provider_acquire_error_handler.h"
#include "form_provider/error_handler/provider_refresh_error_handler.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {

class FormProviderErrorHandlerFactory {
public:
    static sptr<FormProviderRefreshErrorHandler> GetRefreshHandler()
    {
        static sptr<FormProviderRefreshErrorHandler> instance = new FormProviderRefreshErrorHandler();
        return instance;
    }

    static sptr<FormProviderAcquireErrorHandler> GetAcquireHandler()
    {
        static sptr<FormProviderAcquireErrorHandler> instance = new FormProviderAcquireErrorHandler();
        return instance;
    }

private:
    FormProviderErrorHandlerFactory() = default;
    DISALLOW_COPY_AND_MOVE(FormProviderErrorHandlerFactory);
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_PROVIDER_ERROR_HANDLER_FACTORY_H