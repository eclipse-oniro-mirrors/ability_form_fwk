/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_ERRORS_H
#define OHOS_FORM_FWK_FORM_ERRORS_H

#include <cstring>
#include <map>

#include "errors.h"
#include "nocopyable.h"
#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormErrors
 * FormErrors is used to access form error message.
 */
class FormErrors final : public DelayedRefSingleton<FormErrors> {
    DECLARE_DELAYED_REF_SINGLETON(FormErrors)
public:
    DISALLOW_COPY_AND_MOVE(FormErrors);

    /**
     * @brief Get the error message content.
     *
     * @param errCode Internal error code
     * @return Message content.
     */
    std::string GetErrorMessage(int errCode);

    /**
     * @brief Get external error code by internal error code.
     *
     * @param internalErrorCode Internal error code.
     * @return External error code.
     */
    int32_t QueryExternalErrorCode(int32_t internalErrorCode);

    /**
     * @brief Get external error message by error code.
     *
     * @param internalErrorCode Internal error code.
     * @param externalErrorCode External error code.
     * @return External error message.
     */
    std::string QueryExternalErrorMessage(int32_t internalErrorCode, int32_t externalErrorCode);

    /**
     * @brief Get external error message by external error code.
     *
     * @param externalErrorCode External error code.
     * @return External error message.
     */
    std::string GetErrorMsgByExternalErrorCode(int32_t externalErrorCode);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_ERRORS_H
