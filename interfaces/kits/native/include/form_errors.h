/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
enum {
    ERR_FORM_EXTERNAL_PERMISSION_DENIED = 201,
    ERR_FORM_EXTERNAL_NOT_SYSTEM_APP = 202,
    ERR_FORM_EXTERNAL_PARAM_INVALID = 401,
    ERR_FORM_EXTERNAL_SYSTEMCAP_ERROR = 801,
    ERR_FORM_EXTERNAL_KERNEL_ERROR = 16500001,
    ERR_FORM_EXTERNAL_KERNEL_MALLOC_ERROR = 16500002,
    ERR_FORM_EXTERNAL_IPC_ERROR = 16500050,
    ERR_FORM_EXTERNAL_SERVICE_CONNECTION_ERROR = 16500060,
    ERR_FORM_EXTERNAL_GET_INFO_FAILED = 16500100,
    ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR = 16501000,
    ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST = 16501001,
    ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND = 16501002,
    ERR_FORM_EXTERNAL_OPERATION_FORM_NOT_SELF = 16501003,
    ERR_FORM_EXTERNAL_ABILITY_NOT_INSTALLED = 16501004,
    ERR_FORM_EXTERNAL_CONNECT_RENDER_FAILED = 16501005,
    ERR_FORM_EXTERNAL_RENDER_DIED = 16501006,
};

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
     * @param errCode Error code.
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

private:
    /**
    * @brief Init error message map object.
    *
    */
    void InitErrorMessageMap();

private:
    std::map<ErrCode, std::string> errorMessageMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_FORM_ERRORS_H
