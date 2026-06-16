/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_ANI_FORM_ERROR_UTIL_H
#define OHOS_FORM_FWK_ANI_FORM_ERROR_UTIL_H

#include "ability.h"
#include "ani.h"

namespace OHOS {
namespace AbilityRuntime {
constexpr int32_t ERR_COMMON = 1;
constexpr int32_t ERR_PERMISSION_DENY = 2;
constexpr int32_t ERR_GET_INFO_FAILED = 4;
constexpr int32_t ERR_GET_BUNDLE_FAILED = 5;
constexpr int32_t ERR_GET_LAYOUT_FAILED = 6;
constexpr int32_t ERR_ADD_INVALID_PARAM = 7;
constexpr int32_t ERR_CFG_NOT_MATCH_ID = 8;
constexpr int32_t ERR_NOT_EXIST_ID = 9;
constexpr int32_t ERR_BIND_PROVIDER_FAILED = 10;
constexpr int32_t ERR_MAX_SYSTEM_FORMS = 11;
constexpr int32_t ERR_MAX_INSTANCES_PER_FORM = 12;
constexpr int32_t ERR_OPERATION_FORM_NOT_SELF = 13;
constexpr int32_t ERR_PROVIDER_DEL_FAIL = 14;
constexpr int32_t ERR_MAX_FORMS_PER_CLIENT = 15;
constexpr int32_t ERR_MAX_SYSTEM_TEMP_FORMS = 16;
constexpr int32_t ERR_FORM_NO_SUCH_MODULE = 17;
constexpr int32_t ERR_FORM_NO_SUCH_ABILITY = 18;
constexpr int32_t ERR_FORM_NO_SUCH_DIMENSION = 19;
constexpr int32_t ERR_FORM_FA_NOT_INSTALLED = 20;
constexpr int32_t ERR_SYSTEM_RESPONSES_FAILED = 30;
constexpr int32_t ERR_FORM_DUPLICATE_ADDED = 31;
constexpr int32_t ERR_IN_RECOVERY = 36;
constexpr int32_t ERR_DISTRIBUTED_SCHEDULE_FAILED = 37;
constexpr int32_t CALLBACK_RETURN_MSG_SIZE = 2;

class EtsFormErrorUtil {
public:
    static bool ThrowParamError(ani_env *env, const std::string &extraMessage);
    static bool ThrowByInternalErrorCode(ani_env *env, int32_t internalErrorCode);
    static bool Throw(ani_env *env, int32_t errCode, const std::string &errMessage);
    static bool ThrowByExternalErrorCode(ani_env *env, int32_t externalErrorCode);
    static bool ThrowParamTypeError(ani_env *env, const std::string &paramName, const std::string &type);
    static ani_object CreateError(ani_env *env, ani_int code, const std::string &msg);
    static ani_object CreateError(ani_env *env, const ErrCode &err);
    static ani_object WrapError(ani_env *env, const std::string &msg);
    static ani_object CreateErrorByInternalErrorCode(ani_env *env, int32_t internalErrorCode);
    static std::string QueryRetMsg(int32_t errorCode);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif /* OHOS_FORM_FWK_ANI_FORM_ERROR_UTIL_H */