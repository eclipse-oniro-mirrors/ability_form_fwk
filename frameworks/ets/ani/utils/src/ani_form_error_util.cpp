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

#include "ani_form_error_util.h"

#include <cinttypes>
#include <regex>
#include <uv.h>
#include <vector>

#include "fms_log_wrapper.h"
#include "form_mgr.h"
#include "form_errors.h"
#include "runtime.h"

using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AbilityRuntime {
namespace {
const std::map<int32_t, std::string> CODE_MSG_MAP = {
    { ERR_OK, "success" },
    { ERR_COMMON, "internal error" },
    { ERR_PERMISSION_DENY, "does not have permission to use forms" },
    { ERR_GET_INFO_FAILED, "failed to obtain the configuration information" },
    { ERR_GET_BUNDLE_FAILED, "failed to obtain the bundle information" },
    { ERR_GET_LAYOUT_FAILED, "failed to initialize the form layout" },
    { ERR_ADD_INVALID_PARAM, "invalid input parameter during form operation" },
    { ERR_CFG_NOT_MATCH_ID, "the form id is different from that obtained for the first time" },
    { ERR_NOT_EXIST_ID, "the ID of the form to be operated does not exist" },
    { ERR_BIND_PROVIDER_FAILED, "failed to bind the Form Manager Service to the provider service" },
    { ERR_MAX_SYSTEM_FORMS, "the total number of added forms exceeds the maximum allowed by the system" },
    { ERR_MAX_INSTANCES_PER_FORM, "the number of form instances exceeds the maximum allowed by the system" },
    { ERR_OPERATION_FORM_NOT_SELF, "can not be operated by the current application" },
    { ERR_PROVIDER_DEL_FAIL, "failed to instruct the form provider to delete the form" },
    { ERR_MAX_FORMS_PER_CLIENT, "the total number of added forms exceeds the maximum per client" },
    { ERR_MAX_SYSTEM_TEMP_FORMS, "the total number of added temp forms exceeds the maximum in system" },
    { ERR_FORM_NO_SUCH_MODULE, "the module can not be find in system" },
    { ERR_FORM_NO_SUCH_ABILITY, "the ability can not be find in system" },
    { ERR_FORM_NO_SUCH_DIMENSION, "the dimension is not exist in the form" },
    { ERR_FORM_FA_NOT_INSTALLED, "the ability is not installed" },
    { ERR_SYSTEM_RESPONSES_FAILED, "failed to obtain the RPC object" },
    { ERR_FORM_DUPLICATE_ADDED, "failed to obtain the form requested by the client" },
    { ERR_DISTRIBUTED_SCHEDULE_FAILED, "failed to distributed schedule" },
    { ERR_IN_RECOVERY, "the form is being restored" }
};
constexpr const char *BUSINESS_ERROR_CLASS = "L@ohos/base/BusinessError;";
constexpr const char *ERROR_CLASS_NAME = "Lescompat/Error;";
}

bool EtsFormErrorUtil::ThrowParamError(ani_env *env, const std::string &extraMessage)
{
    std::string errorMessage = "Parameter error. " + extraMessage;
    return Throw(env, ERR_FORM_EXTERNAL_PARAM_INVALID, errorMessage);
}

bool EtsFormErrorUtil::ThrowByInternalErrorCode(ani_env *env, int32_t internalErrorCode)
{
    int32_t externalErrorCode = 0;
    std::string externalErrorMessage;
    FormMgr::GetInstance().GetExternalError(internalErrorCode, externalErrorCode, externalErrorMessage);
    return Throw(env, externalErrorCode, externalErrorMessage);
}

bool EtsFormErrorUtil::ThrowByExternalErrorCode(ani_env *env, int32_t externalErrorCode)
{
    std::string externalErrorMessage = FormMgr::GetInstance().GetErrorMsgByExternalErrorCode(externalErrorCode);
    return Throw(env, externalErrorCode, externalErrorMessage);
}

bool EtsFormErrorUtil::Throw(ani_env *env, int32_t errCode, const std::string &errMessage)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_object err = CreateError(env, errCode, errMessage);
    if (err == nullptr) {
        HILOG_ERROR("null err");
        return false;
    }
    env->ThrowError(static_cast<ani_error>(err));
    return true;
}

ani_object EtsFormErrorUtil::CreateErrorByInternalErrorCode(ani_env *env, int32_t internalErrorCode)
{
    int32_t externalErrorCode = 0;
    std::string externalErrorMessage;
    FormMgr::GetInstance().GetExternalError(internalErrorCode, externalErrorCode, externalErrorMessage);
    return CreateError(env, externalErrorCode, externalErrorMessage);
}

ani_object EtsFormErrorUtil::CreateError(ani_env *env, ani_int code, const std::string &msg)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(BUSINESS_ERROR_CLASS, &cls)) != ANI_OK) {
        HILOG_ERROR("FindClass failed %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object error = EtsFormErrorUtil::WrapError(env, msg);
    if (error == nullptr) {
        HILOG_ERROR("error nulll");
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, method, &obj)) != ANI_OK) {
        HILOG_ERROR("Object_New failed %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetFieldByName_Int(obj, "code", code)) != ANI_OK) {
        HILOG_ERROR("Object_SetFieldByName_Int failed %{public}d", status);
        return nullptr;
    }
    ani_string errMessage;
    if ((status = env->String_NewUTF8(msg.c_str(), msg.size(), &errMessage)) != ANI_OK) {
        HILOG_ERROR("String_NewUTF8 failed %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetPropertyByName_Ref(obj, "message", errMessage)) != ANI_OK) {
        HILOG_ERROR("Object_SetPropertyByName_Ref failed %{public}d", status);
        return nullptr;
    }
    return obj;
}

ani_object EtsFormErrorUtil::CreateError(ani_env *env, const ErrCode &err)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    return CreateError(env, static_cast<int32_t>(err), QueryRetMsg(err));
}

std::string EtsFormErrorUtil::QueryRetMsg(int32_t errorCode)
{
    auto iter = CODE_MSG_MAP.find(errorCode);
    if (iter != CODE_MSG_MAP.end()) {
        return iter->second;
    } else {
        return CODE_MSG_MAP.at(ERR_COMMON);
    }
}

ani_object EtsFormErrorUtil::WrapError(ani_env *env, const std::string &msg)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_string aniMsg = nullptr;
    if ((status = env->String_NewUTF8(msg.c_str(), msg.size(), &aniMsg)) != ANI_OK) {
        HILOG_ERROR("String_NewUTF8 failed %{public}d", status);
        return nullptr;
    }
    ani_ref undefRef;
    if ((status = env->GetUndefined(&undefRef)) != ANI_OK) {
        HILOG_ERROR("GetUndefined failed %{public}d", status);
        return nullptr;
    }
    ani_class cls = nullptr;
    if ((status = env->FindClass(ERROR_CLASS_NAME, &cls)) != ANI_OK) {
        HILOG_ERROR("FindClass failed %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method)) !=
        ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, method, &obj, aniMsg, undefRef)) != ANI_OK) {
        HILOG_ERROR("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}
} // namespace AbilityRuntime
} // namespace OHOS