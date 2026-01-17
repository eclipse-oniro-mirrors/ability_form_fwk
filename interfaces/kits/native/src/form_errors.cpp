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

#include "form_errors.h"
#include "appexecfwk_errors.h"
#include "form_mgr_errors.h"
#include "ability_business_error/ability_business_error.h"

namespace OHOS {
namespace AppExecFwk {
using AbilityErrorCode = AbilityRuntime::AbilityErrorCode;
namespace {
struct FormErrInfo {
    int32_t externalErr;
    std::string detailMsg = "";
};

// struct： <internalErrCode, {externalErrCode, detailMsg}>
// default: <ERR_APPEXECFWK_FORM_COMMON_CODE, {ERR_FORM_EXTERNAL_FUNCTIONAL_ERRO, An internal functional error occurred>
static const std::unordered_map<int32_t, FormErrInfo> FORM_ERROR_CODES = {
    {
        ERR_OK, { ERR_OK, "" }
    },
    {
        ERR_APPEXECFWK_FORM_COMMON_CODE, { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "" }
    },
    {
        ERR_APPEXECFWK_FORM_PERMISSION_DENY,
        {
            ERR_FORM_EXTERNAL_PERMISSION_DENIED,
            "check permission deny, need to request ohos.permission.REQUIRE_FORM or "
            "ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS."
        }
    },
    {
        ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
        {
            ERR_FORM_EXTERNAL_NOT_SYSTEM_APP,
            "The application is not a system application, check permission deny, need system permission."
        }
    },
    {
        ERR_APPEXECFWK_FORM_GET_INFO_FAILED, { ERR_FORM_EXTERNAL_GET_INFO_FAILED, "" }
    },
    {
        ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED,
        { ERR_FORM_EXTERNAL_GET_INFO_FAILED, "the requested bundle name does not exist." }
    },
    {
        ERR_APPEXECFWK_FORM_INVALID_PARAM, { ERR_FORM_EXTERNAL_PARAM_INVALID, "" }
    },
    {
        ERR_APPEXECFWK_FORM_INVALID_FORM_ID, { ERR_FORM_EXTERNAL_PARAM_INVALID, "The formId is invalid." }
    },
    {
        ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR, { ERR_FORM_EXTERNAL_PARAM_INVALID, "formId must be a numeric string." }
    },
    {
        ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR, { ERR_FORM_EXTERNAL_PARAM_INVALID, "formIds must be a array." }
    },
    {
        ERR_APPEXECFWK_FORM_RELEASE_FLG_ERR,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "release cache flag must be a boolean." }
    },
    {
        ERR_APPEXECFWK_FORM_REFRESH_TIME_NUM_ERR,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "refresh time must be a number." }
    },
    {
        ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME, { ERR_FORM_EXTERNAL_PARAM_INVALID, "bundleName is not available." }
    },
    {
        ERR_APPEXECFWK_FORM_INVALID_MODULENAME, { ERR_FORM_EXTERNAL_PARAM_INVALID, "moduleName is not available." }
    },
    {
        ERR_APPEXECFWK_FORM_INVALID_PROVIDER_DATA, { ERR_FORM_EXTERNAL_PARAM_INVALID, "" }
    },
    {
        ERR_APPEXECFWK_FORM_INVALID_REFRESH_TIME, { ERR_FORM_EXTERNAL_PARAM_INVALID, "refresh time is not available." }
    },
    {
        ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR, { ERR_FORM_EXTERNAL_PARAM_INVALID, "formId array is empty." }
    },
    {
        ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR, { ERR_FORM_EXTERNAL_SERVICE_CONNECTION_ERROR, "" }
    },
    {
        ERR_APPEXECFWK_FORM_CFG_NOT_MATCH_ID,
        { ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST, "the form id and form config are not matched." }
    },
    {
        ERR_APPEXECFWK_FORM_NOT_EXIST_ID, { ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST, "" }
    },
    {
        ERR_APPEXECFWK_FORM_PROVIDER_DATA_EMPTY, { ERR_FORM_EXTERNAL_PARAM_INVALID, "" }
    },
    {
        ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "fms bind provider failed." }
    },
    {
        ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS,
        { ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND, "exceed max forms in system" }
    },
    {
        ERR_APPEXECFWK_FORM_EXCEED_INSTANCES_PER_FORM,
        {  ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND, "exceed max instances per form, limit is 32." }
    },
    {
        ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,
        {
            ERR_FORM_EXTERNAL_OPERATION_FORM_NOT_SELF,
            "the form to be operated is not self-owned or has been deleted already."
        }
    },
    {
        ERR_APPEXECFWK_FORM_PROVIDER_DEL_FAIL,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "fms notify provider to delete failed." }
    },
    {
        ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT,
        { ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND, "exceed max forms per client" }
    },
    {
        ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS,
        { ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND, "exceed max temp forms in system" }
    },
    {
        ERR_APPEXECFWK_FORM_NO_SUCH_MODULE, { ERR_FORM_EXTERNAL_PARAM_INVALID, "the module not exist in the bundle." }
    },
    {
        ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY, { ERR_FORM_EXTERNAL_PARAM_INVALID, "the ability not exist in the module." }
    },
    {
        ERR_APPEXECFWK_FORM_NO_SUCH_DIMENSION,
        { ERR_FORM_EXTERNAL_PARAM_INVALID, "the dimension not exist in the form." }
    },
    {
        ERR_APPEXECFWK_FORM_FA_NOT_INSTALLED,
        { ERR_FORM_EXTERNAL_ABILITY_NOT_INSTALLED, "the ability not installed, need install first." }
    },
    {
        ERR_APPEXECFWK_FORM_MAX_REQUEST,
        { ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND, "too many request,try again later." }
    },
    {
        ERR_APPEXECFWK_FORM_MAX_REFRESH, { ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND, "already refresh 50 times." }
    },
    {
        ERR_APPEXECFWK_FORM_GET_BMS_FAILED, { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "get bms rpc failed." }
    },
    {
        ERR_APPEXECFWK_FORM_GET_HOST_FAILED, { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "" }
    },
    {
        ERR_APPEXECFWK_FORM_GET_FMS_FAILED, { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "get fms rpc failed." }
    },
    {
        ERR_APPEXECFWK_FORM_SEND_FMS_MSG, { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "send request to fms failed." }
    },
    {
        ERR_APPEXECFWK_FORM_FORM_DUPLICATE_ADDED,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "form do not support acquire same id twice." }
    },
    {
        ERR_APPEXECFWK_FORM_IN_RECOVER,
        { ERR_FORM_EXTERNAL_SERVICE_CONNECTION_ERROR, "form is in recover status, can't do action on form." }
    },
    {
        ERR_APPEXECFWK_FORM_DISTRIBUTED_SCHEDULE_FAILED, { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "" }
    },
    {
        ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED,
        { ERR_FORM_EXTERNAL_IPC_ERROR, "get system manager failed, or IPC connection error" }
    },
    {
        ERR_APPEXECFWK_FORM_CONNECT_FORM_RENDER_FAILED, { ERR_FORM_EXTERNAL_CONNECT_RENDER_FAILED, "" }
    },
    {
        ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED, { ERR_FORM_EXTERNAL_RENDER_DIED, "" }
    },
    {
        ERR_APPEXECFWK_FORM_NOT_TRUST, { ERR_FORM_EXTERNAL_FORM_NOT_TRUST, "" }
    },
    {
        ERR_APPEXECFWK_FORM_ADD_FORM_TIME_OUT, { ERR_FORM_EXTERNAL_ADD_FORM_TIME_OUT, "" }
    },
    {
        ERR_APPEXECFWK_FORM_STATUS_TIMIE_OUT, { ERR_FORM_EXTERNAL_FORM_STATUS_TIMIE_OUT, "" }
    },
    {
        ERR_APPEXECFWK_FORM_SET_OPERATION_FAILED, { ERR_FORM_EXTERNAL_SET_OPERATION_FAILED, "" }
    },
    {
        ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED,
        {
            ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED,
            "The form can not support this operation, please check if the interface is directly used in click event "
            "callback."
        }
    },
    {
        ERR_APPEXECFWK_SYSTEMCAP_ERROR, { ERR_FORM_EXTERNAL_SYSTEMCAP_ERROR, "" }
    },
    {
        ERR_APPEXECFWK_FORM_DIMENSION_ERROR, { ERR_FORM_EXTERNAL_FORM_DIMENSION_ERROR, "" }
    },
    {
        ERR_APPEXECFWK_FORM_LIVE_OP_PAGE_INFO_MISTMATCH,
        {
            ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED,
            "The form can not support this operation, please check if page information specified in want belongs to "
            "the formProvider application."
        }
    },
    {
        ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE,
        {
            ERR_FORM_EXTERNAL_PERMISSION_DENIED,
            "check permission deny, need to request ohos.permission.GET_BUNDLE_INFO_PRIVILEGED."
        }
    },
    {
        ERR_APPEXECFWK_PARCEL_ERROR, { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "Data serialization exception." }
    },
    {
        ERR_APPEXECFWK_TEMPLATE_FORM_IPC_CONNECTION_FAILED, { ERR_FORM_EXTERNAL_IPC_ERROR, "" }
    },
    {
        ERR_APPEXECFWK_FORM_NOT_UI_ABILITY,
        {
            static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_TARGET_TYPE_NOT_UI_ABILITY),
            "Target ability is not UI ability."
        }
    },
    {
        ERR_APPEXECFWK_FORM_ABILITY_NOT_FOREGROUND,
        {
            ERR_FORM_EXTERNAL_FORM_ABILITY_NOT_FOREGROUND,
            "The form edit page is not in the foreground. The current operation is not supported."
        }
    },
    {
        ERR_APPEXECFWK_TEMPLATE_UNSUPPORTED_OPERATION, { ERR_FORM_EXTERNAL_SYSTEM_UNSUPPORT_OPERATION, "" }
    },
    {
        ERR_APPEXECFWK_FORM_EDIT_UNSUPPORT_OPERATION,
        {
            ERR_FORM_EXTERNAL_FORM_EDIT_OP_UNSUPPORTED,
            "Cannot close the widget editing page. The page is not in the foreground or not owned by the caller."
        }
    },
    {
        ERR_APPEXECFWK_CALLING_NOT_UI_ABILITY,
        { ERR_FORM_EXTERNAL_PARAM_INVALID, "The context is not ability context." }
    },
    {
        ERR_APPEXECFWK_LIVE_FORM_IS_ACTIVING,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "The live form is activing." }
    },
    {
        ERR_APPEXECFWK_LIVE_FORM_POWER_MODE_ERROR,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "Device status check failed, possibly due to power saving mode." }
    },
    {
        ERR_APPEXECFWK_LIVE_FORM_HOT_CONTROL,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "Device status check failed, possibly due to hot control." }
    },
    {
        ERR_APPEXECFWK_LIVE_FORM_HOST_STATUS_ERROR,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "Form Host status check failed." }
    },
    {
        ERR_APPEXECFWK_LIVE_FORM_OVERFLOW_COMPETITION_FAILED,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "The live form overflow competition failure." }
    },
    {
        ERR_APPEXECFWK_LIVE_FORM_OVERFLOW_PARAMS_ERROR,
        { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR, "The live form overflow request parameter is invalid." }
    }
};

static const std::unordered_map<int32_t, std::string> EXTERNAL_ERR_RELATED_MSG = {
    { ERR_OK,                                         "success" },
    { ERR_FORM_EXTERNAL_PERMISSION_DENIED,            "Permissions denied." },
    { ERR_FORM_EXTERNAL_PARAM_INVALID,                "Parameter error. Possible causes: 1.Mandatory parameters are "
        "left unspecified; 2.Incorrect parameter types; 3.Parameter verification failed." },
    { ERR_FORM_EXTERNAL_SYSTEMCAP_ERROR,              "Capability not supported. Failed to call ${functionName} due "
        "to limited device capabilities." },
    { ERR_FORM_EXTERNAL_KERNEL_ERROR,                 "A generic kernel error occurred." },
    { ERR_FORM_EXTERNAL_KERNEL_MALLOC_ERROR,          "Failed to alloc." },
    { ERR_FORM_EXTERNAL_IPC_ERROR,                    "IPC connection error." },
    { ERR_FORM_EXTERNAL_SERVICE_CONNECTION_ERROR,     "Service connection error." },
    { ERR_FORM_EXTERNAL_GET_INFO_FAILED,              "Failed to obtain the configuration information." },
    { ERR_FORM_EXTERNAL_NOT_SYSTEM_APP,               "The application is not a system application." },
    { ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR,             "An internal functional error occurred." },
    { ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND, "The number of forms exceeds the maximum allowed." },
    { ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST,            "The ID of the form to be operated does not exist" },
    { ERR_FORM_EXTERNAL_OPERATION_FORM_NOT_SELF,      "The form cannot be operated by the current application." },
    { ERR_FORM_EXTERNAL_ABILITY_NOT_INSTALLED,        "The ability is not installed" },
    { ERR_FORM_EXTERNAL_CONNECT_RENDER_FAILED,        "Failed to connect to FormRenderService." },
    { ERR_FORM_EXTERNAL_RENDER_DIED,                  "FormRenderService is dead, please reconnect." },
    { ERR_FORM_EXTERNAL_FORM_NOT_TRUST,               "Form is not trust." },
    { ERR_FORM_EXTERNAL_ADD_FORM_TIME_OUT,            "Waiting for the form addition to the desktop timed out." },
    { ERR_FORM_EXTERNAL_FORM_STATUS_TIMIE_OUT,        "form status timeout, try reAddForm." },
    { ERR_FORM_EXTERNAL_SET_OPERATION_FAILED,         "Failed to set the live form background image." },
    { ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED,          "The form can not support this operation, Please check whether "
        "the configuration information of sceneAnimationParams in your form_config is correct."},
    { ERR_FORM_EXTERNAL_FORM_DIMENSION_ERROR,         "The dimension parameter is incorrect." },
    { ERR_FORM_EXTERNAL_SYSTEM_UNSUPPORT_OPERATION,   "The system does not support the current operation."},
    { ERR_FORM_EXTERNAL_FORM_ABILITY_NOT_FOREGROUND,  "The app is not in the foreground." },
    { ERR_FORM_EXTERNAL_FORM_EDIT_OP_UNSUPPORTED,     "Cannot close the widget editing page opened by other apps." },
};
}

FormErrors::FormErrors()
{
}
FormErrors::~FormErrors()
{
}

/**
 * @brief Get the error message content.
 *
 * @param errCode Internal error code
 * @return Message content.
 */
std::string FormErrors::GetErrorMessage(int internalErrorCode)
{
    auto iter = FORM_ERROR_CODES.find(internalErrorCode);
    if (iter != FORM_ERROR_CODES.end() && !iter->second.detailMsg.empty()) {
        return iter->second.detailMsg;
    }
    return GetErrorMsgByExternalErrorCode(QueryExternalErrorCode(internalErrorCode));
}

/**
 * @brief Get external error code by internal error code.
 *
 * @param internalErrorCode Internal error code.
 * @return External error code.
 */
int32_t FormErrors::QueryExternalErrorCode(int32_t internalErrorCode)
{
    auto iter = FORM_ERROR_CODES.find(internalErrorCode);
    if (iter != FORM_ERROR_CODES.end()) {
        return iter->second.externalErr;
    }
    return ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR;
}

/**
 * @brief Get external error message by error code.
 *
 * @param internalErrorCode Internal error code.
 * @param externalErrorCode External error code.
 * @return External error message.
 */
std::string FormErrors::QueryExternalErrorMessage(int32_t internalErrorCode, int32_t externalErrorCode)
{
    auto iter = FORM_ERROR_CODES.find(internalErrorCode);
    if (iter != FORM_ERROR_CODES.end() && !iter->second.detailMsg.empty()) {
        return iter->second.detailMsg;
    }
    return GetErrorMsgByExternalErrorCode(externalErrorCode);
}

/**
 * @brief Get external error message by external error code.
 *
 * @param externalErrorCode External error code.
 * @return External error message.
 */
std::string FormErrors::GetErrorMsgByExternalErrorCode(int32_t externalErrorCode)
{
    std::string errorMessage = EXTERNAL_ERR_RELATED_MSG.at(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR);
    auto iter = EXTERNAL_ERR_RELATED_MSG.find(externalErrorCode);
    if (iter != EXTERNAL_ERR_RELATED_MSG.end()) {
        errorMessage = iter->second;
    }
    return errorMessage;
}
}  // namespace AppExecFwk
}  // namespace OHOS
