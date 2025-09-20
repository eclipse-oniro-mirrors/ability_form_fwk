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

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::map<int32_t, int32_t> ERROR_CODE_MAP_EXTERNAL = {
    { ERR_OK,                                          ERR_OK },
    { ERR_APPEXECFWK_FORM_COMMON_CODE,                 ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_PERMISSION_DENY,             ERR_FORM_EXTERNAL_PERMISSION_DENIED },
    { ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE,      ERR_FORM_EXTERNAL_PERMISSION_DENIED },
    { ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,         ERR_FORM_EXTERNAL_NOT_SYSTEM_APP },
    { ERR_APPEXECFWK_FORM_GET_INFO_FAILED,             ERR_FORM_EXTERNAL_GET_INFO_FAILED },
    { ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED,           ERR_FORM_EXTERNAL_GET_INFO_FAILED },
    { ERR_APPEXECFWK_FORM_INVALID_PARAM,               ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_INVALID_FORM_ID,             ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,             ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR,              ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_RELEASE_FLG_ERR,             ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_REFRESH_TIME_NUM_ERR,        ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME,          ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_INVALID_MODULENAME,          ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_INVALID_PROVIDER_DATA,       ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_INVALID_REFRESH_TIME,        ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR,           ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR,           ERR_FORM_EXTERNAL_SERVICE_CONNECTION_ERROR },
    { ERR_APPEXECFWK_FORM_CFG_NOT_MATCH_ID,            ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST },
    { ERR_APPEXECFWK_FORM_NOT_EXIST_ID,                ERR_FORM_EXTERNAL_FORM_ID_NOT_EXIST },
    { ERR_APPEXECFWK_FORM_PROVIDER_DATA_EMPTY,         ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,        ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS,            ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND },
    { ERR_APPEXECFWK_FORM_EXCEED_INSTANCES_PER_FORM,   ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND },
    { ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,          ERR_FORM_EXTERNAL_OPERATION_FORM_NOT_SELF },
    { ERR_APPEXECFWK_FORM_PROVIDER_DEL_FAIL,           ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT,        ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND },
    { ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS,       ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND },
    { ERR_APPEXECFWK_FORM_NO_SUCH_MODULE,              ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY,             ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_NO_SUCH_DIMENSION,           ERR_FORM_EXTERNAL_PARAM_INVALID },
    { ERR_APPEXECFWK_FORM_FA_NOT_INSTALLED,            ERR_FORM_EXTERNAL_ABILITY_NOT_INSTALLED },
    { ERR_APPEXECFWK_FORM_MAX_REQUEST,                 ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND },
    { ERR_APPEXECFWK_FORM_MAX_REFRESH,                 ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND },
    { ERR_APPEXECFWK_FORM_GET_BMS_FAILED,              ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_GET_HOST_FAILED,             ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_GET_FMS_FAILED,              ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_SEND_FMS_MSG,                ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_FORM_DUPLICATE_ADDED,        ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_IN_RECOVER,                  ERR_FORM_EXTERNAL_SERVICE_CONNECTION_ERROR },
    { ERR_APPEXECFWK_FORM_DISTRIBUTED_SCHEDULE_FAILED, ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR },
    { ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED,           ERR_FORM_EXTERNAL_IPC_ERROR },
    { ERR_APPEXECFWK_FORM_CONNECT_FORM_RENDER_FAILED,  ERR_FORM_EXTERNAL_CONNECT_RENDER_FAILED },
    { ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED,         ERR_FORM_EXTERNAL_RENDER_DIED },
    { ERR_APPEXECFWK_FORM_NOT_TRUST,                   ERR_FORM_EXTERNAL_FORM_NOT_TRUST },
    { ERR_APPEXECFWK_FORM_ADD_FORM_TIME_OUT,           ERR_FORM_EXTERNAL_ADD_FORM_TIME_OUT},
    { ERR_APPEXECFWK_FORM_STATUS_TIMIE_OUT,            ERR_FORM_EXTERNAL_FORM_STATUS_TIMIE_OUT },
    { ERR_APPEXECFWK_FORM_SET_OPERATION_FAILED,        ERR_FORM_EXTERNAL_SET_OPERATION_FAILED },
    { ERR_APPEXECFWK_FORM_LIVE_OP_UNSUPPORTED,         ERR_FORM_EXTERNAL_LIVE_OP_UNSUPPORTED },
    { ERR_APPEXECFWK_SYSTEMCAP_ERROR,                  ERR_FORM_EXTERNAL_SYSTEMCAP_ERROR },
    { ERR_APPEXECFWK_FORM_DIMENSION_ERROR,             ERR_FORM_EXTERNAL_FORM_DIMENSION_ERROR},
};

const std::map<int32_t, std::string> ERR_MSG_MAP_EXTERNAL = {
    { ERR_OK,                                         "success" },
    { ERR_FORM_EXTERNAL_PERMISSION_DENIED,            "Permissions denied." },
    { ERR_FORM_EXTERNAL_PARAM_INVALID,                "Parameter error. Possible causes: "
        "1.Mandatory parameters are left unspecified; 2.Incorrect parameter types; 3.Parameter verification failed." },
    { ERR_FORM_EXTERNAL_SYSTEMCAP_ERROR,              "Capability not supported. "
        "Failed to call ${functionName} due to limited device capabilities." },
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
        "the configuration information of sceneAnimationParams in your form_config is correct." },
    { ERR_FORM_EXTERNAL_FORM_DIMENSION_ERROR,         "The dimension parameter is incorrect." },
};

const std::map<int32_t, std::string> ERR_MSG_MAP_INTERNAL = {
    { ERR_APPEXECFWK_FORM_INVALID_PARAM,   "" },
    { ERR_APPEXECFWK_FORM_INVALID_FORM_ID, "The formId is invalid." },
    { ERR_APPEXECFWK_PARCEL_ERROR, "Data serialization exception." },
};
}
FormErrors::FormErrors()
{
    InitErrorMessageMap();
}
FormErrors::~FormErrors()
{
}

/**
 * @brief Get the error message content.
 *
 * @param errCode Error code.
 * @return Message content.
 */
std::string FormErrors::GetErrorMessage(int errCode)
{
    if (errorMessageMap_.find(errCode) != errorMessageMap_.end()) {
        return errorMessageMap_[errCode];
    } else {
        return errorMessageMap_[ERR_APPEXECFWK_FORM_COMMON_CODE];
    }
}

int32_t FormErrors::QueryExternalErrorCode(int32_t internalErrorCode)
{
    auto iter = ERROR_CODE_MAP_EXTERNAL.find(internalErrorCode);
    if (iter != ERROR_CODE_MAP_EXTERNAL.end()) {
        return iter->second;
    }
    return ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR;
}

std::string FormErrors::QueryExternalErrorMessage(int32_t internalErrorCode, int32_t externalErrorCode)
{
    std::string errorMessage = GetErrorMsgByExternalErrorCode(externalErrorCode);

    auto iterInternal = ERR_MSG_MAP_INTERNAL.find(internalErrorCode);
    if (iterInternal == ERR_MSG_MAP_INTERNAL.end() || iterInternal->second.empty()) {
        return errorMessage;
    }
    errorMessage += " " + iterInternal->second;
    return errorMessage;
}

std::string FormErrors::GetErrorMsgByExternalErrorCode(int32_t externalErrorCode)
{
    auto iter = ERR_MSG_MAP_EXTERNAL.find(externalErrorCode);
    std::string errorMessage;
    if (iter != ERR_MSG_MAP_EXTERNAL.end()) {
        errorMessage = iter->second;
    } else {
        errorMessage = ERR_MSG_MAP_EXTERNAL.at(ERR_FORM_EXTERNAL_FUNCTIONAL_ERROR);
    }
    return errorMessage;
}

/**
 * @brief Init error message map object.
 *
 */
void FormErrors::InitErrorMessageMap()
{
    errorMessageMap_ = { //  error + message
        {
            ERR_APPEXECFWK_FORM_COMMON_CODE, "some internal server error occurs.",
        },
        {
            ERR_APPEXECFWK_FORM_PERMISSION_DENY,
            "check permission deny, need to request ohos.permission.REQUIRE_FORM"
                " or ohos.permission.INTERACT_ACROSS_LOCAL_ACCOUNTS.",
        },
        {
            ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE,
            "check permission deny, need to request ohos.permission.GET_BUNDLE_INFO_PRIVILEGED.",
        },
        {
            ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,
            "check permission deny, need system permission.",
        },
        {
            ERR_APPEXECFWK_FORM_GET_INFO_FAILED, "can't get form info by the formName.",
        },
        {
            ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED, "the requested bundle name does not exist.",
        },
        {
            ERR_APPEXECFWK_FORM_INVALID_PARAM, "invalid params received on operating form.",
        },
        {
            ERR_APPEXECFWK_FORM_INVALID_FORM_ID, "formId must be a string.",
        },
        {
            ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR, "formId must be a numeric string.",
        },
        {
            ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR, "formIds must be a array.",
        },
        {
            ERR_APPEXECFWK_FORM_RELEASE_FLG_ERR, "release cache flag must be a boolean.",
        },
        {
            ERR_APPEXECFWK_FORM_REFRESH_TIME_NUM_ERR, "refresh time must be a number.",
        },
        {
            ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR, "formId array is empty.",
        },
        {
            ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME, "bundleName is not available.",
        },
        {
            ERR_APPEXECFWK_FORM_INVALID_MODULENAME, "moduleName is not available.",
        },
        {
            ERR_APPEXECFWK_FORM_INVALID_PROVIDER_DATA, "moduleName is not available.",
        },
        {
            ERR_APPEXECFWK_FORM_INVALID_REFRESH_TIME, "refresh time is not available.",
        },
        {
            ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR, "form server error.",
        },
        {
            ERR_APPEXECFWK_FORM_CFG_NOT_MATCH_ID, "the form id and form config are not matched.",
        },
        {
            ERR_APPEXECFWK_FORM_NOT_EXIST_ID, "the requested form id is not existed on fms.",
        },
        {
            ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED, "fms bind provider failed.",
        },
        {
            ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS, "exceed max forms in system",
        },
        {
            ERR_APPEXECFWK_FORM_EXCEED_INSTANCES_PER_FORM, "exceed max instances per form, limit is 32.",
        },
        {
            ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,
            "the form to be operated is not self-owned or has been deleted already.",
        },
        {
            ERR_APPEXECFWK_FORM_PROVIDER_DEL_FAIL, "fms notify provider to delete failed.",
        },
        {
            ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT, "exceed max forms per client",
        },
        {
            ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS, "exceed max temp forms in system",
        },
        {
            ERR_APPEXECFWK_FORM_NO_SUCH_MODULE, "the module not exist in the bundle.",
        },
        {
            ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY, "the ability not exist in the module.",
        },
        {
            ERR_APPEXECFWK_FORM_NO_SUCH_DIMENSION, "the dimension not exist in the form.",
        },
        {
            ERR_APPEXECFWK_FORM_FA_NOT_INSTALLED, "the ability not installed,need install first.",
        },
        {
            ERR_APPEXECFWK_FORM_MAX_REQUEST, "too many request,try again later.",
        },
        {
            ERR_APPEXECFWK_FORM_MAX_REFRESH, "already refresh 50 times.",
        },
        {
            ERR_APPEXECFWK_FORM_GET_BMS_FAILED, "get bms rpc failed.",
        },
        {
            ERR_APPEXECFWK_FORM_GET_FMS_FAILED, "get fms rpc failed.",
        },
        {
            ERR_APPEXECFWK_FORM_SEND_FMS_MSG, "send request to fms failed.",
        },
        {
            ERR_APPEXECFWK_FORM_FORM_DUPLICATE_ADDED, "form do not support acquire same id twice.",
        },
        {
            ERR_APPEXECFWK_FORM_IN_RECOVER, "form is in recover status, can't do action on form.",
        },
        {
            ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED, "get system manager failed.",
        },
        {
            ERR_APPEXECFWK_PARCEL_ERROR, "read parcelable info failed.",
        },
        {
            ERR_APPEXECFWK_FORM_CONNECT_FORM_RENDER_FAILED, "Connect FormRenderService failed.",
        },
        {
            ERR_APPEXECFWK_FORM_RENDER_SERVICE_DIED, "FormRenderService is dead.",
        },
        {
            ERR_APPEXECFWK_FORM_STATUS_TIMIE_OUT, "form status timeout, try reAddForm.",
        },
        {
            ERR_APPEXECFWK_FORM_SET_OPERATION_FAILED, "Failed to set the live form background image.",
        },
    };
}
}  // namespace AppExecFwk
}  // namespace OHOS
