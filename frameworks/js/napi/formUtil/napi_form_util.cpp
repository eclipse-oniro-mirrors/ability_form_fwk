/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "napi_form_util.h"

#include <cinttypes>
#include <regex>
#include <uv.h>
#include <vector>

#include "fms_log_wrapper.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "running_form_info.h"
#include "runtime.h"

using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr int INT_64_LENGTH = 19;
constexpr int ZERO_VALUE = 0;
constexpr int REF_COUNT = 1;
constexpr int DECIMAL_VALUE = 10;
constexpr int BASE_NUMBER = 9;
constexpr int CALLBACK_FLG = 1;
const std::map<int32_t, int32_t> ERROR_CODE_MAP = {
    { ERR_OK,                                             ERR_OK },
    { ERR_APPEXECFWK_FORM_COMMON_CODE,                    ERR_COMMON },
    { ERR_APPEXECFWK_FORM_PERMISSION_DENY,                ERR_PERMISSION_DENY },
    { ERR_APPEXECFWK_FORM_PERMISSION_DENY_BUNDLE,         ERR_PERMISSION_DENY },
    { ERR_APPEXECFWK_FORM_PERMISSION_DENY_SYS,            ERR_PERMISSION_DENY },
    { ERR_APPEXECFWK_FORM_GET_INFO_FAILED,                ERR_GET_INFO_FAILED },
    { ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED,              ERR_GET_BUNDLE_FAILED },
    { ERR_APPEXECFWK_FORM_INVALID_PARAM,                  ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_INVALID_FORM_ID,                ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,                ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_FORM_ARRAY_ERR,                 ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_RELEASE_FLG_ERR,                ERR_COMMON },
    { ERR_APPEXECFWK_FORM_REFRESH_TIME_NUM_ERR,           ERR_COMMON },
    { ERR_APPEXECFWK_FORM_INVALID_BUNDLENAME,             ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_INVALID_MODULENAME,             ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_INVALID_PROVIDER_DATA,          ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_INVALID_REFRESH_TIME,           ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_FORM_ID_ARRAY_ERR,              ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_SERVER_STATUS_ERR,              ERR_COMMON },
    { ERR_APPEXECFWK_FORM_CFG_NOT_MATCH_ID,               ERR_CFG_NOT_MATCH_ID },
    { ERR_APPEXECFWK_FORM_NOT_EXIST_ID,                   ERR_NOT_EXIST_ID },
    { ERR_APPEXECFWK_FORM_PROVIDER_DATA_EMPTY,            ERR_ADD_INVALID_PARAM },
    { ERR_APPEXECFWK_FORM_BIND_PROVIDER_FAILED,           ERR_BIND_PROVIDER_FAILED },
    { ERR_APPEXECFWK_FORM_MAX_SYSTEM_FORMS,               ERR_MAX_SYSTEM_FORMS },
    { ERR_APPEXECFWK_FORM_EXCEED_INSTANCES_PER_FORM,      ERR_MAX_INSTANCES_PER_FORM },
    { ERR_APPEXECFWK_FORM_OPERATION_NOT_SELF,             ERR_OPERATION_FORM_NOT_SELF },
    { ERR_APPEXECFWK_FORM_PROVIDER_DEL_FAIL,              ERR_PROVIDER_DEL_FAIL },
    { ERR_APPEXECFWK_FORM_MAX_FORMS_PER_CLIENT,           ERR_MAX_FORMS_PER_CLIENT },
    { ERR_APPEXECFWK_FORM_MAX_SYSTEM_TEMP_FORMS,          ERR_MAX_SYSTEM_TEMP_FORMS },
    { ERR_APPEXECFWK_FORM_NO_SUCH_MODULE,                 ERR_FORM_NO_SUCH_MODULE },
    { ERR_APPEXECFWK_FORM_NO_SUCH_ABILITY,                ERR_FORM_NO_SUCH_ABILITY },
    { ERR_APPEXECFWK_FORM_NO_SUCH_DIMENSION,              ERR_FORM_NO_SUCH_DIMENSION },
    { ERR_APPEXECFWK_FORM_FA_NOT_INSTALLED,               ERR_FORM_FA_NOT_INSTALLED },
    { ERR_APPEXECFWK_FORM_MAX_REQUEST,                    ERR_MAX_SYSTEM_FORMS },
    { ERR_APPEXECFWK_FORM_MAX_REFRESH,                    ERR_MAX_SYSTEM_FORMS },
    { ERR_APPEXECFWK_FORM_GET_BMS_FAILED,                 ERR_COMMON },
    { ERR_APPEXECFWK_FORM_GET_HOST_FAILED,                ERR_COMMON },
    { ERR_APPEXECFWK_FORM_GET_FMS_FAILED,                 ERR_COMMON },
    { ERR_APPEXECFWK_FORM_SEND_FMS_MSG,                   ERR_COMMON },
    { ERR_APPEXECFWK_FORM_FORM_DUPLICATE_ADDED,           ERR_FORM_DUPLICATE_ADDED },
    { ERR_APPEXECFWK_FORM_IN_RECOVER,                     ERR_IN_RECOVERY },
    { ERR_APPEXECFWK_FORM_DISTRIBUTED_SCHEDULE_FAILED,    ERR_DISTRIBUTED_SCHEDULE_FAILED },
    { ERR_APPEXECFWK_FORM_GET_SYSMGR_FAILED,              ERR_SYSTEM_RESPONSES_FAILED }
};
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
}

bool NapiFormUtil::Throw(napi_env env, int32_t errCode, const std::string &errMessage)
{
    napi_value error = CreateJsError(env, errCode, errMessage);
    napi_throw(env, error);
    return true;
}

bool NapiFormUtil::ThrowByInternalErrorCode(napi_env env, int32_t internalErrorCode)
{
    int32_t externalErrorCode = 0;
    std::string externalErrorMessage;
    FormMgr::GetInstance().GetExternalError(internalErrorCode, externalErrorCode, externalErrorMessage);
    return Throw(env, externalErrorCode, externalErrorMessage);
}

bool NapiFormUtil::ThrowByExternalErrorCode(napi_env env, int32_t externalErrorCode)
{
    std::string externalErrorMessage = FormMgr::GetInstance().GetErrorMsgByExternalErrorCode(externalErrorCode);
    return Throw(env, externalErrorCode, externalErrorMessage);
}

napi_value NapiFormUtil::CreateErrorByInternalErrorCode(napi_env env, int32_t internalErrorCode)
{
    int32_t externalErrorCode = 0;
    std::string externalErrorMessage;
    FormMgr::GetInstance().GetExternalError(internalErrorCode, externalErrorCode, externalErrorMessage);
    return CreateJsError(env, externalErrorCode, externalErrorMessage);
}

napi_value NapiFormUtil::CreateErrorByExternalErrorCode(napi_env env, int32_t externalErrorCode)
{
    std::string externalErrorMessage = FormMgr::GetInstance().GetErrorMsgByExternalErrorCode(externalErrorCode);
    return CreateJsError(env, externalErrorCode, externalErrorMessage);
}

bool NapiFormUtil::ThrowParamTypeError(napi_env env, const std::string &paramName, const std::string &type)
{
    return Throw(env, ERR_FORM_EXTERNAL_PARAM_INVALID, CreateParamTypeErrorMessage(paramName, type));
}

bool NapiFormUtil::ThrowParamNumError(napi_env env, const std::string &gotNum, const std::string &expectedNum)
{
    std::string errorMessage = "Parameter error. Got " + gotNum + ", expected " + expectedNum;
    return Throw(env, ERR_FORM_EXTERNAL_PARAM_INVALID, errorMessage);
}

bool NapiFormUtil::ThrowParamError(napi_env env, const std::string &extraMessage)
{
    std::string errorMessage = "Parameter error. " + extraMessage;
    return Throw(env, ERR_FORM_EXTERNAL_PARAM_INVALID, errorMessage);
}

std::string NapiFormUtil::CreateParamTypeErrorMessage(const std::string &paramName, const std::string &type)
{
    std::string errorMessage = "Parameter error.";
    if (paramName.empty()) {
        // Parameter error.
        return errorMessage;
    }
    errorMessage += " The type of \"" + paramName + "\"";
    if (type.empty()) {
        errorMessage += " is invalid.";
        // Parameter error. The type of "paramName" is invalid.
        return errorMessage;
    }
    errorMessage += " must be " + type + ".";
    // Parameter error. The type of "${paramName}" must be ${type}.
    return errorMessage;
}

/**
 * @brief query the error message by error code
 *
 * @param[in] errorCode the error code return by form JS API.
 *
 * @return the error detail message
 */
std::string QueryRetMsg(int32_t errorCode)
{
    auto iter = CODE_MSG_MAP.find(errorCode);
    if (iter != CODE_MSG_MAP.end()) {
        return iter->second;
    } else {
        return CODE_MSG_MAP.at(ERR_COMMON);
    }
}

/**
 * @brief query the error code by FMS errcode
 *
 * @param[in] innerErrorCode the error code return by form native API.
 *
 * @return the error detail message
 */
int32_t QueryRetCode(int32_t innerErrorCode)
{
    auto iter = ERROR_CODE_MAP.find(innerErrorCode);
    if (iter != ERROR_CODE_MAP.end()) {
        return iter->second;
    } else {
        return ERR_COMMON;
    }
}

/**
 * @brief NapiGetResult
 *
 * @param[in] env The environment that the Node-API call is invoked under
 *
 * @return napi_value
 */
napi_value NapiGetResult(napi_env env, int iResult)
{
    napi_value result;
    NAPI_CALL(env, napi_create_int32(env, iResult, &result));
    return result;
}

/**
 * @brief Convert string to int64_t
 *
 * @param[in] strInfo The string information
 * @param[out] int64Value Convert string to int64_t
 *
 * @return Return the convert result
 */
bool ConvertStringToInt64(const std::string &strInfo, int64_t &int64Value)
{
    size_t strLength = strInfo.size();
    if (strLength == ZERO_VALUE) {
        int64Value = ZERO_VALUE;
        return true;
    }
    std::regex pattern("^0|-?[1-9][0-9]{0,18}$"); // "^-?[0-9]{1,19}$"
    std::smatch match;
    if (regex_match(strInfo, match, pattern)) {
        HILOG_DEBUG("%{public}s, regex_match successed.", __func__);
        if (strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1) != "-") { // maximum: 9223372036854775807
            if (strLength < INT_64_LENGTH) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            int maxSubValue = std::stoi(strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1));
            if (strLength == INT_64_LENGTH && maxSubValue < BASE_NUMBER) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            // Means 0x7FFFFFFFFFFFFFFF remove the first number:(2^63 - 1 - 9 * 10 ^ 19)
            int subValue = std::stoll(strInfo.substr(ZERO_VALUE + 1, INT_64_LENGTH - 1));
            if (strLength == INT_64_LENGTH && subValue <= INT64_MAX - BASE_NUMBER *
                pow(DECIMAL_VALUE, INT_64_LENGTH - 1)) {
                int64Value = std::stoll(strInfo);
                return true;
            }
        }
        if (strLength < INT_64_LENGTH + 1) { // The minimum value: -9223372036854775808
            int64Value = std::stoll(strInfo);
            return true;
        }
        if (strLength == INT_64_LENGTH + 1) {
            int minSubValue = std::stoi(strInfo.substr(1, 1));
            if (minSubValue < BASE_NUMBER) {
                int64Value = std::stoll(strInfo);
                return true;
            }

            // Means 0x8000000000000000 remove the first number:-(2^63 - 9 * 10 ^ 19)
            if (std::stoll(strInfo.substr(ZERO_VALUE + 2, INT_64_LENGTH - 1)) <=
                (INT64_MAX - BASE_NUMBER * pow(DECIMAL_VALUE, INT_64_LENGTH) + 1)) {
                int64Value = std::stoll(strInfo);
                return true;
            }
        }
    }
    HILOG_DEBUG("%{public}s, regex_match failed.", __func__);
    return false;
}

/**
 * @brief Create return message(callback)
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] code result code
 * @param[out] result result message
 *
 * @return void
 */
void InnerCreateCallbackRetMsg(napi_env env, int32_t code, napi_value (&result)[CALLBACK_RETURN_MSG_SIZE])
{
    HILOG_DEBUG("%{public}s called. code:%{public}d", __func__, code);
    napi_value error = nullptr;
    napi_create_object(env, &error);

    auto retCode = QueryRetCode(code);
    auto retMsg = QueryRetMsg(retCode);

    // create error code
    napi_value errCode = nullptr;
    napi_create_int32(env, retCode, &errCode);
    napi_set_named_property(env, error, "code", errCode);

    // create error message
    napi_value errMsg = nullptr;
    napi_create_string_utf8(env, retMsg.c_str(), NAPI_AUTO_LENGTH, &errMsg);
    napi_set_named_property(env, error, "message", errMsg);

    result[0] = error;
    napi_get_undefined(env, &result[1]);
    HILOG_DEBUG("%{public}s, end.", __func__);
}

/**
 * @brief Create return message(promise)
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] code result code
 * @param[out] result result message
 *
 * @return void
 */
void InnerCreatePromiseRetMsg(napi_env env, int32_t code, napi_value* result)
{
    HILOG_DEBUG("%{public}s called. code:%{public}d", __func__, code);
    if (code == ERR_OK) {
        napi_get_undefined(env, result);
        return;
    }
    napi_value errInfo = nullptr;
    napi_create_object(env, &errInfo);

    auto retCode = QueryRetCode(code);
    auto retMsg = QueryRetMsg(retCode);

    // create error code
    napi_value errCode = nullptr;
    napi_create_int32(env, retCode, &errCode);
    napi_set_named_property(env, errInfo, "code", errCode);

    // create error message
    napi_value errMsg = nullptr;
    napi_create_string_utf8(env, retMsg.c_str(), NAPI_AUTO_LENGTH, &errMsg);
    napi_set_named_property(env, errInfo, "message", errMsg);

    *result = errInfo;
    HILOG_DEBUG("%{public}s, end.", __func__);
}

napi_value RetErrMsgForCallback(AsyncErrMsgCallbackInfo* asyncCallbackInfo)
{
    HILOG_INFO("called.");

    napi_env env = asyncCallbackInfo->env;
    napi_value value = asyncCallbackInfo->callbackValue;

    // Check the value type of the arguments
    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, value, &valueType));
    NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of deleteForm is incorrect,\
        expected type is function.");

    napi_create_reference(env, value, REF_COUNT, &asyncCallbackInfo->callback);

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {},
        [](napi_env env, napi_status status, void *data) {
            AsyncErrMsgCallbackInfo *asyncCallbackInfo = (AsyncErrMsgCallbackInfo *)data;
            HILOG_INFO("napi_create_async_work complete");
            if (asyncCallbackInfo->callback != nullptr) {
                napi_value callback;
                napi_value undefined;
                napi_value result[ARGS_SIZE_TWO] = {0};
                InnerCreateCallbackRetMsg(env, asyncCallbackInfo->code, result);
                napi_get_undefined(env, &undefined);
                napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                napi_value callResult;
                napi_call_function(env, undefined, callback, ARGS_SIZE_TWO, result, &callResult);
                napi_delete_reference(env, asyncCallbackInfo->callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default));
    return NapiGetResult(env, 1);
}

napi_value RetErrMsgForPromise(AsyncErrMsgCallbackInfo* asyncCallbackInfo)
{
    HILOG_INFO("called.");

    napi_env env = asyncCallbackInfo->env;
    napi_deferred deferred;
    napi_value promise;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {},
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("promise complete");
            AsyncErrMsgCallbackInfo *asyncCallbackInfo = (AsyncErrMsgCallbackInfo *)data;
            napi_value result;
            InnerCreatePromiseRetMsg(env, asyncCallbackInfo->code, &result);
            napi_reject_deferred(env, asyncCallbackInfo->deferred, result);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work_with_qos(env, asyncCallbackInfo->asyncWork, napi_qos_default);
    return promise;
}

/**
 * @brief Send error message.
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] asyncCallbackInfo Reference, callback info via Node-API
 * @param[out] result result message
 *
 * @return void
 */
napi_value RetErrMsg(AsyncErrMsgCallbackInfo* asyncCallbackInfo)
{
    HILOG_INFO("called.");
    if (asyncCallbackInfo == nullptr) {
        HILOG_ERROR("asyncCallback == nullptr");
        return nullptr;
    }
    if (asyncCallbackInfo->type == CALLBACK_FLG) {
        return RetErrMsgForCallback(asyncCallbackInfo);
    }
    return RetErrMsgForPromise(asyncCallbackInfo);
}

AsyncErrMsgCallbackInfo *InitErrMsg(napi_env env, int32_t code, int32_t type, napi_value callbackValue)
{
    auto *asyncErrorInfo = new (std::nothrow) AsyncErrMsgCallbackInfo {
        .env = env,
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .callbackValue = callbackValue,
        .code = code,
        .type = type
    };
    return asyncErrorInfo;
}

void SetFormInfoPropertyString(napi_env env, const char *inValue, napi_value &result, const char *outName)
{
    napi_value temp;
    napi_create_string_utf8(env, inValue, NAPI_AUTO_LENGTH, &temp);
    HILOG_DEBUG("%{public}s, %{public}s=%{public}s.", __func__, outName, inValue);
    napi_set_named_property(env, result, outName, temp);
}

void SetFormInfoPropertyInt32(napi_env env, int32_t inValue, napi_value &result, const char *outName)
{
    napi_value temp;
    napi_create_int32(env, inValue, &temp);
    HILOG_DEBUG("%{public}s, %{public}s=%{public}d.", __func__, outName, inValue);
    napi_set_named_property(env, result, outName, temp);
}

void SetFormInfoPropertyBoolean(napi_env env, bool inValue, napi_value &result, const char *outName)
{
    napi_value temp;
    napi_get_boolean(env, inValue, &temp);
    HILOG_DEBUG("%{public}s, %{public}s=%{public}d.", __func__, outName, inValue);
    napi_set_named_property(env, result, outName, temp);
}

/**
 * @brief Parse form info into Node-API
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] formInfo it is used for return forminfo to JavaScript
 * @param[out] result This is an opaque pointer that is used to represent a JavaScript value
 *
 * @return void
 */
void ParseFormInfoIntoNapi(napi_env env, const FormInfo &formInfo, napi_value &result)
{
    SetFormInfoPropertyString(env, formInfo.bundleName.c_str(), result, "bundleName");
    SetFormInfoPropertyString(env, formInfo.moduleName.c_str(), result, "moduleName");
    SetFormInfoPropertyString(env, formInfo.abilityName.c_str(), result, "abilityName");
    SetFormInfoPropertyString(env, formInfo.name.c_str(), result, "name");
    SetFormInfoPropertyString(env, formInfo.displayName.c_str(), result, "displayName");
    SetFormInfoPropertyInt32(env, formInfo.displayNameId, result, "displayNameId");
    SetFormInfoPropertyString(env, formInfo.description.c_str(), result, "description");
    SetFormInfoPropertyInt32(env, formInfo.descriptionId, result, "descriptionId");
    FormType formType = formInfo.type;
    SetFormInfoPropertyInt32(env, (int32_t)formType, result, "type");
    SetFormInfoPropertyString(env, formInfo.jsComponentName.c_str(), result, "jsComponentName");
    FormsColorMode formsColorMode = formInfo.colorMode;
    SetFormInfoPropertyInt32(env, (int32_t)formsColorMode, result, "colorMode");
    SetFormInfoPropertyBoolean(env, formInfo.defaultFlag, result, "isDefault");
    SetFormInfoPropertyBoolean(env, formInfo.updateEnabled, result, "updateEnabled");
    SetFormInfoPropertyBoolean(env, formInfo.formVisibleNotify, result, "formVisibleNotify");
    SetFormInfoPropertyString(env, formInfo.formConfigAbility.c_str(), result, "formConfigAbility");
    SetFormInfoPropertyInt32(env, formInfo.updateDuration, result, "updateDuration");
    SetFormInfoPropertyString(env, formInfo.scheduledUpdateTime.c_str(), result, "scheduledUpdateTime");
    SetFormInfoPropertyInt32(env, formInfo.defaultDimension, result, "defaultDimension");
    SetFormInfoPropertyString(env, formInfo.relatedBundleName.c_str(), result, "relatedBundleName");

    // supportDimensions
    napi_value supportDimensions;
    napi_create_array(env, &supportDimensions);
    int32_t iDimensionsCount = 0;
    for (auto dimension : formInfo.supportDimensions) {
        HILOG_DEBUG("%{public}s, dimension=%{public}d.", __func__, dimension);
        napi_value dimensionInfo;
        napi_create_int32(env, (int32_t)dimension, &dimensionInfo);
        napi_set_element(env, supportDimensions, iDimensionsCount, dimensionInfo);
        ++iDimensionsCount;
    }
    HILOG_DEBUG("%{public}s, supportDimensions size=%{public}zu.", __func__, formInfo.supportDimensions.size());
    napi_set_named_property(env, result, "supportDimensions", supportDimensions);

    // customizeData
    napi_value customizeData;
    napi_create_object(env, &customizeData);
    for (const auto& data : formInfo.customizeDatas) {
        SetFormInfoPropertyString(env, data.value.c_str(), customizeData, data.name.c_str());
    }
    HILOG_DEBUG("%{public}s, customizeData size=%{public}zu.", __func__, formInfo.customizeDatas.size());
    napi_set_named_property(env, result, "customizeData", customizeData);
}

void ParseRunningFormInfoIntoNapi(napi_env env, const RunningFormInfo &runningFormInfo, napi_value &result)
{
    std::string formIdString = std::to_string(runningFormInfo.formId);
    SetFormInfoPropertyString(env, formIdString.c_str(), result, "formId");
    SetFormInfoPropertyString(env, runningFormInfo.bundleName.c_str(), result, "bundleName");
    SetFormInfoPropertyString(env, runningFormInfo.hostBundleName.c_str(), result, "hostBundleName");
    FormVisibilityType formVisiblity = runningFormInfo.formVisiblity;
    SetFormInfoPropertyInt32(env, (int32_t)formVisiblity, result, "visibilityType");
    SetFormInfoPropertyString(env, runningFormInfo.moduleName.c_str(), result, "moduleName");
    SetFormInfoPropertyString(env, runningFormInfo.abilityName.c_str(), result, "abilityName");
    SetFormInfoPropertyString(env, runningFormInfo.formName.c_str(), result, "formName");
    SetFormInfoPropertyInt32(env, runningFormInfo.dimension, result, "dimension");
    FormUsageState formUsageState = runningFormInfo.formUsageState;
    SetFormInfoPropertyInt32(env, (int32_t)formUsageState, result, "formUsageState");
    SetFormInfoPropertyString(env, runningFormInfo.description.c_str(), result, "formDescription");
    SetFormInfoPropertyInt32(env, (int32_t)runningFormInfo.formLocation, result, "formLocation");
}

inline FormType GetFormType(const FormInfo &formInfo)
{
    if (formInfo.uiSyntax == FormType::ETS) {
        return FormType::ETS;
    }
    return formInfo.type;
}

napi_value CreateFormInfos(napi_env env, const std::vector<FormInfo> &formInfos)
{
    napi_value arrayValue = nullptr;
    napi_create_array_with_length(env, formInfos.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto &formInfo : formInfos) {
        napi_set_element(env, arrayValue, index++, CreateFormInfo(env, formInfo));
    }
    return arrayValue;
}

napi_value CreateFormInfo(napi_env env, const FormInfo &formInfo)
{
    HILOG_DEBUG("called");

    napi_value objContext = nullptr;
    napi_create_object(env, &objContext);

    napi_set_named_property(env, objContext, "bundleName", CreateJsValue(env, formInfo.bundleName));
    napi_set_named_property(env, objContext, "moduleName", CreateJsValue(env, formInfo.moduleName));
    napi_set_named_property(env, objContext, "abilityName", CreateJsValue(env, formInfo.abilityName));
    napi_set_named_property(env, objContext, "name", CreateJsValue(env, formInfo.name));
    napi_set_named_property(env, objContext, "displayName", CreateJsValue(env, formInfo.displayName));
    napi_set_named_property(env, objContext, "displayNameId", CreateJsValue(env, formInfo.displayNameId));
    napi_set_named_property(env, objContext, "description", CreateJsValue(env, formInfo.description));
    napi_set_named_property(env, objContext, "descriptionId", CreateJsValue(env, formInfo.descriptionId));
    napi_set_named_property(env, objContext, "type", CreateJsValue(env, GetFormType(formInfo)));
    napi_set_named_property(env, objContext, "jsComponentName", CreateJsValue(env, formInfo.jsComponentName));
    napi_set_named_property(env, objContext, "colorMode", CreateJsValue(env, formInfo.colorMode));
    napi_set_named_property(env, objContext, "isDefault", CreateJsValue(env, formInfo.defaultFlag));
    napi_set_named_property(env, objContext, "updateEnabled", CreateJsValue(env, formInfo.updateEnabled));
    napi_set_named_property(env, objContext, "formVisibleNotify", CreateJsValue(env, formInfo.formVisibleNotify));
    napi_set_named_property(env, objContext, "formConfigAbility", CreateJsValue(env, formInfo.formConfigAbility));
    napi_set_named_property(env, objContext, "updateDuration", CreateJsValue(env, formInfo.updateDuration));
    napi_set_named_property(env, objContext, "scheduledUpdateTime", CreateJsValue(env, formInfo.scheduledUpdateTime));
    napi_set_named_property(env, objContext, "defaultDimension", CreateJsValue(env, formInfo.defaultDimension));
    napi_set_named_property(env, objContext, "relatedBundleName", CreateJsValue(env, formInfo.relatedBundleName));
    napi_set_named_property(env, objContext, "supportDimensions", CreateNativeArray(env, formInfo.supportDimensions));
    napi_set_named_property(env, objContext, "customizeData", CreateFormCustomizeDatas(env, formInfo.customizeDatas));
    napi_set_named_property(env, objContext, "isDynamic", CreateJsValue(env, formInfo.isDynamic));
    napi_set_named_property(env, objContext, "transparencyEnabled", CreateJsValue(env, formInfo.transparencyEnabled));
    napi_set_named_property(env, objContext, "fontScaleFollowSystem",
        CreateJsValue(env, formInfo.fontScaleFollowSystem));
    napi_set_named_property(env, objContext, "supportShapes", CreateNativeArray(env, formInfo.supportShapes));

    return objContext;
}

napi_value CreateRunningFormInfos(napi_env env, const std::vector<RunningFormInfo> &runningFormInfos)
{
    napi_value arrayValue = nullptr;
    napi_create_array_with_length(env, runningFormInfos.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto &runningFormInfo : runningFormInfos) {
        napi_set_element(env, arrayValue, index++, CreateRunningFormInfo(env, runningFormInfo));
    }
    return arrayValue;
}

napi_value CreateRunningFormInfo(napi_env env, const RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("called");

    napi_value objContext = nullptr;
    napi_create_object(env, &objContext);

    std::string formStr = std::to_string(runningFormInfo.formId);
    napi_set_named_property(env, objContext, "formId", CreateJsValue(env, formStr));
    napi_set_named_property(env, objContext, "bundleName", CreateJsValue(env, runningFormInfo.bundleName));
    napi_set_named_property(env, objContext, "hostBundleName", CreateJsValue(env, runningFormInfo.hostBundleName));
    napi_set_named_property(env, objContext, "visibilityType", CreateJsValue(env, runningFormInfo.formVisiblity));
    napi_set_named_property(env, objContext, "moduleName", CreateJsValue(env, runningFormInfo.moduleName));
    napi_set_named_property(env, objContext, "abilityName", CreateJsValue(env, runningFormInfo.abilityName));
    napi_set_named_property(env, objContext, "formName", CreateJsValue(env, runningFormInfo.formName));
    napi_set_named_property(env, objContext, "dimension", CreateJsValue(env, runningFormInfo.dimension));
    napi_set_named_property(env, objContext, "formUsageState", CreateJsValue(env, runningFormInfo.formUsageState));
    napi_set_named_property(env, objContext, "formDescription", CreateJsValue(env, runningFormInfo.description));
    napi_set_named_property(env, objContext, "formLocation", CreateJsValue(env, (int32_t)runningFormInfo.formLocation));

    return objContext;
}

napi_value CreateFormCustomizeDatas(napi_env env, const std::vector<FormCustomizeData> &customizeDatas)
{
    napi_value objContext = nullptr;
    napi_create_object(env, &objContext);

    for (const auto& data : customizeDatas) {
        napi_set_named_property(env, objContext, data.name.c_str(), CreateJsValue(env, data.value));
    }

    return objContext;
}

bool ParseParam(napi_env env, napi_value args, FormInstancesFilter &filter)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        HILOG_ERROR("args not object type");
        return false;
    }
    napi_value prop = nullptr;
    napi_get_named_property(env, args, "bundleName", &prop);
    napi_typeof(env, prop, &valueType);
    if (valueType != napi_string) {
        HILOG_ERROR("The input bundleName is not a string.");
        return false;
    }
    filter.bundleName = GetStringFromNapi(env, prop);
    if (filter.bundleName.empty()) {
        HILOG_ERROR("The input bundleName is empty");
        return false;
    }
    prop = nullptr;
    napi_get_named_property(env, args, "formName", &prop);
    filter.formName = GetStringFromNapi(env, prop);
    prop = nullptr;
    napi_get_named_property(env, args, "moduleName", &prop);
    filter.moduleName = GetStringFromNapi(env, prop);
    prop = nullptr;
    napi_get_named_property(env, args, "abilityName", &prop);
    filter.abilityName = GetStringFromNapi(env, prop);
    bool hasIsUnusedIncluded = false;
    napi_has_named_property(env, args, "isUnusedIncluded", &hasIsUnusedIncluded);
    if (hasIsUnusedIncluded) {
        prop = nullptr;
        napi_get_named_property(env, args, "isUnusedIncluded", &prop);
        if (napi_get_value_bool(env, prop, &filter.isUnusedIncluded) != napi_ok) {
            return false;
        }
    }
    return true;
}

std::string GetStringFromNapi(napi_env env, napi_value value)
{
    std::string result;
    size_t size = 0;

    if (napi_get_value_string_utf8(env, value, nullptr, 0, &size) != napi_ok) {
        HILOG_ERROR("can not get string size");
        return "";
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + 1), &size) != napi_ok) {
        HILOG_ERROR("can not get string value");
        return "";
    }
    return result;
}

napi_value CreateFormInstances(napi_env env, const std::vector<FormInstance> &formInstances)
{
    napi_value arrayValue = nullptr;
    napi_create_array_with_length(env, formInstances.size(), &arrayValue);
    uint32_t index = 0;
    for (const auto &formInstance : formInstances) {
        napi_set_element(env, arrayValue, index++, CreateFormInstance(env, formInstance));
    }
    return arrayValue;
}

napi_value CreateFormInstance(napi_env env, const FormInstance &formInstance)
{
    HILOG_DEBUG("called");

    napi_value objContext = nullptr;
    napi_create_object(env, &objContext);

    std::string formStr = std::to_string(formInstance.formId);
    napi_set_named_property(env, objContext, "formId", CreateJsValue(env, formStr));
    napi_set_named_property(env, objContext, "hostBundleName", CreateJsValue(env, formInstance.formHostName));
    napi_set_named_property(env, objContext, "visibilityType", CreateJsValue(env, formInstance.formVisiblity));
    napi_set_named_property(env, objContext, "dimension", CreateJsValue(env, formInstance.specification));
    napi_set_named_property(env, objContext, "bundleName", CreateJsValue(env, formInstance.bundleName));
    napi_set_named_property(env, objContext, "moduleName", CreateJsValue(env, formInstance.moduleName));
    napi_set_named_property(env, objContext, "abilityName", CreateJsValue(env, formInstance.abilityName));
    napi_set_named_property(env, objContext, "formName", CreateJsValue(env, formInstance.formName));
    napi_set_named_property(env, objContext, "formUsageState", CreateJsValue(env, formInstance.formUsageState));
    napi_set_named_property(env, objContext, "formDescription", CreateJsValue(env, formInstance.description));
    return objContext;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
