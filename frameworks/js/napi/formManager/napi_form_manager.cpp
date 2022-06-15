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

#include "napi_form_manager.h"

#include <cinttypes>
#include <regex>
#include <uv.h>
#include <vector>

#include "form_mgr_errors.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "runtime.h"

using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace {
    constexpr size_t ARGS_SIZE_ZERO = 0;
    constexpr size_t ARGS_SIZE_ONE = 1;
    constexpr size_t ARGS_SIZE_TWO = 2;
    constexpr size_t ARGS_SIZE_THREE = 3;
    constexpr int INT_64_LENGTH = 19;
    constexpr int ZERO_VALUE = 0;
    constexpr int64_t INT_64_MAX_VALUE = 0x7FFFFFFFFFFFFFFF;
    constexpr int DECIMAL_VALUE = 10;
    constexpr int BASE_NUMBER = 9;
    constexpr int REF_COUNT = 1;
    constexpr int CALLBACK_FLG = 1;
    constexpr int PROMISE_FLG = 2;
    OHOS::AppExecFwk::Ability* g_ability = nullptr;
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
 * @brief GetGlobalAbility
 *
 * @param[in] env The environment that the Node-API call is invoked under
 *
 * @return OHOS::AppExecFwk::Ability*
 */
OHOS::AppExecFwk::Ability* GetGlobalAbility(napi_env env)
{
    // get global value
    napi_value global = nullptr;
    napi_get_global(env, &global);

    // get ability
    napi_value abilityObj = nullptr;
    napi_get_named_property(env, global, "ability", &abilityObj);

    // get ability pointer
    OHOS::AppExecFwk::Ability* ability = nullptr;
    napi_get_value_external(env, abilityObj, (void**)&ability);
    HILOG_INFO("%{public}s, ability", __func__);
    if (ability == nullptr) {
        if (g_ability == nullptr) {
            std::unique_ptr<AbilityRuntime::Runtime> runtime;
            g_ability = OHOS::AppExecFwk::Ability::Create(runtime);
        }
        ability = g_ability;
        HILOG_INFO("%{public}s, Use Local tmp Ability for Stage Module", __func__);
    }
    return ability;
}

/**
 * @brief Convert string to int64_t
 *
 * @param[in] strInfo The string information
 * @param[out] int64Value Convert string to int64_t
 *
 * @return Return the convert result
 */
static bool ConvertStringToInt64(const std::string &strInfo, int64_t &int64Value)
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
            if (strLength == INT_64_LENGTH && subValue <= INT_64_MAX_VALUE - BASE_NUMBER *
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
                (INT_64_MAX_VALUE - BASE_NUMBER * pow(DECIMAL_VALUE, INT_64_LENGTH) + 1)) {
                int64Value = std::stoll(strInfo);
                return true;
            }
        }
    }
    HILOG_DEBUG("%{public}s, regex_match failed.", __func__);
    return false;
}

/**
 * @brief Get a C++ string value from Node-API
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] value This is an opaque pointer that is used to represent a JavaScript value
 *
 * @return Return a C++ string
 */
static std::string GetStringFromNAPI(napi_env env, napi_value value)
{
    std::string result;
    size_t size = 0;

    if (napi_get_value_string_utf8(env, value, nullptr, 0, &size) != napi_ok) {
        HILOG_ERROR("%{public}s, can not get string size", __func__);
        return "";
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + 1), &size) != napi_ok) {
        HILOG_ERROR("%{public}s, can not get string value", __func__);
        return "";
    }
    return result;
}

/**
 * @brief Create return message
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] code result code
 * @param[out] result result message
 *
 * @return void
 */
void InnerCreateRetMsg(napi_env env, int32_t code, napi_value* result)
{
    HILOG_DEBUG("%{public}s called. code:%{public}d", __func__, code);
    if (code == ERR_OK) {
        napi_create_int32(env, ERR_OK, result);
        return;
    }

    OHOS::AppExecFwk::Ability* ability = GetGlobalAbility(env);
    std::string msg = ability->GetErrorMsg(code);
    HILOG_DEBUG("message: %{public}s", msg.c_str());
    napi_value errInfo = nullptr;
    napi_value errCode = nullptr;
    napi_value errMsg = nullptr;

    napi_create_object(env, &errInfo);
    napi_create_int32(env, code, &errCode);
    napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errMsg);
    napi_set_named_property(env, errInfo, "code", errCode);
    napi_set_named_property(env, errInfo, "data", errMsg);
    result[0] = errInfo;
    HILOG_DEBUG("%{public}s, end.", __func__);
}

/**
 * @brief Send error message.
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[in] value Use create callback
 * @param[in] code Result code
 * @param[in] type Callback or promise type
 * @param[out] result result message
 *
 * @return void
 */
napi_value RetErrMsg(AsyncErrMsgCallbackInfo* asyncCallbackInfo)
{
    HILOG_INFO("%{public}s called.", __func__);
    napi_env env = asyncCallbackInfo->env;
    napi_value value = asyncCallbackInfo->callbackValue;

    if (asyncCallbackInfo->type == CALLBACK_FLG) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

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
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value callback;
                    napi_value undefined;
                    napi_value result;
                    InnerCreateRetMsg(env, asyncCallbackInfo->code, &result);
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
                HILOG_INFO("%{public}s, promise complete", __func__);
                AsyncErrMsgCallbackInfo *asyncCallbackInfo = (AsyncErrMsgCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->code, &result);
                napi_resolve_deferred(env, asyncCallbackInfo->deferred, result);
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
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
static void ParseFormInfoIntoNapi(napi_env env, const FormInfo &formInfo, napi_value &result)
{
    // bundleName
    napi_value bundleName;
    napi_create_string_utf8(env, formInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &bundleName);
    HILOG_DEBUG("%{public}s, bundleName=%{public}s.", __func__, formInfo.bundleName.c_str());
    napi_set_named_property(env, result, "bundleName", bundleName);

    // moduleName
    napi_value moduleName;
    napi_create_string_utf8(env, formInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &moduleName);
    HILOG_DEBUG("%{public}s, moduleName=%{public}s.", __func__, formInfo.moduleName.c_str());
    napi_set_named_property(env, result, "moduleName", moduleName);

    // abilityName
    napi_value abilityName;
    napi_create_string_utf8(env, formInfo.abilityName.c_str(), NAPI_AUTO_LENGTH, &abilityName);
    HILOG_DEBUG("%{public}s, abilityName=%{public}s.", __func__, formInfo.abilityName.c_str());
    napi_set_named_property(env, result, "abilityName", abilityName);

    // name
    napi_value name;
    napi_create_string_utf8(env, formInfo.name.c_str(), NAPI_AUTO_LENGTH, &name);
    HILOG_DEBUG("%{public}s, name=%{public}s.", __func__, formInfo.name.c_str());
    napi_set_named_property(env, result, "name", name);

    // description
    napi_value description;
    napi_create_string_utf8(env, formInfo.description.c_str(), NAPI_AUTO_LENGTH, &description);
    HILOG_DEBUG("%{public}s, description=%{public}s.", __func__, formInfo.description.c_str());
    napi_set_named_property(env, result, "description", description);

    // descriptionId
    napi_value descriptionId;
    napi_create_int32(env, formInfo.descriptionId, &descriptionId);
    HILOG_DEBUG("%{public}s, descriptionId=%{public}d.", __func__, formInfo.descriptionId);
    napi_set_named_property(env, result, "descriptionId", descriptionId);

    // type
    napi_value type;
    FormType formType = formInfo.type;
    napi_create_int32(env, (int32_t)formType, &type);
    HILOG_DEBUG("%{public}s, formInfo_type=%{public}d.", __func__, (int32_t)formType);
    napi_set_named_property(env, result, "type", type);

    // jsComponentName
    napi_value jsComponentName;
    napi_create_string_utf8(env, formInfo.jsComponentName.c_str(), NAPI_AUTO_LENGTH, &jsComponentName);
    HILOG_DEBUG("%{public}s, jsComponentName=%{public}s.", __func__, formInfo.jsComponentName.c_str());
    napi_set_named_property(env, result, "jsComponentName", jsComponentName);

    // colorMode
    napi_value colorMode;
    FormsColorMode  formsColorMode = formInfo.colorMode;
    napi_create_int32(env, (int32_t)formsColorMode, &colorMode);
    HILOG_DEBUG("%{public}s, formInfo_type=%{public}d.", __func__, (int32_t)formsColorMode);
    napi_set_named_property(env, result, "colorMode", colorMode);

    // defaultFlag
    napi_value defaultFlag;
    napi_create_int32(env, (int32_t)formInfo.defaultFlag, &defaultFlag);
    HILOG_DEBUG("%{public}s, defaultFlag=%{public}d.", __func__, formInfo.defaultFlag);
    napi_set_named_property(env, result, "isDefault", defaultFlag);

    // updateEnabled
    napi_value updateEnabled;
    napi_create_int32(env, (int32_t)formInfo.updateEnabled, &updateEnabled);
    HILOG_DEBUG("%{public}s, updateEnabled=%{public}d.", __func__, formInfo.updateEnabled);
    napi_set_named_property(env, result, "updateEnabled", updateEnabled);

    // formVisibleNotify
    napi_value formVisibleNotify;
    napi_create_int32(env, (int32_t)formInfo.formVisibleNotify, &formVisibleNotify);
    HILOG_DEBUG("%{public}s, formVisibleNotify=%{public}d.", __func__, formInfo.formVisibleNotify);
    napi_set_named_property(env, result, "formVisibleNotify", formVisibleNotify);

    // formConfigAbility
    napi_value formConfigAbility;
    napi_create_string_utf8(env, formInfo.formConfigAbility.c_str(), NAPI_AUTO_LENGTH, &formConfigAbility);
    HILOG_DEBUG("%{public}s, formConfigAbility=%{public}s.", __func__, formInfo.formConfigAbility.c_str());
    napi_set_named_property(env, result, "formConfigAbility", formConfigAbility);

    // updateDuration
    napi_value updateDuration;
    napi_create_int32(env, formInfo.updateDuration, &updateDuration);
    HILOG_DEBUG("%{public}s, updateDuration=%{public}d.", __func__, formInfo.updateDuration);
    napi_set_named_property(env, result, "updateDuration", updateDuration);

    // scheduledUpdateTime
    napi_value scheduledUpdateTime;
    napi_create_string_utf8(env, formInfo.scheduledUpdateTime.c_str(), NAPI_AUTO_LENGTH, &scheduledUpdateTime);
    HILOG_DEBUG("%{public}s, scheduledUpdateTime=%{public}s.", __func__, formInfo.scheduledUpdateTime.c_str());
    napi_set_named_property(env, result, "scheduledUpdateTime", scheduledUpdateTime);

    // defaultDimension
    napi_value defaultDimension;
    napi_create_int32(env, formInfo.defaultDimension, &defaultDimension);
    HILOG_DEBUG("%{public}s, defaultDimension=%{public}d.", __func__, formInfo.defaultDimension);
    napi_set_named_property(env, result, "defaultDimension", defaultDimension);

    // supportDimensions
    napi_value supportDimensions;
    napi_create_array(env, &supportDimensions);
    int iDimensionsCount = 0;
    for (auto  dimension : formInfo.supportDimensions) {
        HILOG_DEBUG("%{public}s, dimension=%{public}d.", __func__, dimension);
        napi_value dimensionInfo;
        napi_create_int32(env, (int32_t)dimension, &dimensionInfo);
        napi_set_element(env, supportDimensions, iDimensionsCount, dimensionInfo);
        ++iDimensionsCount;
    }
    HILOG_DEBUG("%{public}s, supportDimensions size=%{public}zu.", __func__, formInfo.supportDimensions.size());
    napi_set_named_property(env, result, "supportDimensions", supportDimensions);

    // metaData
    napi_value metaData;
    napi_create_object(env, &metaData);

    // metaData: customizeDatas
    napi_value customizeDatas;
    napi_create_array(env, &customizeDatas);
    int iCustomizeDatasCount = 0;
    for (auto  customizeData : formInfo.customizeDatas) {
        napi_value customizeDataOnject = nullptr;
        napi_create_object(env, &customizeDataOnject);

        // customizeData : name
        napi_value customizeDataName;
        napi_create_string_utf8(env, customizeData.name.c_str(), NAPI_AUTO_LENGTH, &customizeDataName);
        HILOG_DEBUG("%{public}s, customizeData.name=%{public}s.", __func__, customizeData.name.c_str());
        napi_set_named_property(env, customizeDataOnject, "name", customizeDataName);

        // customizeData : value
        napi_value customizeDataValue;
        napi_create_string_utf8(env, customizeData.value.c_str(), NAPI_AUTO_LENGTH, &customizeDataValue);
        HILOG_DEBUG("%{public}s, customizeData.value=%{public}s.", __func__, customizeData.value.c_str());
        napi_set_named_property(env, customizeDataOnject, "value", customizeDataValue);

        napi_set_element(env, customizeDatas, iCustomizeDatasCount, customizeDataOnject);
        ++iDimensionsCount;
    }
    HILOG_DEBUG("%{public}s, customizeDatas size=%{public}zu.", __func__, formInfo.customizeDatas.size());
    napi_set_named_property(env, metaData, "customizeData", customizeDatas);
    napi_set_named_property(env, result, "metaData", metaData);

    return;
}

static std::string GetStringByProp(napi_env env, napi_value value, const std::string& prop)
{
    std::string result;
    bool propExist = false;
    napi_value propValue = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_has_named_property(env, value, prop.c_str(), &propExist);
    if (!propExist) {
        HILOG_ERROR("%{public}s, prop[%{public}s] not exist.", __func__, prop.c_str());
        return result;
    }
    napi_get_named_property(env, value, prop.c_str(), &propValue);
    if (propValue == nullptr) {
        HILOG_ERROR("%{public}s, prop[%{public}s] get failed.", __func__, prop.c_str());
        return result;
    }
    napi_typeof(env, propValue, &valueType);
    if (valueType != napi_string) {
        HILOG_ERROR("%{public}s, prop[%{public}s] is not napi_string.", __func__, prop.c_str());
        return result;
    }
    size_t size = 0;
    if (napi_get_value_string_utf8(env, propValue, nullptr, 0, &size) != napi_ok) {
        HILOG_ERROR("%{public}s, prop[%{public}s] get size failed.", __func__, prop.c_str());
        return result;
    }
    result.reserve(size + 1);
    result.resize(size);
    if (napi_get_value_string_utf8(env, propValue, result.data(), (size + 1), &size) != napi_ok) {
        HILOG_ERROR("%{public}s, prop[%{public}s] get value failed.", __func__, prop.c_str());
        return "";
    }
    return result;
}

static bool UnwrapRawImageDataMap(napi_env env, napi_value value, std::map<std::string, int>& rawImageDataMap)
{
    HILOG_INFO("%{public}s called.", __func__);
    bool propExist = false;
    napi_value param = nullptr;
    napi_valuetype valueType = napi_undefined;
    napi_has_named_property(env, value, "image", &propExist);
    if (!propExist) {
        HILOG_ERROR("%{public}s, prop[image] not exist.", __func__);
        return false;
    }
    napi_get_named_property(env, value, "image", &param);
    if (param == nullptr) {
        HILOG_ERROR("%{public}s, prop[image] get failed.", __func__);
        return false;
    }
    napi_typeof(env, param, &valueType);
    if (valueType != napi_object) {
        HILOG_ERROR("%{public}s, prop[image]] is not napi_object.", __func__);
        return false;
    }
    napi_valuetype jsValueType = napi_undefined;
    napi_value jsProNameList = nullptr;
    uint32_t jsProCount = 0;
    NAPI_CALL_BASE(env, napi_get_property_names(env, param, &jsProNameList), false);
    NAPI_CALL_BASE(env, napi_get_array_length(env, jsProNameList, &jsProCount), false);
    HILOG_INFO("%{public}s called. Property size=%{public}d.", __func__, jsProCount);
    napi_value jsProName = nullptr;
    napi_value jsProValue = nullptr;
    for (uint32_t index = 0; index < jsProCount; index++) {
        NAPI_CALL_BASE(env, napi_get_element(env, jsProNameList, index, &jsProName), false);
        std::string strProName = GetStringFromNAPI(env, jsProName);
        HILOG_INFO("%{public}s called. Property name=%{public}s.", __func__, strProName.c_str());
        NAPI_CALL_BASE(env, napi_get_named_property(env, param, strProName.c_str(), &jsProValue), false);
        NAPI_CALL_BASE(env, napi_typeof(env, jsProValue, &jsValueType), false);
        int natValue = 0;
        if (napi_get_value_int32(env, param, &natValue) != napi_ok) {
            HILOG_INFO("%{public}s Property:%{public}s get value failed.", __func__, strProName.c_str());
            continue;
        }
        rawImageDataMap.emplace(strProName, natValue);
        HILOG_INFO("%{public}s called. Property value=%{public}d.", __func__, natValue);
    }
    return true;
}

/**
 * @brief  Call native kit function: DeleteForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerDelForm(napi_env env, AsyncDelFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    ErrCode ret = ability->DeleteForm(asyncCallbackInfo->formId);
    asyncCallbackInfo->result = ret;
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: deleteForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_DeleteForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[0]);
    int64_t formId;
    HILOG_ERROR("%{public}s, form id ", strFormId.c_str());
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    AsyncDelFormCallbackInfo *asyncCallbackInfo = new
        AsyncDelFormCallbackInfo {
            .env = env,
            .ability = GetGlobalAbility(env),
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formId = 0,
            .result = 0,
        };
    asyncCallbackInfo->formId = formId;

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of deleteForm is incorrect,\
            expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
                AsyncDelFormCallbackInfo *asyncCallbackInfo = (AsyncDelFormCallbackInfo *)data;
                InnerDelForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncDelFormCallbackInfo *asyncCallbackInfo = (AsyncDelFormCallbackInfo *)data;
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result;
                    napi_create_int32(env, asyncCallbackInfo->result, &result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncDelFormCallbackInfo *asyncCallbackInfo = (AsyncDelFormCallbackInfo *)data;
                InnerDelForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);
                AsyncDelFormCallbackInfo *asyncCallbackInfo = (AsyncDelFormCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: ReleaseForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerReleaseForm(napi_env env, AsyncReleaseFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    ErrCode ret = ability->ReleaseForm(asyncCallbackInfo->formId, asyncCallbackInfo->isReleaseCache);
    asyncCallbackInfo->result = ret;
    HILOG_DEBUG("%{public}s end", __func__);
}

// NAPI_ReleaseForm InnerReleaseForm callback execute
napi_async_execute_callback NAPI_ReleaseFormAsyncExecute = [](napi_env env, void *data) {
    HILOG_INFO("NAPI_ReleaseForm InnerReleaseForm execute callback");
    AsyncReleaseFormCallbackInfo *asyncCallbackInfo =
    (AsyncReleaseFormCallbackInfo *)data;
    InnerReleaseForm(env, asyncCallbackInfo);
};

// NAPI_ReleaseForm callback complete
napi_async_complete_callback NAPI_ReleaseFormAsyncComplete = [](napi_env env, napi_status status, void *data) {
    HILOG_INFO("NAPI_ReleaseForm compeleted callback");
    AsyncReleaseFormCallbackInfo *asyncCallbackInfo =
    (AsyncReleaseFormCallbackInfo *)data;

    if (asyncCallbackInfo->callback != nullptr) {
        napi_value result;
        InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
        napi_value callback;
        napi_value undefined;
        napi_get_undefined(env, &undefined);
        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_value callResult;
        napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
};

// NAPI_ReleaseForm promise Complete
napi_async_complete_callback NAPI_ReleaseFormPromiseComplete = [](napi_env env, napi_status status, void *data) {
    HILOG_INFO("%{public}s, promise complete", __func__);
    AsyncReleaseFormCallbackInfo *asyncCallbackInfo = (AsyncReleaseFormCallbackInfo *)data;

    napi_value result;
    InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
    if (asyncCallbackInfo->result == ERR_OK) {
        napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
    } else {
        napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
};

// ReleaseForm callback
napi_value ReleaseFormCallback(napi_env env, AsyncReleaseFormCallbackInfo *asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);

    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        NAPI_ReleaseFormAsyncExecute,
        NAPI_ReleaseFormAsyncComplete,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

// ReleaseForm promise
napi_value ReleaseFormPromise(napi_env env, AsyncReleaseFormCallbackInfo *asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
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
        NAPI_ReleaseFormAsyncExecute,
        NAPI_ReleaseFormPromiseComplete,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: releaseForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_ReleaseForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < ARGS_SIZE_ONE || argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ZERO], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0,
                .callbackValue = argv[ARGS_SIZE_TWO]
            };

        if (argc == ARGS_SIZE_ONE) {
            asyncErrorInfo->type = PROMISE_FLG;
        } else if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
            asyncErrorInfo->callbackValue = argv[ARGS_SIZE_TWO];
        } else {
            valueType = napi_undefined;
            NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
            if (valueType == napi_function) {
                asyncErrorInfo->type = CALLBACK_FLG;
                asyncErrorInfo->callbackValue = argv[1];
            } else if (valueType == napi_boolean) {
                asyncErrorInfo->type = PROMISE_FLG;
            } else {
                NAPI_ASSERT(env, valueType == napi_function || valueType == napi_boolean,
                    "The arguments[2] type of releaseForm is incorrect,expected type is function or boolean.");
            }
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[ARGS_SIZE_ZERO]);
    int64_t formId;
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0,
                .callbackValue = argv[ARGS_SIZE_TWO]
            };

        if (argc == ARGS_SIZE_ONE) {
            asyncErrorInfo->type = PROMISE_FLG;
        } else if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
            asyncErrorInfo->callbackValue = argv[ARGS_SIZE_TWO];
        } else {
            valueType = napi_undefined;
            NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
            if (valueType == napi_function) {
                asyncErrorInfo->type = CALLBACK_FLG;
                asyncErrorInfo->callbackValue = argv[1];
            } else if (valueType == napi_boolean) {
                asyncErrorInfo->type = PROMISE_FLG;
            } else {
                NAPI_ASSERT(env, valueType == napi_function || valueType == napi_boolean,
                    "The arguments[2] type of releaseForm is incorrect,expected type is function or boolean.");
            }
        }
        return RetErrMsg(asyncErrorInfo);
    }

    AsyncReleaseFormCallbackInfo *asyncCallbackInfo = new
    AsyncReleaseFormCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formId = formId,
        .isReleaseCache = false,
        .result = 0,
    };

    if (argc == ARGS_SIZE_ONE) { // release promise, one argv
        return ReleaseFormPromise(env, asyncCallbackInfo);
    } else if (argc == ARGS_SIZE_THREE) { // release callback, three argv
        HILOG_INFO("%{public}s, asyncCallback.", __func__);
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_boolean, "The arguments[1] type of releaseForm is incorrect,\
            expected type is boolean.");

        napi_get_value_bool(env, argv[1], &asyncCallbackInfo->isReleaseCache);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[2] type of releaseForm is incorrect,\
            expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
        ReleaseFormCallback(env, asyncCallbackInfo);
    } else {
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        if (valueType == napi_function) { // release callback, two argv
            napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
            ReleaseFormCallback(env, asyncCallbackInfo);
        } else if (valueType == napi_boolean) { // release promise, two argv
            return ReleaseFormPromise(env, asyncCallbackInfo);
        } else {
            NAPI_ASSERT(env, valueType == napi_function || valueType == napi_boolean,
                "The arguments[2] type of releaseForm is incorrect,expected type is function or boolean.");
        }
    }
    return NapiGetResult(env, 1);
}

/**
 * @brief  Call native kit function: RequestForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerRequestForm(napi_env env, AsyncRequestFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->RequestForm(asyncCallbackInfo->formId);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: requestForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_RequestForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[0]);
    int64_t formId;
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    AsyncRequestFormCallbackInfo *asyncCallbackInfo = new
    AsyncRequestFormCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formId = formId,
        .result = 0,
    };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of requestForm is incorrect,\
        expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
                AsyncRequestFormCallbackInfo *asyncCallbackInfo = (AsyncRequestFormCallbackInfo *)data;
                InnerRequestForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncRequestFormCallbackInfo *asyncCallbackInfo = (AsyncRequestFormCallbackInfo *)data;
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result;
                    InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncRequestFormCallbackInfo *asyncCallbackInfo = (AsyncRequestFormCallbackInfo *)data;
                InnerRequestForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);
                AsyncRequestFormCallbackInfo *asyncCallbackInfo = (AsyncRequestFormCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: SetFormNextRefreshTime
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerSetFormNextRefreshTime(napi_env env, AsyncNextRefreshTimeFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->SetFormNextRefreshTime(asyncCallbackInfo->formId, asyncCallbackInfo->time);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: setFormNextRefreshTime
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_SetFormNextRefreshTime(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE || argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[0]);
    int64_t formId;
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
    if (valueType != napi_number) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_REFRESH_TIME_NUM_ERR,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    int32_t time;
    napi_get_value_int32(env, argv[1], &time);

    AsyncNextRefreshTimeFormCallbackInfo *asyncCallbackInfo = new
        AsyncNextRefreshTimeFormCallbackInfo {
            .env = env,
            .ability = GetGlobalAbility(env),
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formId = formId,
            .time = time,
            .result = 0,
        };

    if (argc == ARGS_SIZE_THREE) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[2] type of setFormNextRefreshTime is incorrect,\
        expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncNextRefreshTimeFormCallbackInfo *asyncCallbackInfo =
                (AsyncNextRefreshTimeFormCallbackInfo *)data;

                InnerSetFormNextRefreshTime(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncNextRefreshTimeFormCallbackInfo *asyncCallbackInfo =
                (AsyncNextRefreshTimeFormCallbackInfo *)data;

                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result;
                    InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncNextRefreshTimeFormCallbackInfo *asyncCallbackInfo =
                (AsyncNextRefreshTimeFormCallbackInfo *)data;

                InnerSetFormNextRefreshTime(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);
                AsyncNextRefreshTimeFormCallbackInfo *asyncCallbackInfo =
                (AsyncNextRefreshTimeFormCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: UpdateForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerUpdateForm(napi_env env, AsyncUpdateFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->UpdateForm(asyncCallbackInfo->formId, *asyncCallbackInfo->formProviderData);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: updateForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_UpdateForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE || argc < ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc size = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        HILOG_ERROR("%{public}s formId is not napi_string.", __func__);
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[0]);
    int64_t formId = 0;
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        HILOG_ERROR("%{public}s formId ConvertStringToInt64 failed.", __func__);
        return RetErrMsg(asyncErrorInfo);
    }

    NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
    if (valueType != napi_object) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_INVALID_PROVIDER_DATA,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_THREE) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        HILOG_ERROR("%{public}s formBindingData is not napi_object.", __func__);
        return RetErrMsg(asyncErrorInfo);
    }

    auto formProviderData = std::make_shared<OHOS::AppExecFwk::FormProviderData>();
    std::string formDataStr = GetStringByProp(env, argv[1], "data");
    HILOG_INFO("%{public}s %{public}s - %{public}s.", __func__, strFormId.c_str(), formDataStr.c_str());
    formProviderData->SetDataString(formDataStr);
    std::map<std::string, int> rawImageDataMap;
    UnwrapRawImageDataMap(env, argv[1], rawImageDataMap);
    HILOG_INFO("%{public}s Image number is %{public}zu", __func__, rawImageDataMap.size());
    for (const auto& entry : rawImageDataMap) {
        formProviderData->AddImageData(entry.first, entry.second);
    }

    AsyncUpdateFormCallbackInfo *asyncCallbackInfo = new
        AsyncUpdateFormCallbackInfo {
            .env = env,
            .ability = GetGlobalAbility(env),
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formId = formId,
            .formProviderData = formProviderData,
            .result = 0,
        };

    if (argc == ARGS_SIZE_THREE) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[2] type of updateForm is incorrect,\
        expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
                AsyncUpdateFormCallbackInfo *asyncCallbackInfo = (AsyncUpdateFormCallbackInfo *)data;
                InnerUpdateForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncUpdateFormCallbackInfo *asyncCallbackInfo = (AsyncUpdateFormCallbackInfo *)data;
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result;
                    InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncUpdateFormCallbackInfo *asyncCallbackInfo = (AsyncUpdateFormCallbackInfo *)data;
                InnerUpdateForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);
                AsyncUpdateFormCallbackInfo *asyncCallbackInfo = (AsyncUpdateFormCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: CastTempForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerCastTempForm(napi_env env, AsyncCastTempFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->CastTempForm(asyncCallbackInfo->formId);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: castTempForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_CastTempForm(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    if (valueType != napi_string) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    std::string strFormId = GetStringFromNAPI(env, argv[0]);
    int64_t formId;
    if (!ConvertStringToInt64(strFormId, formId)) {
        AsyncErrMsgCallbackInfo *asyncErrorInfo = new
            AsyncErrMsgCallbackInfo {
                .env = env,
                .asyncWork = nullptr,
                .deferred = nullptr,
                .callback = nullptr,
                .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                .type = 0,
                .callbackValue = argv[1]
            };

        if (argc == ARGS_SIZE_TWO) {
            asyncErrorInfo->type = CALLBACK_FLG;
        } else {
            asyncErrorInfo->type = PROMISE_FLG;
        }
        return RetErrMsg(asyncErrorInfo);
    }

    AsyncCastTempFormCallbackInfo *asyncCallbackInfo = new
    AsyncCastTempFormCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formId = formId,
        .result = 0,
    };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of castTempForm is incorrect,\
        expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
                AsyncCastTempFormCallbackInfo *asyncCallbackInfo = (AsyncCastTempFormCallbackInfo *)data;
                InnerCastTempForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncCastTempFormCallbackInfo *asyncCallbackInfo = (AsyncCastTempFormCallbackInfo *)data;
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result;
                    InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncCastTempFormCallbackInfo *asyncCallbackInfo = (AsyncCastTempFormCallbackInfo *)data;
                InnerCastTempForm(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);
                AsyncCastTempFormCallbackInfo *asyncCallbackInfo = (AsyncCastTempFormCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: NotifyVisibleForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerNotifyVisibleForms(napi_env env, AsyncNotifyVisibleFormsCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->NotifyVisibleForms(asyncCallbackInfo->formIds);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: notifyVisibleForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_NotifyVisibleForms(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &arrayLength));
    NAPI_ASSERT(env, arrayLength > 0, "The arguments[0] value of notifyVisibleForms is incorrect,\
        this array is empty.");

    std::vector<int64_t> formIds;
    formIds.clear();
    napi_valuetype valueType;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                    .type = 0,
                    .callbackValue = argv[1]
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                    .type = 0,
                    .callbackValue = argv[1]
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        formIds.push_back(formIdValue);
    }

    AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo = new
        AsyncNotifyVisibleFormsCallbackInfo {
            .env = env,
            .ability = GetGlobalAbility(env),
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formIds = formIds,
            .result = 1,
        };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of notifyVisibleForms is incorrect,\
        expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyVisibleFormsCallbackInfo *)data;

                InnerNotifyVisibleForms(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyVisibleFormsCallbackInfo *)data;

                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result;
                    InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);

                AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyVisibleFormsCallbackInfo *)data;

                InnerNotifyVisibleForms(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncNotifyVisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyVisibleFormsCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: NotifyInvisibleForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerNotifyInvisibleForms(napi_env env, AsyncNotifyInvisibleFormsCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->NotifyInvisibleForms(asyncCallbackInfo->formIds);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: notifyInvisibleForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_NotifyInvisibleForms(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &arrayLength));
    NAPI_ASSERT(env, arrayLength > 0, "The arguments[0] value of notifyInvisibleForms is incorrect,\
    this array is empty.");

    std::vector<int64_t> formIds;
    formIds.clear();
    napi_valuetype valueType;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                    .type = 0,
                    .callbackValue = argv[1]
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                    .type = 0,
                    .callbackValue = argv[1]
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        formIds.push_back(formIdValue);
    }

    AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo = new
        AsyncNotifyInvisibleFormsCallbackInfo {
            .env = env,
            .ability = GetGlobalAbility(env),
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formIds = formIds,
            .result = 1,
        };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of notifyInvisibleForms is incorrect,\
        expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyInvisibleFormsCallbackInfo *)data;

                InnerNotifyInvisibleForms(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyInvisibleFormsCallbackInfo *)data;

                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result;
                    InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);

                AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyInvisibleFormsCallbackInfo *)data;

                InnerNotifyInvisibleForms(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncNotifyInvisibleFormsCallbackInfo *asyncCallbackInfo =
                (AsyncNotifyInvisibleFormsCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: EnableUpdateForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerEnableFormsUpdate(napi_env env, AsyncEnableUpdateFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->EnableUpdateForm(asyncCallbackInfo->formIds);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: enableFormsUpdate
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_EnableFormsUpdate(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &arrayLength));
    NAPI_ASSERT(env, arrayLength > 0, "The arguments[0] value of enableFormsUpdate \
        is incorrect, this array is empty.");

    std::vector<int64_t> formIds;
    formIds.clear();
    napi_valuetype valueType;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                    .type = 0,
                    .callbackValue = argv[1]
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                    .type = 0,
                    .callbackValue = argv[1]
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        formIds.push_back(formIdValue);
    }

    AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo = new
    AsyncEnableUpdateFormCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formIds = formIds,
        .result = 0,
    };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of enableFormsUpdate \
            is incorrect, expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncEnableUpdateFormCallbackInfo *)data;

                InnerEnableFormsUpdate(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncEnableUpdateFormCallbackInfo *)data;

                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result;
                    InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);
                AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncEnableUpdateFormCallbackInfo *)data;

                InnerEnableFormsUpdate(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncEnableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncEnableUpdateFormCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: DisableUpdateForm
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerDisableFormsUpdate(napi_env env, AsyncDisableUpdateFormCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->DisableUpdateForm(asyncCallbackInfo->formIds);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: disableFormsUpdate
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_DisableFormsUpdate(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &arrayLength));
    NAPI_ASSERT(env, arrayLength > 0, "The arguments[0] value of disableFormsUpdate \
        is incorrect, this array is empty.");

    std::vector<int64_t> formIds;
    formIds.clear();
    napi_valuetype valueType;
    for (size_t i = 0; i < arrayLength; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        if (valueType != napi_string) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .code = ERR_APPEXECFWK_FORM_INVALID_FORM_ID,
                    .type = 0,
                    .callbackValue = argv[1]
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        if (!ConvertStringToInt64(strFormId, formIdValue)) {
            AsyncErrMsgCallbackInfo *asyncErrorInfo = new
                AsyncErrMsgCallbackInfo {
                    .env = env,
                    .asyncWork = nullptr,
                    .deferred = nullptr,
                    .callback = nullptr,
                    .code = ERR_APPEXECFWK_FORM_FORM_ID_NUM_ERR,
                    .type = 0,
                    .callbackValue = argv[1]
                };

            if (argc == ARGS_SIZE_TWO) {
                asyncErrorInfo->type = CALLBACK_FLG;
            } else {
                asyncErrorInfo->type = PROMISE_FLG;
            }
            return RetErrMsg(asyncErrorInfo);
        }

        formIds.push_back(formIdValue);
    }

    AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo = new
        AsyncDisableUpdateFormCallbackInfo {
            .env = env,
            .ability = GetGlobalAbility(env),
            .asyncWork = nullptr,
            .deferred = nullptr,
            .callback = nullptr,
            .formIds = formIds,
            .result = 0,
        };

    if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of disableFormsUpdate \
        is incorrect, expected type is function.");

        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);

        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncDisableUpdateFormCallbackInfo *)data;

                InnerDisableFormsUpdate(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncDisableUpdateFormCallbackInfo *)data;

                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value result;
                    InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                    napi_value callback;
                    napi_value undefined;
                    napi_get_undefined(env, &undefined);
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, undefined, callback, ARGS_SIZE_ONE, &result, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);

                AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncDisableUpdateFormCallbackInfo *)data;

                InnerDisableFormsUpdate(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncDisableUpdateFormCallbackInfo *asyncCallbackInfo =
                (AsyncDisableUpdateFormCallbackInfo *)data;

                napi_value result;
                InnerCreateRetMsg(env, asyncCallbackInfo->result, &result);
                if (asyncCallbackInfo->result == ERR_OK) {
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    napi_reject_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: CheckFMSReady
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerCheckFMSReady(napi_env env, AsyncCheckFMSReadyCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->isFMSReady = ability->CheckFMSReady();
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  The implementation of Node-API interface: checkFMSReady
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_CheckFMSReady(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_ONE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo = new
    AsyncCheckFMSReadyCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .isFMSReady = false,
    };

    if (argc == ARGS_SIZE_ONE) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        napi_valuetype valueType;
        NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[0] type of checkFMSReady is incorrect,\
        expected type is function.");

        napi_create_reference(env, argv[0], REF_COUNT, &asyncCallbackInfo->callback);
        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work running", __func__);

                AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo =
                (AsyncCheckFMSReadyCallbackInfo *)data;

                InnerCheckFMSReady(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);

                AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo =
                (AsyncCheckFMSReadyCallbackInfo *)data;

                if (asyncCallbackInfo->callback != nullptr) {
                    napi_value isFMSReadyResult;
                    napi_create_int32(env, asyncCallbackInfo->isFMSReady, &isFMSReadyResult);
                    napi_value callback;
                    napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                    napi_value callResult;
                    napi_call_function(env, nullptr, callback, ARGS_SIZE_ONE, &isFMSReadyResult, &callResult);
                    napi_delete_reference(env, asyncCallbackInfo->callback);
                }
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            [](napi_env env, void *data) {
                HILOG_INFO("%{public}s, promise running", __func__);

                AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo =
                (AsyncCheckFMSReadyCallbackInfo *)data;

                InnerCheckFMSReady(env, asyncCallbackInfo);
            },
            [](napi_env env, napi_status status, void *data) {
                HILOG_INFO("%{public}s, promise complete", __func__);

                AsyncCheckFMSReadyCallbackInfo *asyncCallbackInfo =
                (AsyncCheckFMSReadyCallbackInfo *)data;

                napi_value result;
                napi_create_int32(env, asyncCallbackInfo->isFMSReady, &result);
                napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
                delete asyncCallbackInfo;
            },
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

static void InnerDeleteInvalidForms(napi_env env, AsyncDeleteInvalidFormsCallbackInfo *const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    ErrCode ret = ability->DeleteInvalidForms(asyncCallbackInfo->formIds, asyncCallbackInfo->numFormsDeleted);
    asyncCallbackInfo->result = ret;
    if (ret != ERR_OK) {
        asyncCallbackInfo->numFormsDeleted = 0;
    }
    HILOG_DEBUG("%{public}s, end", __func__);
}

napi_value DeleteInvalidFormsCallback(napi_env env, AsyncDeleteInvalidFormsCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncDeleteInvalidFormsCallbackInfo *) data;
            InnerDeleteInvalidForms(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncDeleteInvalidFormsCallbackInfo *) data;

            if (asyncCallbackInfo->callback != nullptr) {
                napi_value callback;
                napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr};
                napi_create_int32(env, asyncCallbackInfo->result, &callbackValues[0]);
                napi_create_int32(env, asyncCallbackInfo->numFormsDeleted, &callbackValues[1]);

                napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                napi_value callResult;
                napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
                napi_delete_reference(env, asyncCallbackInfo->callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

napi_value DeleteInvalidFormsPromise(napi_env env, AsyncDeleteInvalidFormsCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
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
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncDeleteInvalidFormsCallbackInfo *) data;
            InnerDeleteInvalidForms(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncDeleteInvalidFormsCallbackInfo *) data;
            napi_value result;
            napi_create_int32(env, asyncCallbackInfo->numFormsDeleted, &result);
            napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: deleteInvalidForms
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_DeleteInvalidForms(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    uint32_t numForms = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &numForms));
    NAPI_ASSERT(env, numForms > 0, "The arguments[0] value of deleteInvalidForms is incorrect, this array is empty.");

    std::vector<int64_t> formIds {};
    napi_valuetype valueType;
    for (size_t i = 0; i < numForms; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        NAPI_ASSERT(env, valueType == napi_string, "The arguments[0] value type of deleteInvalidForms \
        is incorrect, expected type is string.");

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        bool isConversionSucceeded = ConvertStringToInt64(strFormId, formIdValue);
        NAPI_ASSERT(env, isConversionSucceeded, "The arguments[0] type of deleteInvalidForms is incorrect,\
        expected type is string and the content must be numeric,\
        value range is: 0x8000000000000000~0x7FFFFFFFFFFFFFFF.");
        formIds.push_back(formIdValue);
    }

    auto *asyncCallbackInfo = new AsyncDeleteInvalidFormsCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formIds = formIds,
        .numFormsDeleted = 0,
    };

    if (argc == ARGS_SIZE_TWO) {
        // Check the value type of the arguments
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of deleteInvalidForms \
        is incorrect, expected type is function.");
        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
        return DeleteInvalidFormsCallback(env, asyncCallbackInfo);
    } else {
        return DeleteInvalidFormsPromise(env, asyncCallbackInfo);
    }
}

static void InnerAcquireFormState(napi_env env, AsyncAcquireFormStateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    ErrCode ret = ability->AcquireFormState(asyncCallbackInfo->want, asyncCallbackInfo->stateInfo);
    asyncCallbackInfo->result = ret;
    HILOG_DEBUG("%{public}s, end", __func__);
}

napi_value ParseFormStateInfo(napi_env env, FormStateInfo &stateInfo)
{
    napi_value formStateInfoObject = nullptr;
    napi_create_object(env, &formStateInfoObject);
    napi_value jsValue = WrapWant(env, stateInfo.want);
    SetPropertyValueByPropertyName(env, formStateInfoObject, "want", jsValue);
    napi_value formState = nullptr;
    napi_create_int32(env, (int32_t) stateInfo.state, &formState);
    SetPropertyValueByPropertyName(env, formStateInfoObject, "formState", formState);

    return formStateInfoObject;
}

napi_value AcquireFormStateCallback(napi_env env, AsyncAcquireFormStateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncAcquireFormStateCallbackInfo *) data;
            InnerAcquireFormState(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncAcquireFormStateCallbackInfo *) data;
            if (asyncCallbackInfo->callback != nullptr) {
                napi_value callback;
                napi_value callbackValues[ARGS_SIZE_TWO] = {nullptr};
                napi_create_int32(env, asyncCallbackInfo->result, &callbackValues[0]);
                callbackValues[1] = ParseFormStateInfo(env, asyncCallbackInfo->stateInfo);

                napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                napi_value callResult;
                napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
                napi_delete_reference(env, asyncCallbackInfo->callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

napi_value AcquireFormStatePromise(napi_env env, AsyncAcquireFormStateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
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
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncAcquireFormStateCallbackInfo *) data;
            InnerAcquireFormState(env, asyncCallbackInfo);
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncAcquireFormStateCallbackInfo *) data;
            napi_value result = ParseFormStateInfo(env, asyncCallbackInfo->stateInfo);
            napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: acquireFormState
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_AcquireFormState(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    NAPI_ASSERT(env, valueType == napi_object,
        "The arguments[0] type of acquireFormState is incorrect, expected type is object.");

    auto *asyncCallbackInfo = new AsyncAcquireFormStateCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .want = {},
        .stateInfo = {},
    };

    bool parseResult = UnwrapWant(env, argv[0], asyncCallbackInfo->want);
    if (!parseResult) {
        HILOG_ERROR("%{public}s, failed to parse want.", __func__);
        delete asyncCallbackInfo;
        return nullptr;
    }

    if (argc == ARGS_SIZE_TWO) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of acquireFormState \
        is incorrect, expected type is function.");
        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
        return AcquireFormStateCallback(env, asyncCallbackInfo);
    } else {
        return AcquireFormStatePromise(env, asyncCallbackInfo);
    }
}

napi_value RegisterFormUninstallObserverCallback(napi_env env,
                                                 AsyncFormUninstallObserverCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncFormUninstallObserverCallbackInfo *) data;
            asyncCallbackInfo->result = 0;
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncFormUninstallObserverCallbackInfo *) data;

            if (asyncCallbackInfo->callback != nullptr) {
                napi_value result;
                napi_create_int32(env, asyncCallbackInfo->result, &result);
                napi_value callback;
                napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                napi_value callResult;
                napi_call_function(env, nullptr, callback, ARGS_SIZE_ONE, &result, &callResult);
                napi_delete_reference(env, asyncCallbackInfo->callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

napi_value RegisterFormUninstallObserverPromise(napi_env env,
                                                AsyncFormUninstallObserverCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
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
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncFormUninstallObserverCallbackInfo *) data;
            asyncCallbackInfo->result = 0;
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncFormUninstallObserverCallbackInfo *) data;
            napi_value result;
            napi_create_int32(env, asyncCallbackInfo->result, &result);
            napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: on
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_RegisterFormUninstallObserver(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    NAPI_ASSERT(env, valueType == napi_string,
        "The arguments[0] type of on is incorrect, expected type is string.");

    auto *asyncCallbackInfo = new AsyncFormUninstallObserverCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .result = 0,
    };

    if (argc == ARGS_SIZE_TWO) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of on \
        is incorrect, expected type is function.");
        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
        return RegisterFormUninstallObserverCallback(env, asyncCallbackInfo);
    } else {
        return RegisterFormUninstallObserverPromise(env, asyncCallbackInfo);
    }
}


napi_value UnregisterFormUninstallObserverCallback(napi_env env,
                                                   AsyncFormUninstallObserverCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncFormUninstallObserverCallbackInfo *) data;
            asyncCallbackInfo->result = 0;
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncFormUninstallObserverCallbackInfo *) data;

            if (asyncCallbackInfo->callback != nullptr) {
                napi_value result;
                napi_create_int32(env, asyncCallbackInfo->result, &result);
                napi_value callback;
                napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                napi_value callResult;
                napi_call_function(env, nullptr, callback, ARGS_SIZE_ONE, &result, &callResult);
                napi_delete_reference(env, asyncCallbackInfo->callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

napi_value UnregisterFormUninstallObserverPromise(napi_env env,
                                                  AsyncFormUninstallObserverCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
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
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncFormUninstallObserverCallbackInfo *) data;
            asyncCallbackInfo->result = 0;
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncFormUninstallObserverCallbackInfo *) data;
            napi_value result;
            napi_create_int32(env, asyncCallbackInfo->result, &result);
            napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: off
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_UnregisterFormUninstallObserver(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_TWO) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
    NAPI_ASSERT(env, valueType == napi_string,
        "The arguments[0] type of off is incorrect, expected type is string.");

    auto *asyncCallbackInfo = new AsyncFormUninstallObserverCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .result = 0,
    };

    if (argc == ARGS_SIZE_TWO) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of off \
        is incorrect, expected type is function.");
        napi_create_reference(env, argv[1], REF_COUNT, &asyncCallbackInfo->callback);
        return UnregisterFormUninstallObserverCallback(env, asyncCallbackInfo);
    } else {
        return UnregisterFormUninstallObserverPromise(env, asyncCallbackInfo);
    }
}

napi_value NotifyFormsVisibleCallback(napi_env env, AsyncNotifyFormsVisibleCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsVisibleCallbackInfo *) data;
            asyncCallbackInfo->result = 0;
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsVisibleCallbackInfo *) data;

            if (asyncCallbackInfo->callback != nullptr) {
                napi_value result;
                napi_create_int32(env, asyncCallbackInfo->result, &result);
                napi_value callback;
                napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                napi_value callResult;
                napi_call_function(env, nullptr, callback, ARGS_SIZE_ONE, &result, &callResult);
                napi_delete_reference(env, asyncCallbackInfo->callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

napi_value NotifyFormsVisiblePromise(napi_env env, AsyncNotifyFormsVisibleCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
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
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsVisibleCallbackInfo *) data;
            asyncCallbackInfo->result = 0;
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsVisibleCallbackInfo *) data;
            napi_value result;
            napi_create_int32(env, asyncCallbackInfo->result, &result);
            napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: notifyFormsVisible
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_NotifyFormsVisible(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }

    uint32_t numForms = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &numForms));
    NAPI_ASSERT(env, numForms > 0, "The type of arg 0 is incorrect, this array is empty.");

    std::vector<int64_t> formIds {};
    napi_valuetype valueType;
    for (size_t i = 0; i < numForms; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        NAPI_ASSERT(env, valueType == napi_string, "The type of arg 0 is incorrect, expected type is string.");

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        bool isConversionSucceeded = ConvertStringToInt64(strFormId, formIdValue);
        NAPI_ASSERT(env, isConversionSucceeded, "The arguments[0] type of notifyFormsVisible is incorrect, expected "
        "type is string and the content must be numeric,value range is: 0x8000000000000000~0x7FFFFFFFFFFFFFFF.");
        formIds.push_back(formIdValue);
    }

    valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
    NAPI_ASSERT(env, valueType == napi_boolean, "The type of arg 1 is incorrect, expected type is boolean.");
    auto *asyncCallbackInfo = new AsyncNotifyFormsVisibleCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formIds = formIds,
        .isVisible = false,
    };
    napi_get_value_bool(env, argv[1], &asyncCallbackInfo->isVisible);

    if (argc == ARGS_SIZE_THREE) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of arg 2 is incorrect, expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
        return NotifyFormsVisibleCallback(env, asyncCallbackInfo);
    } else {
        return NotifyFormsVisiblePromise(env, asyncCallbackInfo);
    }
}

napi_value NotifyFormsEnableUpdateCallback(napi_env env,
                                           AsyncNotifyFormsEnableUpdateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, asyncCallback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work running", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsEnableUpdateCallbackInfo *) data;
            asyncCallbackInfo->result = 0;
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, napi_create_async_work complete", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsEnableUpdateCallbackInfo *) data;

            if (asyncCallbackInfo->callback != nullptr) {
                napi_value result;
                napi_create_int32(env, asyncCallbackInfo->result, &result);
                napi_value callback;
                napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
                napi_value callResult;
                napi_call_function(env, nullptr, callback, ARGS_SIZE_ONE, &result, &callResult);
                napi_delete_reference(env, asyncCallbackInfo->callback);
            }
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

napi_value NotifyFormsEnableUpdatePromise(napi_env env,
                                          AsyncNotifyFormsEnableUpdateCallbackInfo *const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s, promise.", __func__);
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
        [](napi_env env, void *data) {
            HILOG_INFO("%{public}s, promise runnning", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsEnableUpdateCallbackInfo *) data;
            asyncCallbackInfo->result = 0;
        },
        [](napi_env env, napi_status status, void *data) {
            HILOG_INFO("%{public}s, promise complete", __func__);
            auto *asyncCallbackInfo = (AsyncNotifyFormsEnableUpdateCallbackInfo *) data;
            napi_value result;
            napi_create_int32(env, asyncCallbackInfo->result, &result);
            napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
            napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
            delete asyncCallbackInfo;
        },
        (void *) asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

/**
 * @brief  The implementation of Node-API interface: notifyFormsEnableUpdate
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_NotifyFormsEnableUpdate(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }

    uint32_t numForms = 0;
    NAPI_CALL(env, napi_get_array_length(env, argv[0], &numForms));
    NAPI_ASSERT(env, numForms > 0, "The type of arg 0 is incorrect, this array is empty.");

    std::vector<int64_t> formIds {};
    napi_valuetype valueType;
    for (size_t i = 0; i < numForms; i++) {
        napi_value napiFormId;
        napi_get_element(env, argv[0], i, &napiFormId);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, napiFormId, &valueType));
        NAPI_ASSERT(env, valueType == napi_string, "The type of arg 0 is incorrect, expected type is string.");

        std::string strFormId = GetStringFromNAPI(env, napiFormId);
        int64_t formIdValue;
        bool isConversionSucceeded = ConvertStringToInt64(strFormId, formIdValue);
        NAPI_ASSERT(env, isConversionSucceeded, "The type of arg 0 is incorrect, expected type is string and "
        "the content must be numeric, value range is: 0x8000000000000000~0x7FFFFFFFFFFFFFFF.");
        formIds.push_back(formIdValue);
    }

    valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[1], &valueType));
    NAPI_ASSERT(env, valueType == napi_boolean, "The type of arg 1 is incorrect, expected type is boolean.");
    auto *asyncCallbackInfo = new AsyncNotifyFormsEnableUpdateCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formIds = formIds,
        .isEnableUpdate = false,
    };
    napi_get_value_bool(env, argv[1], &asyncCallbackInfo->isEnableUpdate);

    if (argc == ARGS_SIZE_THREE) {
        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The type of arg 2 is incorrect, expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
        return NotifyFormsEnableUpdateCallback(env, asyncCallbackInfo);
    } else {
        return NotifyFormsEnableUpdatePromise(env, asyncCallbackInfo);
    }
}

/**
 * @brief  Call native kit function: GetAllFormsInfo
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerGetAllFormsInfo(napi_env env, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->GetAllFormsInfo(asyncCallbackInfo->formInfos);
    HILOG_DEBUG("%{public}s, end", __func__);
}

// NAPI_GetAllFormsInfo callback execute
napi_async_execute_callback NAPI_GetAllFormsInfoAsyncExecute = [](napi_env env, void *data) {
    HILOG_INFO("NAPI_GetAllFormsInfo execute callback");
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = (AsyncGetFormsInfoCallbackInfo *)data;
    InnerGetAllFormsInfo(env, asyncCallbackInfo);
};

// NAPI_GetFormsInfo callback complete
napi_async_complete_callback NAPI_GetFormsInfoAsyncComplete = [](napi_env env, napi_status status, void *data) {
    HILOG_INFO("NAPI_GetFormsInfo compeleted callback");
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = (AsyncGetFormsInfoCallbackInfo *)data;
    napi_value arrayFormInfos;
    napi_create_array(env, &arrayFormInfos);
    if (asyncCallbackInfo->result == ERR_OK) {
        int iFormInfoCount = 0;
        for (auto formInfo : asyncCallbackInfo->formInfos) {
            napi_value formInfoObject = nullptr;
            napi_create_object(env, &formInfoObject);
            ParseFormInfoIntoNapi(env, formInfo, formInfoObject);
            napi_set_element(env, arrayFormInfos, iFormInfoCount, formInfoObject);
            ++iFormInfoCount;
        }
    }
    if (asyncCallbackInfo->callback != nullptr) {
        napi_value callbackValues[2] = {0};
        napi_value callback;
        napi_value resultCode;
        ErrCode errCode = asyncCallbackInfo->result;
        if (errCode == ERR_OK) {
            napi_create_int32(env, errCode, &resultCode);
            callbackValues[0] = resultCode;
            callbackValues[1] = arrayFormInfos;
        } else {
            InnerCreateRetMsg(env, errCode, callbackValues);
        }

        napi_get_reference_value(env, asyncCallbackInfo->callback, &callback);
        napi_value callResult;
        napi_call_function(env, nullptr, callback, ARGS_SIZE_TWO, callbackValues, &callResult);
        napi_delete_reference(env, asyncCallbackInfo->callback);
    }
    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
};

// NAPI_GetFormsInfo promise Complete
napi_async_complete_callback NAPI_GetFormsInfoPromiseComplete = [](napi_env env, napi_status status, void *data) {
    HILOG_INFO("%{public}s, promise complete", __func__);
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = (AsyncGetFormsInfoCallbackInfo *)data;
    if (asyncCallbackInfo->result == ERR_OK) {
        napi_value arrayFormInfos;
        napi_create_array(env, &arrayFormInfos);
        int iFormInfoCount = 0;
        for (auto formInfo : asyncCallbackInfo->formInfos) {
            napi_value formInfoObject = nullptr;
            napi_create_object(env, &formInfoObject);
            ParseFormInfoIntoNapi(env, formInfo, formInfoObject);
            napi_set_element(env, arrayFormInfos, iFormInfoCount, formInfoObject);
            ++iFormInfoCount;
        }
        napi_resolve_deferred(
            asyncCallbackInfo->env,
            asyncCallbackInfo->deferred,
            arrayFormInfos);
    } else {
        napi_value getFormsInfoResult;
        InnerCreateRetMsg(env, asyncCallbackInfo->result, &getFormsInfoResult);

        napi_reject_deferred(
            asyncCallbackInfo->env,
            asyncCallbackInfo->deferred,
            getFormsInfoResult);
    }

    napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
    delete asyncCallbackInfo;
};

/**
 * @brief  The implementation of Node-API interface: getAllFormsInfo
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_GetAllFormsInfo(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_ONE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = new
    AsyncGetFormsInfoCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formInfos = std::vector<OHOS::AppExecFwk::FormInfo>(),
        .bundleName = "",
        .moduleName = "",
        .result = 0,
    };

    if (argc == ARGS_SIZE_ONE) {
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        napi_valuetype valueType;
        NAPI_CALL(env, napi_typeof(env, argv[0], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[0] type of getAllFormsInfo is incorrect,\
            expected type is function.");

        napi_create_reference(env, argv[0], REF_COUNT, &asyncCallbackInfo->callback);
        napi_value resourceName;
        napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
        napi_create_async_work(
            env,
            nullptr,
            resourceName,
            NAPI_GetAllFormsInfoAsyncExecute,
            NAPI_GetFormsInfoAsyncComplete,
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        return NapiGetResult(env, 1);
    } else {
        HILOG_INFO("%{public}s, promise.", __func__);
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
            NAPI_GetAllFormsInfoAsyncExecute,
            NAPI_GetFormsInfoPromiseComplete,
            (void *)asyncCallbackInfo,
            &asyncCallbackInfo->asyncWork);
        napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
        return promise;
    }
}

/**
 * @brief  Call native kit function: GetFormsInfoByApp
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerGetFormsInfoByApp(napi_env env, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->GetFormsInfoByApp(
        asyncCallbackInfo->bundleName,
        asyncCallbackInfo->formInfos);
    HILOG_DEBUG("%{public}s, end", __func__);
}

/**
 * @brief  Call native kit function: GetFormsInfoByModule
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] asyncCallbackInfo Reference, callback info via Node-API
 *
 * @return void
 */
static void InnerGetFormsInfoByModule(napi_env env, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_DEBUG("%{public}s called.", __func__);
    OHOS::AppExecFwk::Ability *ability = asyncCallbackInfo->ability;
    asyncCallbackInfo->result = ability->GetFormsInfoByModule(
        asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName,
        asyncCallbackInfo->formInfos);
    HILOG_DEBUG("%{public}s, end", __func__);
}

// NAPI_GetFormsInfo byModule callback execute
auto NAPI_GetFormsInfoByModuleAsyncExecute = [](napi_env env, void *data) {
    HILOG_INFO("NAPI_GetFormsInfo byModule execute callback");
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo =
        (AsyncGetFormsInfoCallbackInfo *)data;
    InnerGetFormsInfoByModule(env, asyncCallbackInfo);
};

// NAPI_GetFormsInfo byApp callback execute
auto NAPI_GetFormsInfoByAppAsyncExecute = [](napi_env env, void *data) {
    HILOG_INFO("NAPI_GetFormsInfo byApp execute callback");
    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo =
        (AsyncGetFormsInfoCallbackInfo *)data;
    InnerGetFormsInfoByApp(env, asyncCallbackInfo);
};

// GetFormsInfo callback
napi_value GetFormsInfoCallback(napi_env env, AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo, bool isByApp)
{
    HILOG_INFO("%{public}s, callback.", __func__);
    napi_value resourceName;
    napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName);
    napi_create_async_work(
        env,
        nullptr,
        resourceName,
        isByApp ? NAPI_GetFormsInfoByAppAsyncExecute :
        NAPI_GetFormsInfoByModuleAsyncExecute,
        NAPI_GetFormsInfoAsyncComplete,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    return NapiGetResult(env, 1);
}

// GetFormsInfo promise
napi_value GetFormsInfoPromise(napi_env env, AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo, bool isByApp)
{
    HILOG_INFO("%{public}s, promise.", __func__);
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
        isByApp ? NAPI_GetFormsInfoByAppAsyncExecute : NAPI_GetFormsInfoByModuleAsyncExecute,
        NAPI_GetFormsInfoPromiseComplete,
        (void *)asyncCallbackInfo,
        &asyncCallbackInfo->asyncWork);
    napi_queue_async_work(env, asyncCallbackInfo->asyncWork);
    return promise;
}

// GetFormsInfo THREE ARGV
napi_value GetFormsInfoThreeArgv(napi_env env, napi_value *argv, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s.", __func__);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ONE], &valueType));
    std::string moduleNameInfo = GetStringFromNAPI(env, argv[ARGS_SIZE_ONE]);
    HILOG_INFO("%{public}s, moduleNameInfo=%{public}s.", __func__, moduleNameInfo.c_str());
    asyncCallbackInfo->moduleName = moduleNameInfo;

    // Check the value type of the arguments
    valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valueType));
    NAPI_ASSERT(env, valueType == napi_function, "The arguments[2] type of getFormsInfo is incorrect,\
        expected type is function.");
    napi_create_reference(env, argv[ARGS_SIZE_TWO], REF_COUNT, &asyncCallbackInfo->callback);
    return GetFormsInfoCallback(env, asyncCallbackInfo, false);
}

// GetFormsInfo TWO ARGV
napi_value GetFormsInfoTwoArgv(napi_env env, napi_value *argv, AsyncGetFormsInfoCallbackInfo* const asyncCallbackInfo)
{
    HILOG_INFO("%{public}s.", __func__);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ONE], &valueType));

    // GetFormsInfoByModule promise
    if (valueType == napi_string) {
        std::string moduleNameInfo = GetStringFromNAPI(env, argv[ARGS_SIZE_ONE]);
        HILOG_INFO("%{public}s, moduleNameInfo=%{public}s.", __func__, moduleNameInfo.c_str());
        asyncCallbackInfo->moduleName = moduleNameInfo;
        return GetFormsInfoPromise(env, asyncCallbackInfo, false);
    } else if (valueType == napi_function) { // GetFormsInfoByApp callback
        HILOG_INFO("%{public}s, asyncCallback.", __func__);

        // Check the value type of the arguments
        valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ONE], &valueType));
        NAPI_ASSERT(env, valueType == napi_function, "The arguments[1] type of getFormsInfo is incorrect,\
            expected type is function.");
        napi_create_reference(env, argv[ARGS_SIZE_ONE], REF_COUNT, &asyncCallbackInfo->callback);
        return GetFormsInfoCallback(env, asyncCallbackInfo, true);
    } else {
        NAPI_ASSERT(env, false, "The arguments[1] type of getFormsInfo is incorrect,\
            expected type is string or function.");
        return NapiGetResult(env, 1);
    }
}

/**
 * @brief  The implementation of Node-API interface: getFormsInfo
 *
 * @param[in] env The environment that the Node-API call is invoked under
 * @param[out] info An opaque datatype that is passed to a callback function
 *
 * @return This is an opaque pointer that is used to represent a JavaScript value
 */
napi_value NAPI_GetFormsInfo(napi_env env, napi_callback_info info)
{
    HILOG_INFO("%{public}s called.", __func__);

    // Check the number of the arguments
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARGS_SIZE_THREE) {
        HILOG_ERROR("%{public}s, wrong number of arguments.", __func__);
        return nullptr;
    }
    HILOG_INFO("%{public}s, argc = [%{public}zu]", __func__, argc);

    // Check the value type of the arguments
    napi_valuetype valueType;
    NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_ZERO], &valueType));
    std::string bundleNameInfo = GetStringFromNAPI(env, argv[ARGS_SIZE_ZERO]);
    HILOG_INFO("%{public}s, bundleName=%{public}s.", __func__, bundleNameInfo.c_str());

    AsyncGetFormsInfoCallbackInfo *asyncCallbackInfo = new
    AsyncGetFormsInfoCallbackInfo {
        .env = env,
        .ability = GetGlobalAbility(env),
        .asyncWork = nullptr,
        .deferred = nullptr,
        .callback = nullptr,
        .formInfos = std::vector<OHOS::AppExecFwk::FormInfo>(),
        .bundleName = bundleNameInfo,
        .moduleName = "",
        .result = 0,
    };

    if (argc == ARGS_SIZE_THREE) { // GetFormsInfoByModule callback
        HILOG_INFO("%{public}s, ARGS_SIZE_THREE.", __func__);
        return GetFormsInfoThreeArgv(env, argv, asyncCallbackInfo);
    } else if (argc == ARGS_SIZE_TWO) {
        HILOG_INFO("%{public}s, ARGS_SIZE_TWO.", __func__);
        return GetFormsInfoTwoArgv(env, argv, asyncCallbackInfo);
    } else if (argc == ARGS_SIZE_ONE) { // GetFormsInfoByApp promise
        return GetFormsInfoPromise(env, asyncCallbackInfo, true);
    }
    return NapiGetResult(env, 1);
}

