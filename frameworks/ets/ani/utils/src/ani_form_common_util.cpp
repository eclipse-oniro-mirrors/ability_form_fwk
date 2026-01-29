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

#include <iostream>
#include <cstring>
#include <cinttypes>
#include <regex>
#include <charconv>

#include "ani_form_common_util.h"
#include "ani_enum_convert.h"
#include "fms_log_wrapper.h"
#include "ani_form_error_util.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int ZERO_VALUE = 0;
constexpr int TWO_VALUE = 2;
constexpr int INT_64_LENGTH = 19;
constexpr int BASE_NUMBER = 9;
constexpr int64_t HEAD_BIT_NUM = 9000000000000000000;
constexpr const char* CLASSNAME_BOOL = "std.core.Boolean";
constexpr const char* CLASSNAME_ARRAY = "std.core.Array";
constexpr const char* CLASSNAME_RUNNING_FORM_INFO = "@ohos.app.form.formInfo.formInfo.RunningFormInfoInner";
constexpr const char* ENUMNAME_VISIBILITYTYPE = "@ohos.app.form.formInfo.formInfo.VisibilityType";
constexpr const char* ENUMNAME_FORMUSAGESTATE = "@ohos.app.form.formInfo.formInfo.FormUsageState";
constexpr const char* ENUMNAME_FORMLOCATION = "@ohos.app.form.formInfo.formInfo.FormLocation";

ani_object CreateBoolean(ani_env *env, ani_boolean value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(CLASSNAME_BOOL, &cls)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    ani_method ctor = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "z:", &ctor)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, ctor, &obj, value)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    return obj;
}
}

ani_object CreateAniObject(ani_env* env, const char* className)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        HILOG_ERROR("find Context failed status: %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":", &method);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_FindMethod ctor failed status: %{public}d", status);
        return nullptr;
    }
    ani_object objValue = nullptr;
    if (env->Object_New(cls, method, &objValue) != ANI_OK) {
        HILOG_ERROR("Object_New failed status: %{public}d", status);
        return nullptr;
    }
    return objValue;
}

bool SetPropertyStringByName(ani_env* env, ani_object object, const char* name, std::string string)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_string aniString = nullptr;
    env->String_NewUTF8(string.c_str(), string.size(), &aniString);
    if ((status = env->Object_SetPropertyByName_Ref(object, name, aniString)) != ANI_OK) {
        HILOG_ERROR("name is: %{public}s SetProperty status: %{public}d", name, status);
        return false;
    }
    return true;
}

void SetPropertyBoolByName(ani_env *env, ani_object object, const char *name, bool value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_object obj = CreateBoolean(env, static_cast<ani_boolean>(value));
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Ref(object, name, reinterpret_cast<ani_ref>(obj))) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return;
    }
}

void SetPropertyBoolByNameValue(ani_env *env, ani_object object, const char *name, bool value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Boolean(object, name, static_cast<ani_boolean>(value))) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return;
    }
}

void SetPropertyDoubleByName(ani_env *env, ani_object object, const char *name, double value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Double(object, name, value)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return;
    }
    return;
}

bool SetPropertyIntByName(ani_env *env, ani_object object, const char *name, int32_t value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Int(object, name, value)) != ANI_OK) {
        HILOG_ERROR("Object_SetFieldByName_Int status: %{public}d", status);
        return false;
    }
    return true;
}

void SetPropertyByName(ani_env *env, ani_object object, const char *name, ani_object value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Ref(object, name, value)) != ANI_OK) {
        HILOG_ERROR("Object_SetFieldByName_Int status: %{public}d", status);
        return;
    }
}

ani_object CreateArrayObject(ani_env *env)
{
    ani_status status = ANI_OK;
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_class arrayCls = nullptr;
    status = env->FindClass(CLASSNAME_ARRAY, &arrayCls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed status: %{public}d", status);
        return nullptr;
    }
    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, "<ctor>", ":", &arrayCtor);
    if (status != ANI_OK) {
        HILOG_ERROR("find ctor failed status: %{public}d", status);
        return nullptr;
    }
    ani_object arrayObj;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New array failed status: %{public}d", status);
        return nullptr;
    }
    return arrayObj;
}

bool GetStdString(ani_env *env, ani_string str, std::string &value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_size sz = 0;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    value.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, value.data(), value.size(), &sz)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    value.resize(sz);
    return true;
}

ani_string GetAniString(ani_env *env, const std::string &str)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_string aniStr = nullptr;
    ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
    if (status != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return nullptr;
    }
    return aniStr;
}

bool GetPropertyIntObject(ani_env *env, ani_object param, const char *name, int32_t &value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }

    ani_status status = ANI_ERROR;
    ani_int res = 0;
    if ((status = env->Object_GetPropertyByName_Int(param, name, &res)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    value = res;
    return true;
}

bool GetPropertyDoubleObject(ani_env *env, ani_object param, const char *name, double &value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }

    ani_status status = ANI_ERROR;
    ani_double res = 0.0;
    if ((status = env->Object_GetPropertyByName_Double(param, name, &res)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    value = static_cast<double>(res);
    return true;
}

bool GetPropertyBoolByName(ani_env *env, ani_object object, const char *name, bool &value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_ref field = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(object, name, &field)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    ani_boolean isUndefined = ANI_TRUE;
    if ((status = env->Reference_IsUndefined(field, &isUndefined)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    if (isUndefined) {
        HILOG_ERROR("%{public}s: undefined", name);
        return false;
    }
    ani_boolean aniValue = ANI_FALSE;
    if ((status = env->Object_CallMethodByName_Boolean(
        reinterpret_cast<ani_object>(field), "toBoolean", nullptr, &aniValue)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    value = static_cast<bool>(aniValue);
    return true;
}

int ConvertStringToInt(const std::string &strInfo)
{
    return static_cast<int>(strtoll(strInfo.c_str(), nullptr, BASE_REQUEST_CODE_NUM));
}
bool ConvertStringToInt64(const std::string &strInfo, int64_t &int64Value)
{
    size_t strLength = strInfo.size();
    if (strLength == ZERO_VALUE) {
        int64Value = ZERO_VALUE;
        return true;
    }
    std::regex pattern("^0|-?[1-9][0-9]{0,18}$");  // "^-?[0-9]{1,19}$"
    std::smatch match;
    if (regex_match(strInfo, match, pattern)) {
        HILOG_DEBUG("regex_match successed");
        if (strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1) != "-") {
            int maxSubValue = ConvertStringToInt(strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1));
            if (strLength < INT_64_LENGTH || (strLength == INT_64_LENGTH && maxSubValue < BASE_NUMBER)) {
                auto result = std::from_chars(strInfo.data(), strInfo.data() + strLength, int64Value);
                return result.ec == std::errc();
            }
            int64_t subValue;
            const std::string newStrInfo = strInfo.substr(ZERO_VALUE + 1, INT_64_LENGTH - 1);
            auto checkResult = std::from_chars(newStrInfo.data(), newStrInfo.data() + newStrInfo.size(), subValue);
            if (checkResult.ec != std::errc()) {
                return false;
            }
            if (strLength == INT_64_LENGTH && subValue <= (INT64_MAX - HEAD_BIT_NUM)) {
                auto result = std::from_chars(strInfo.data(), strInfo.data() + strLength, int64Value);
                return result.ec == std::errc();
            }
            return false;
        }
        int minSubValue = ConvertStringToInt(strInfo.substr(1, 1));
        if (strLength < INT_64_LENGTH + 1 || (strLength == INT_64_LENGTH + 1 && minSubValue < BASE_NUMBER)) {
            auto result = std::from_chars(strInfo.data(), strInfo.data() + strLength, int64Value);
            return result.ec == std::errc();
        }
        int64_t subValue;
        const std::string newStrInfo = strInfo.substr(ZERO_VALUE + TWO_VALUE, INT_64_LENGTH - 1);
        auto result = std::from_chars(newStrInfo.data(), newStrInfo.data() + newStrInfo.size(), subValue);
        if (result.ec != std::errc()) {
            return false;
        }
        if (strLength == INT_64_LENGTH + 1 && subValue <= (INT64_MAX - HEAD_BIT_NUM + 1)) {
            auto result = std::from_chars(strInfo.data(), strInfo.data() + strLength, int64Value);
            return result.ec == std::errc();
        }
    }
    HILOG_DEBUG("regex_match failed");
    return false;
}

bool AsyncCallback(ani_env *env, const char* className, ani_object call, ani_object error, ani_object result)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass(className, &clsCall);
    if (status!= ANI_OK || clsCall == nullptr) {
        HILOG_ERROR("FindClass status: %{public}d, or null clsCall", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "invoke", nullptr, &method)) != ANI_OK || method == nullptr) {
        HILOG_ERROR("Class_FindMethod status: %{public}d, or null method", status);
        return false;
    }
    if (error == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        error = reinterpret_cast<ani_object>(nullRef);
    }
    if (result == nullptr) {
        ani_ref undefinedRef = nullptr;
        env->GetUndefined(&undefinedRef);
        result = reinterpret_cast<ani_object>(undefinedRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        HILOG_ERROR("Object_CallMethod_Void status: %{public}d", status);
        return false;
    }
    return true;
}

bool Callback(ani_env *env, ani_object call, ani_object result, const char *name)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_class clsCall = nullptr;
    ani_status status = env->FindClass(name, &clsCall);
    if (status!= ANI_OK || clsCall == nullptr) {
        HILOG_ERROR("FindClass status: %{public}d, or null clsCall", status);
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(clsCall, "invoke", nullptr, &method)) != ANI_OK || method == nullptr) {
        HILOG_ERROR("Class_FindMethod status: %{public}d, or null method", status);
        return false;
    }
    if ((status = env->Object_CallMethod_Void(call, method, result)) != ANI_OK) {
        HILOG_ERROR("Object_CallMethod_Void status: %{public}d", status);
        return false;
    }
    return true;
}

ani_object CreateFormInstances(ani_env *env, const std::vector<AppExecFwk::FormInstance> &formInstances)
{
    HILOG_DEBUG("call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_class arrayCls = nullptr;
    ani_status status = ANI_OK;
    status = env->FindClass(CLASSNAME_ARRAY, &arrayCls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed status: %{public}d", status);
        return nullptr;
    }

    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        HILOG_ERROR("find ctor failed status: %{public}d", status);
        return nullptr;
    }

    ani_object arrayObj;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, formInstances.size());
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New array status: %{public}d", status);
        return arrayObj;
    }
    ani_size index = 0;
    for (auto &iter : formInstances) {
        ani_object aniInfo = CreateFormInstance(env, iter);
        if (aniInfo == nullptr) {
            HILOG_WARN("null aniInfo");
            break;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, aniInfo);
        if (status != ANI_OK) {
            HILOG_WARN("Object_CallMethodByName_Void failed status: %{public}d", status);
            break;
        }
        index++;
    }
    return arrayObj;
}

ani_object CreateFormInstance(ani_env *env, const AppExecFwk::FormInstance &formInstance)
{
    HILOG_DEBUG("call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_class infoClass = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object infoObject = nullptr;
    if ((status = env->FindClass(CLASSNAME_RUNNING_FORM_INFO, &infoClass)) != ANI_OK || infoClass == nullptr) {
        HILOG_ERROR("FindClass status: %{public}d or null infoClass", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(infoClass, "<ctor>", ":", &method)) != ANI_OK || method == nullptr) {
        HILOG_ERROR("Class_FindMethod status: %{public}d or null method", status);
        return nullptr;
    }
    if ((status = env->Object_New(infoClass, method, &infoObject)) != ANI_OK || infoObject == nullptr) {
        HILOG_ERROR("Object_New status: %{public}d or null infoObject", status);
        return nullptr;
    }
    std::string formStr = std::to_string(formInstance.formId);
    if (!SetPropertyIntByName(env, infoObject, "dimension", formInstance.specification) ||
        !SetPropertyStringByName(env, infoObject, "formId", formStr) ||
        !SetPropertyStringByName(env, infoObject, "bundleName", formInstance.bundleName) ||
        !SetPropertyStringByName(env, infoObject, "hostBundleName", formInstance.formHostName) ||
        !SetPropertyStringByName(env, infoObject, "moduleName", formInstance.moduleName) ||
        !SetPropertyStringByName(env, infoObject, "abilityName", formInstance.abilityName) ||
        !SetPropertyStringByName(env, infoObject, "formName", formInstance.formName) ||
        !SetPropertyStringByName(env, infoObject, "formDescription", formInstance.description)) {
            HILOG_ERROR("CreateFormInstance failed");
            return nullptr;
    }
    ani_enum_item visibilityType {};
    AniEnumConvertUtil::EnumConvert_NativeToEts(env, ENUMNAME_VISIBILITYTYPE,
        formInstance.formVisiblity, visibilityType);
    if ((status = env->Object_SetPropertyByName_Ref(infoObject, "visibilityType", visibilityType)) != ANI_OK) {
        HILOG_ERROR("visibilityType failed status:%{public}d", status);
        return nullptr;
    }
    ani_enum_item formUsageState {};
    AniEnumConvertUtil::EnumConvert_NativeToEts(env, ENUMNAME_FORMUSAGESTATE,
        formInstance.formUsageState, formUsageState);
    if ((status = env->Object_SetPropertyByName_Ref(infoObject, "formUsageState", formUsageState)) != ANI_OK) {
        HILOG_ERROR("formUsageState failed status:%{public}d", status);
        return nullptr;
    }
    return infoObject;
}

ani_object CreateRunningFormInfos(ani_env *env, const std::vector<AppExecFwk::RunningFormInfo> &runningFormInfos)
{
    HILOG_DEBUG("call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_class arrayCls = nullptr;
    ani_status status = ANI_OK;
    status = env->FindClass(CLASSNAME_ARRAY, &arrayCls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed status: %{public}d", status);
        return nullptr;
    }

    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        HILOG_ERROR("find ctor failed status: %{public}d", status);
        return nullptr;
    }

    ani_object arrayObj;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, runningFormInfos.size());
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New array status: %{public}d", status);
        return arrayObj;
    }
    ani_size index = 0;
    for (auto &iter : runningFormInfos) {
        ani_object aniInfo = CreateRunningFormInfo(env, iter);
        if (aniInfo == nullptr) {
            HILOG_WARN("null aniInfo");
            break;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, aniInfo);
        if (status != ANI_OK) {
            HILOG_WARN("Object_CallMethodByName_Void failed status: %{public}d", status);
            break;
        }
        index++;
    }
    return arrayObj;
}

bool CreateRunningFormInfoEnum(ani_env *env, const AppExecFwk::RunningFormInfo &runningFormInfo, ani_object &infoObject)
{
    HILOG_DEBUG("call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_enum_item visibilityType {};
    AniEnumConvertUtil::EnumConvert_NativeToEts(env,
        ENUMNAME_VISIBILITYTYPE,
        runningFormInfo.formVisiblity, visibilityType);
    if ((status = env->Object_SetPropertyByName_Ref(infoObject, "visibilityType", visibilityType)) != ANI_OK) {
        HILOG_ERROR("visibilityType failed status:%{public}d", status);
        return false;
    }
    ani_enum_item formUsageState {};
    AniEnumConvertUtil::EnumConvert_NativeToEts(env,
        ENUMNAME_FORMUSAGESTATE,
        runningFormInfo.formUsageState, formUsageState);
    if ((status = env->Object_SetPropertyByName_Ref(infoObject, "formUsageState", formUsageState)) != ANI_OK) {
        HILOG_ERROR("formUsageState failed status:%{public}d", status);
        return false;
    }
    ani_enum_item formLocation {};
    AniEnumConvertUtil::EnumConvert_NativeToEts(env,
        ENUMNAME_FORMLOCATION,
        runningFormInfo.formLocation, formLocation);
    if ((status = env->Object_SetPropertyByName_Ref(infoObject, "formLocation", formLocation)) != ANI_OK) {
        HILOG_ERROR("formLocation failed status:%{public}d", status);
        return false;
    }
    return true;
}

ani_object CreateRunningFormInfo(ani_env *env, const AppExecFwk::RunningFormInfo &runningFormInfo)
{
    HILOG_DEBUG("call");
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_class infoClass = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object infoObject = nullptr;
    if ((status = env->FindClass(CLASSNAME_RUNNING_FORM_INFO, &infoClass)) != ANI_OK || infoClass == nullptr) {
        HILOG_ERROR("FindClass status: %{public}d or null infoClass", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(infoClass, "<ctor>", ":", &method)) != ANI_OK || method == nullptr) {
        HILOG_ERROR("Class_FindMethod status: %{public}d or null method", status);
        return nullptr;
    }
    if ((status = env->Object_New(infoClass, method, &infoObject)) != ANI_OK || infoObject == nullptr) {
        HILOG_ERROR("Object_New status: %{public}d or null infoObject", status);
        return nullptr;
    }
    std::string formStr = std::to_string(runningFormInfo.formId);
    if (!SetPropertyIntByName(env, infoObject, "dimension", runningFormInfo.dimension) ||
        !SetPropertyStringByName(env, infoObject, "formId", formStr) ||
        !SetPropertyStringByName(env, infoObject, "bundleName", runningFormInfo.bundleName) ||
        !SetPropertyStringByName(env, infoObject, "hostBundleName", runningFormInfo.hostBundleName) ||
        !SetPropertyStringByName(env, infoObject, "moduleName", runningFormInfo.moduleName) ||
        !SetPropertyStringByName(env, infoObject, "abilityName", runningFormInfo.abilityName) ||
        !SetPropertyStringByName(env, infoObject, "formName", runningFormInfo.formName) ||
        !SetPropertyStringByName(env, infoObject, "formDescription", runningFormInfo.description)) {
            HILOG_ERROR("CreateRunningFormInfo failed");
            return nullptr;
    }
    if (!CreateRunningFormInfoEnum(env, runningFormInfo, infoObject)) {
        HILOG_ERROR("CreateRunningFormInfoEnum failed");
        return nullptr;
    }
    return infoObject;
}

bool GetStringProperty(ani_env *env, ani_object param, const char *name, std::string &value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return false;
    }

    ani_ref obj = nullptr;
    ani_boolean isUndefined = true;
    ani_status status = ANI_ERROR;

    if ((status = env->Object_GetPropertyByName_Ref(param, name, &obj)) != ANI_OK) {
        HILOG_ERROR("get %{public}s status: %{public}d", name, status);
        return false;
    }
    if ((status = env->Reference_IsUndefined(obj, &isUndefined)) != ANI_OK) {
        HILOG_ERROR("get %{public}s status: %{public}d", name, status);
        return false;
    }
    if (isUndefined) {
        HILOG_ERROR("%{public}s : undefined", name);
        return false;
    }
    if (!GetStdString(env, reinterpret_cast<ani_string>(obj), value)) {
        HILOG_ERROR("GetStdString failed");
        return false;
    }
    return true;
}

bool ParseProviderFilter(ani_env *env, ani_object aniProviderFilter, AppExecFwk::FormInstancesFilter &filter)
{
    HILOG_DEBUG("call");
    if (env == nullptr || aniProviderFilter == nullptr) {
        HILOG_ERROR("env or aniProviderFilter is null");
        return false;
    }
    if (!GetStringProperty(env, aniProviderFilter, "bundleName", filter.bundleName)) {
        HILOG_ERROR("get bundleName failed");
        return false;
    }
    GetStringProperty(env, aniProviderFilter, "formName", filter.formName);
    GetStringProperty(env, aniProviderFilter, "moduleName", filter.moduleName);
    GetStringProperty(env, aniProviderFilter, "abilityName", filter.abilityName);
    GetPropertyBoolByName(env, aniProviderFilter, "isUnusedIncluded", filter.isUnusedIncluded);
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS
