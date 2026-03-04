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
#include <ctime>

#include "ani_form_common_util.h"
#include "ani_enum_convert.h"
#include "fms_log_wrapper.h"
#include "ani_form_error_util.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int ZERO_VALUE = 0;
constexpr int TWO_VALUE = 2;
constexpr int INT_64_LENGTH = 19;
constexpr int BASE_NUMBER = 9;
constexpr int BASE_REQUEST_CODE_NUM = 10;
constexpr int64_t HEAD_BIT_NUM = 9000000000000000000;
constexpr int64_t NANOSECONDS = 1000000000;
constexpr int64_t MICROSECONDS = 1000000;
constexpr const char *CLASSNAME_BOOL = "std.core.Boolean";
constexpr const char *CLASSNAME_INT = "std.core.Int";
constexpr const char *CLASSNAME_RECORD = "std.core.Record";
constexpr const char *CLASSNAME_ARRAY = "std.core.Array";
constexpr const char *CLASSNAME_ERROR = "escompat.Error";
constexpr const char *CLASSNAME_RUNNING_FORM_INFO = "@ohos.app.form.formInfo.formInfo.RunningFormInfoInner";
constexpr const char *FORM_INFO_INNER_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.formInfoInner";
constexpr const char *ENUMNAME_VISIBILITYTYPE = "@ohos.app.form.formInfo.formInfo.VisibilityType";
constexpr const char *ENUMNAME_FORMUSAGESTATE = "@ohos.app.form.formInfo.formInfo.FormUsageState";
constexpr const char *ENUMNAME_FORMLOCATION = "@ohos.app.form.formInfo.formInfo.FormLocation";
constexpr const char *ETS_FUNINTERACTIONPARAMS_NAME = "@ohos.app.form.formInfo.formInfo.FunInteractionParamsInner";
constexpr const char *ETS_SCENEANIMATIONPARAMS_NAME = "@ohos.app.form.formInfo.formInfo.SceneAnimationParamsInner";
constexpr const char *FORM_STATE_INFO_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.FormStateInfo";
constexpr const char *FORM_STATE_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.FormState";

ani_class GetAniClass(ani_env *env, const char *className)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }
    ani_status status = ANI_OK;
    ani_class cls{};
    status = env->FindClass(className, &cls);
    if (status != ANI_OK || cls == nullptr) {
        HILOG_ERROR("FindClass failed, error code: %{public}d", status);
    }
    return cls;
}

bool CreateRunningFormInfoEnum(ani_env *env,
    const AppExecFwk::RunningFormInfo &runningFormInfo, ani_object &infoObject)
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

void SetStringProperty(ani_env *env, ani_object obj, const char *propName, const std::string &value)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    ani_string anistr{};
    env->String_NewUTF8(value.c_str(), value.size(), &anistr);
    env->Object_SetPropertyByName_Ref(obj, propName, anistr);
}

ani_object CreateInt(ani_env *env, int32_t value)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }

    ani_class cls = nullptr;
    ani_method ctor = nullptr;
    ani_object object = nullptr;
    ani_status status = ANI_ERROR;

    status = env->FindClass(CLASSNAME_INT, &cls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed, status: %{public}d", status);
        return nullptr;
    }

    status = env->Class_FindMethod(cls, "<ctor>", "i:", &ctor);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed, status: %{public}d", status);
        return nullptr;
    }

    status = env->Object_New(cls, ctor, &object, value);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New failed, status: %{public}d", status);
        return nullptr;
    }

    return object;
}

bool AniParseInt32(ani_env *env, const ani_ref &aniInt, int32_t &out)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return false;
    }

    ani_int tmp = 0;
    ani_status status = env->Object_CallMethodByName_Int(
        static_cast<ani_object>(aniInt), "toInt", nullptr, &tmp);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_CallMethodByName_Int failed, status: %{public}d", status);
        return false;
    }

    out = static_cast<int32_t>(tmp);
    return true;
}

ani_array CreateAniArrayIntFromStdVector(ani_env *env, const std::vector<int32_t> &vec)
{
    ani_array array = nullptr;
    ani_ref undefined_ref;
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }

    if (env->GetUndefined(&undefined_ref) != ANI_OK) {
        HILOG_ERROR("GetUndefined failed");
        return array;
    }

    if (!vec.empty()) {
        if (env->Array_New(vec.size(), undefined_ref, &array) != ANI_OK) {
            HILOG_ERROR("Array_New failed");
            return array;
        }
        ani_size index = 0;
        for (auto value : vec) {
            ani_object valueAni = CreateInt(env, value);
            ani_status status = env->Array_Set(array, index, valueAni);
            if (status != ANI_OK) {
                HILOG_ERROR("Array_Set failed, status code: %{public}d", status);
                break;
            }
            index++;
        }
    }
    return array;
}

bool CreateRecordObject(ani_env *env, ani_class recordCls, ani_object &recordObject)
{
    if (env == nullptr || recordCls == nullptr) {
        HILOG_ERROR("env or recordCls is nullptr");
        return false;
    }

    ani_method ctorMethod = nullptr;
    ani_status status = env->Class_FindMethod(recordCls, "<ctor>", nullptr, &ctorMethod);
    if (status != ANI_OK) {
        HILOG_ERROR("Find constructor failed, status: %{public}d", status);
        return false;
    }

    status = env->Object_New(recordCls, ctorMethod, &recordObject);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New failed, status: %{public}d", status);
        return false;
    }
    return true;
}

bool CreateFormCustomizeDataRecord(ani_env *env, ani_object &recordObject,
    const std::vector<AppExecFwk::FormCustomizeData> &customizeData)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return false;
    }

    ani_class recordCls = nullptr;

    ani_status status = env->FindClass(CLASSNAME_RECORD, &recordCls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass 'std.core.Record' failed, status: %{public}d", status);
        return false;
    }

    if (!CreateRecordObject(env, recordCls, recordObject)) {
        HILOG_ERROR("create record object failed");
        return false;
    }

    ani_method setFunc = nullptr;
    status = env->Class_FindMethod(recordCls, FormAniUtil::ANI_SETTER_MARKER, nullptr, &setFunc);
    if (status != ANI_OK) {
        HILOG_ERROR("Find setter method failed, status: %{public}d", status);
        return false;
    }

    for (const auto &item : customizeData) {
        ani_string aniKey = nullptr;
        status = env->String_NewUTF8(item.name.c_str(), item.name.length(), &aniKey);
        if (status != ANI_OK) {
            HILOG_ERROR("String_NewUTF8 for key '%{public}s' failed, status: %{public}d",
                item.name.c_str(), status);
            return false;
        }

        ani_string aniValue = nullptr;
        status = env->String_NewUTF8(item.value.c_str(), item.value.length(), &aniValue);
        if (status != ANI_OK) {
            HILOG_ERROR("String_NewUTF8 for value '%{public}s' failed, status: %{public}d",
                item.value.c_str(), status);
            return false;
        }

        status = env->Object_CallMethod_Void(recordObject, setFunc, aniKey, (ani_ref)aniValue);
        if (status != ANI_OK) {
            HILOG_ERROR("Set key-value failed. key: %{public}s, value: %{public}s, status: %{public}d",
                item.name.c_str(), item.value.c_str(), status);
            return false;
        }
    }

    return true;
}

void SetFormInfoArrayProperties(ani_env *env, ani_object formInfoAni, const AppExecFwk::FormInfo &formInfo)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    // Set array properties
    ani_array supportDimensionAni = CreateAniArrayIntFromStdVector(env, formInfo.supportDimensions);
    if (supportDimensionAni != nullptr) {
        env->Object_SetPropertyByName_Ref(formInfoAni, "supportDimensions", supportDimensionAni);
    }
    ani_array supportedShapesAni = CreateAniArrayIntFromStdVector(env, formInfo.supportShapes);
    if (supportedShapesAni != nullptr) {
        env->Object_SetPropertyByName_Ref(formInfoAni, "supportedShapes", supportedShapesAni);
    }
    std::vector<int32_t> formPreviewImagesIntAni(formInfo.formPreviewImages.begin(), formInfo.formPreviewImages.end());
    ani_array formPreviewImagesAni = CreateAniArrayIntFromStdVector(env, formPreviewImagesIntAni);
    if (formPreviewImagesAni != nullptr) {
        env->Object_SetPropertyByName_Ref(formInfoAni, "previewImages", formPreviewImagesAni);
    }
    ani_object record{};
    if (CreateFormCustomizeDataRecord(env, record, formInfo.customizeDatas)) {
        env->Object_SetPropertyByName_Ref(formInfoAni, "customizeData", record);
    }
}

void SetFormInfoFunInteractionParams(ani_env *env, ani_object formInfoAni,
    const AppExecFwk::FormFunInteractionParams &funInteractionParams)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    ani_object funInteractionParamsAni = FormAniUtil::CreateAniObject(env, ETS_FUNINTERACTIONPARAMS_NAME);
    if (funInteractionParamsAni == nullptr) {
        HILOG_ERROR("Cannot create funInteractionParams object");
        return;
    }
    SetStringProperty(env, funInteractionParamsAni, "abilityName", funInteractionParams.abilityName);
    SetStringProperty(env, funInteractionParamsAni, "targetBundleName", funInteractionParams.targetBundleName);
    SetStringProperty(env, funInteractionParamsAni, "subBundleName", funInteractionParams.subBundleName);
    env->Object_SetPropertyByName_Int(funInteractionParamsAni, "keepStateDuration",
        funInteractionParams.keepStateDuration);
    env->Object_SetPropertyByName_Ref(formInfoAni, "funInteractionParams", funInteractionParamsAni);
}

void SetFormInfoSceneAnimationParams(ani_env *env, ani_object formInfoAni,
    const AppExecFwk::FormSceneAnimationParams &formSceneAnimationParams)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    ani_object sceneAnimationParamsAni = FormAniUtil::CreateAniObject(env, ETS_SCENEANIMATIONPARAMS_NAME);
    if (sceneAnimationParamsAni == nullptr) {
        HILOG_ERROR("Cannot create sceneAnimationParams object");
        return;
    }
    SetStringProperty(env, sceneAnimationParamsAni, "abilityName", formSceneAnimationParams.abilityName);
    SetStringProperty(env, sceneAnimationParamsAni, "disabledDesktopBehaviors",
        formSceneAnimationParams.disabledDesktopBehaviors);
    env->Object_SetPropertyByName_Ref(formInfoAni, "sceneAnimationParams", sceneAnimationParamsAni);
}

ani_object WrapBusinessError(ani_env *env, const std::string &msg)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }

    ani_status status = ANI_ERROR;
    ani_string aniMsg = nullptr;
    ani_ref undefRef = nullptr;
    ani_class cls = nullptr;
    ani_method method = nullptr;
    ani_object obj = nullptr;

    status = env->String_NewUTF8(msg.c_str(), msg.size(), &aniMsg);
    if (status != ANI_OK) {
        HILOG_ERROR("String_NewUTF8 failed, status: %{public}d", status);
        return nullptr;
    }

    status = env->GetUndefined(&undefRef);
    if (status != ANI_OK) {
        HILOG_ERROR("GetUndefined failed, status: %{public}d", status);
        return nullptr;
    }

    status = env->FindClass(CLASSNAME_ERROR, &cls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed, status: %{public}d", status);
        return nullptr;
    }

    status = env->Class_FindMethod(cls, "<ctor>", "C{std.core.String}C{escompat.ErrorOptions}:", &method);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed, status: %{public}d", status);
        return nullptr;
    }

    status = env->Object_New(cls, method, &obj, aniMsg, undefRef);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New failed, status: %{public}d", status);
        return nullptr;
    }

    return obj;
}

ani_object CreateBusinessError(ani_env *env, ani_int code, const std::string& msg)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return nullptr;
    }
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = env->FindClass("@ohos.base.BusinessError", &cls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed %{public}d", status);
        return nullptr;
    }
    status = env->Class_FindMethod(cls, "<ctor>", "iC{escompat.Error}:", &method);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed %{public}d", status);
        return nullptr;
    }
    ani_object error = WrapBusinessError(env, msg);
    if (error == nullptr) {
        HILOG_ERROR("error nulll");
        return nullptr;
    }
    status = env->Object_New(cls, method, &obj, code, error);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New failed %{public}d", status);
        return nullptr;
    }
    return obj;
}

int ConvertStringToInt(const std::string &strInfo)
{
    return static_cast<int>(strtoll(strInfo.c_str(), nullptr, BASE_REQUEST_CODE_NUM));
}
} // anonymous namespace

namespace FormAniUtil {

ani_object CreateAniObject(ani_env* env, const char *className)
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

bool SetPropertyStringByName(ani_env* env, ani_object object, const char *name, std::string string)
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
    ani_object obj = CreateBool(env, static_cast<ani_boolean>(value));
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

std::string AniStringToStdString(ani_env *env, ani_string aniStr)
{
    HILOG_INFO("Call AniStringToStdString");
    ani_size strSize;
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return "";
    }
    if (env->String_GetUTF8Size(aniStr, &strSize) != ANI_OK) {
        HILOG_ERROR("String_GetUTF8Size failed");
        return "";
    }

    std::vector<char> buffer(strSize + 1);
    char *utf8Buffer = buffer.data();
    ani_size bytesWritten = 0;
    if (env->String_GetUTF8(aniStr, utf8Buffer, strSize + 1, &bytesWritten) != ANI_OK) {
        HILOG_ERROR("String_GetUTF8 failed");
        return "";
    }

    utf8Buffer[bytesWritten] = '\0';
    std::string content = std::string(utf8Buffer, bytesWritten);
    HILOG_INFO("End AniStringToStdString");
    return content;
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

bool ConvertStringToInt64(const std::string &strInfo, int64_t &int64Value)
{
    size_t strLength = strInfo.size();
    if (strLength == ZERO_VALUE) {
        int64Value = ZERO_VALUE;
        return true;
    }

    const std::regex pattern("^0|-?[1-9][0-9]{0,18}$");
    std::smatch match;
    if (regex_match(strInfo, match, pattern)) {
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
        auto checkResult = std::from_chars(newStrInfo.data(), newStrInfo.data() + newStrInfo.size(), subValue);
        if (checkResult.ec != std::errc()) {
            return false;
        }
        if (subValue <= (INT64_MAX - HEAD_BIT_NUM + 1)) {
            auto result = std::from_chars(strInfo.data(), strInfo.data() + strLength, int64Value);
            return result.ec == std::errc();
        }
    }
    HILOG_DEBUG("regex_match failed");
    return false;
}

bool AsyncCallback(ani_env *env, const char *className, ani_object call, ani_object error, ani_object result)
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

bool CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
}

ani_env *GetEnvFromVm(ani_vm *vm)
{
    ani_env *env = nullptr;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        HILOG_ERROR("Unsupported ANI_VERSION_1");
        return nullptr;
    }
    return env;
}

ani_object CreateBool(ani_env *env, ani_boolean value)
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

ani_object CreateInt(ani_env *env, ani_int value)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }

    ani_class cls = nullptr;
    ani_method ctor = nullptr;
    ani_object object = nullptr;
    ani_status status = ANI_ERROR;

    status = env->FindClass("std.core.Int", &cls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed, status: %{public}d", status);
        return nullptr;
    }

    status = env->Class_FindMethod(cls, "<ctor>", "i:", &ctor);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed, status: %{public}d", status);
        return nullptr;
    }

    status = env->Object_New(cls, ctor, &object, value);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New failed, status: %{public}d", status);
        return nullptr;
    }

    return object;
}

ani_object CreateFormInfoAniArrayFromVec(ani_env *env, const std::vector<AppExecFwk::FormInfo> &formInfos)
{
    ani_object array = GetAniArray(env, formInfos.size());
    if (array == nullptr) {
        HILOG_ERROR("GetAniArray failed");
        return nullptr;
    }

    ani_size index = 0;
    for (auto formInfo : formInfos) {
        ani_object formInfoAni = CreateAniObject(env, FORM_INFO_INNER_CLASS_NAME);
        if (formInfoAni == nullptr) {
            HILOG_ERROR("CreateAniObject failed");
            return nullptr;
        }
        SetFormInfoFields(env, formInfoAni, formInfo);
        ani_status status = env->Object_CallMethodByName_Void(array, ANI_SETTER_MARKER, "iY:",
            index, formInfoAni);
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethodByName_Void $_set Failed. status code: %{public}d", status);
            break;
        }
        index++;
    }
    return array;
}

ani_object CreateFormStateInfo(ani_env *env, int32_t state, Want want)
{
    ani_object returnObject = FormAniUtil::CreateAniObject(env, FORM_STATE_INFO_CLASS_NAME);
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }

    if (returnObject == nullptr) {
        HILOG_INFO("Cannot create FormStateInfoInner object");
        return nullptr;
    }
    ani_enum formState;
    ani_status status = env->FindEnum(FORM_STATE_CLASS_NAME, &formState);
    if (status != ANI_OK) {
        HILOG_INFO("Cannot find FormState enum");
        return nullptr;
    }

    ani_enum_item item;
    status = env->Enum_GetEnumItemByIndex(formState, static_cast<ani_size>(((int)state) + 1), &item);
    if (status != ANI_OK) {
        HILOG_INFO("Cannot get enum item");
        return nullptr;
    }

    ani_object wantAni = AppExecFwk::WrapWant(env, want);
    if (wantAni == nullptr) {
        HILOG_INFO("Cannot create want object");
        return nullptr;
    }

    status = env->Object_SetPropertyByName_Ref(returnObject, "want", static_cast<ani_ref>(wantAni));
    if (status != ANI_OK) {
        HILOG_INFO("Cannot set want param %{public}d", status);
        return nullptr;
    }

    status = env->Object_SetPropertyByName_Ref(returnObject, "formState", static_cast<ani_ref>(item));
    if (status != ANI_OK) {
        HILOG_INFO("Cannot set formState param %{public}d", status);
        return nullptr;
    }
    return returnObject;
}

ani_object GetAniArray(ani_env *env, size_t array_size)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }
    ani_class arrayCls = GetAniClass(env, CLASSNAME_ARRAY);
    ani_method arrayCtor;
    ani_status status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        HILOG_ERROR("FindMethod failed");
        return nullptr;
    }

    ani_object arrayObj;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, array_size);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New Array failed");
        return arrayObj;
    }
    return arrayObj;
}

ani_object NewRecordClass(ani_env *env)
{
    HILOG_INFO("Call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return nullptr;
    }
    ani_object recordObj = {};
    ani_class recordCls;
    ani_status status = env->FindClass(CLASSNAME_RECORD, &recordCls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass status = %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return nullptr;
    }

    ani_method ctor;
    status = env->Class_FindMethod(recordCls, "<ctor>", nullptr, &ctor);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_FindMethod status = %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return nullptr;
    }

    status = env->Object_New(recordCls, ctor, &recordObj);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New status = %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return nullptr;
    }
    HILOG_INFO("End");
    return recordObj;
}

ani_status GetEnumValueInt(ani_env *env, ani_object obj, ani_int &enumValue)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return ANI_ERROR;
    }
    HILOG_INFO("Call GetEnumValueInt");
    ani_size enumIndex = 0;
    ani_status enumIndexStatus = env->EnumItem_GetIndex(static_cast<ani_enum_item>(obj),
        &enumIndex);
    if (enumIndexStatus != ANI_OK) {
        HILOG_ERROR("EnumItem_GetIndex failed");
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return ANI_ERROR;
    }

    ani_enum aniEnum;
    ani_status aniEnumStatus = env->EnumItem_GetEnum(static_cast<ani_enum_item>(obj), &aniEnum);
    if (aniEnumStatus != ANI_OK) {
        HILOG_ERROR("EnumItem_GetEnum failed");
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return ANI_ERROR;
    }

    ani_enum_item aniEnumItem;
    ani_status aniEnumItemStatus = env->Enum_GetEnumItemByIndex(static_cast<ani_enum>(aniEnum),
        enumIndex, &aniEnumItem);
    if (aniEnumItemStatus != ANI_OK) {
        HILOG_ERROR("Enum_GetEnumItemByIndex failed");
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return ANI_ERROR;
    }

    ani_status enumValueStatus = env->EnumItem_GetValue_Int(aniEnumItem, &enumValue);
    if (enumValueStatus != ANI_OK) {
        HILOG_ERROR("EnumItem_GetValue_Int failed");
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return ANI_ERROR;
    }

    HILOG_INFO("End GetEnumValueInt");
    return ANI_OK;
}

bool AniParseIntArray(ani_env *env, const ani_array &array, std::vector<int32_t> &out)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return false;
    }
    ani_size size;
    ani_status status = env->Array_GetLength(array, &size);
    if (status != ANI_OK) {
        HILOG_ERROR("Array_GetLength failed!");
        return false;
    }

    for (ani_size i = 0; i < size; ++i) {
        ani_ref elementRef;
        status = env->Array_Get(array, i, &elementRef);
        if (status != ANI_OK) {
            HILOG_ERROR("Array_Get failed at index %{public}zu!", i);
            return false;
        }
        int32_t value;
        if (!AniParseInt32(env, elementRef, value)) {
            return false;
        }
        out.emplace_back(value);
    }
    return true;
}

bool InvokeAsyncCallback(ani_env *env, ani_object obj, ani_object error, ani_object arg)
{
    return AsyncCallback(env, AppExecFwk::Constants::ASYNC_CALLBACK_WRAPPER_CLASS_NAME, obj, error, arg);
}

bool InvokeCallback(ani_env *env, ani_object obj, ani_object arg)
{
    return Callback(env, obj, arg, AppExecFwk::Constants::CALLBACK_WRAPPER_CLASS_NAME);
}

bool IsRefUndefined(ani_env *env, ani_object obj)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return false;
    }
    ani_boolean isUndefined = false;
    env->Reference_IsUndefined(obj, &isUndefined);
    return isUndefined == ANI_TRUE;
}

bool VectorHasNegativeValue(const std::vector<int>& vec)
{
    return std::any_of(vec.begin(), vec.end(), [](int v) {
        return v < 0;
    });
}

int64_t FormIdAniStrtoInt64(ani_env *env, const ani_string &formId)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return INVALID_FORMID;
    }
    HILOG_INFO("Call FormIdAniStrtoInt64");
    std::string stdFormId = AniStringToStdString(env, static_cast<ani_string>(formId));
    if (stdFormId.empty()) {
        HILOG_ERROR("formId AniStringToStdString failed");
        return INVALID_FORMID;
    }

    int64_t formIdNum = INVALID_FORMID;
    if (!ConvertStringToInt64(stdFormId, formIdNum)) {
        HILOG_ERROR("formId ConvertStringToInt64 failed");
        return INVALID_FORMID;
    }

    HILOG_INFO("End FormIdAniStrtoInt64");
    return formIdNum;
}

int64_t SystemTimeMillis() noexcept
{
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<int64_t>(((t.tv_sec) * NANOSECONDS + t.tv_nsec) / MICROSECONDS);
}

void CheckIfRefValidOrThrow(ani_env *env, ani_object obj)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }

    ani_boolean isUndefined = false;
    ani_status status = env->Reference_IsUndefined(reinterpret_cast<ani_ref>(obj), &isUndefined);
    if (status != ANI_OK || isUndefined) {
        HILOG_ERROR("Object reference is not valid");
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
    }
}

void ExtractProxyVector(ani_env *env, std::vector<AppExecFwk::FormDataProxy> &formDataProxies,
    ani_ref proxiesArrayRef)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    size_t formDataProxiesArrayLen = 0;
    env->Array_GetLength(static_cast<ani_array>(proxiesArrayRef), &formDataProxiesArrayLen);

    for (size_t i = 0; i < formDataProxiesArrayLen; i++) {
        ani_ref element;
        if (ANI_OK != env->Object_CallMethodByName_Ref(
            static_cast<ani_array>(proxiesArrayRef), ANI_GETTER_MARKER, "i:Y", &element, (ani_int)i)) {
            HILOG_ERROR("Object_CallMethodByName_Ref failed");
            return;
        }

        ani_ref key;
        ani_ref subscriberId;
        env->Object_GetPropertyByName_Ref(static_cast<ani_object>(element), "key", &key);
        env->Object_GetPropertyByName_Ref(static_cast<ani_object>(element), "subscriberId", &subscriberId);
        std::string stdKey = AniStringToStdString(env, static_cast<ani_string>(key));
        std::string stdSubscriberId  = AniStringToStdString(env, static_cast<ani_string>(subscriberId));
        HILOG_DEBUG("Key is %{public}s subscriberId %{public}s", stdKey.c_str(), stdSubscriberId.c_str());
        AppExecFwk::FormDataProxy fdp(stdKey, stdSubscriberId);
        formDataProxies.push_back(fdp);
    }
}

void InvokeAsyncWithBusinessError(ani_env *env, ani_object obj, int32_t internalErrorCode, ani_object arg)
{
    auto extErrCode = AppExecFwk::FormErrors::GetInstance().QueryExternalErrorCode(internalErrorCode);
    auto errMsg = AppExecFwk::FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(extErrCode);
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }

    ani_boolean isUndefined;
    env->Reference_IsUndefined(obj, &isUndefined);
    auto callbackIsValid = (obj != nullptr) || (isUndefined != ANI_TRUE);

    if ((internalErrorCode != ERR_OK) && !callbackIsValid) {
        AbilityRuntime::EtsErrorUtil::ThrowError(env, extErrCode, errMsg);
        return;
    }

    ani_object errorObject = CreateBusinessError(env, extErrCode, errMsg);
    bool result = InvokeAsyncCallback(env, obj, errorObject, arg);
    if (!result) {
        auto errorCode = static_cast<int>(ERR_APPEXECFWK_FORM_COMMON_CODE);
        auto message = AppExecFwk::FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(errorCode);
        AbilityRuntime::EtsErrorUtil::ThrowError(env, errorCode, message);
        return;
    }
}

void PrepareExceptionAndThrow(ani_env *env, int32_t internalErrorCode)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    auto extErrCode = AppExecFwk::FormErrors::GetInstance().QueryExternalErrorCode(internalErrorCode);
    auto errMsg = AppExecFwk::FormErrors::GetInstance().GetErrorMsgByExternalErrorCode(extErrCode);
    AbilityRuntime::EtsErrorUtil::ThrowError(env, extErrCode, errMsg);
}

void SetFormInfoFields(ani_env *env, ani_object formInfoAni, const AppExecFwk::FormInfo &formInfo)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    // Set nullable boolean properties
    SetPropertyBoolByName(env, formInfoAni, "enableBlurBackground", formInfo.enableBlurBackground);
    SetPropertyBoolByName(env, formInfoAni, "resizable", formInfo.resizable);
    SetPropertyBoolByName(env, formInfoAni, "isStandbySupported", formInfo.standby.isSupported);
    SetPropertyBoolByName(env, formInfoAni, "isStandbyAdapted", formInfo.standby.isAdapted);
    SetPropertyBoolByName(env, formInfoAni, "isPrivacySensitive", formInfo.standby.isPrivacySensitive);
    SetPropertyBoolByName(env, formInfoAni, "isTemplateForm", formInfo.isTemplateForm);
    // Set boolean properties
    SetPropertyBoolByNameValue(env, formInfoAni, "isDefault", formInfo.defaultFlag);
    SetPropertyBoolByNameValue(env, formInfoAni, "formVisibleNotify", formInfo.formVisibleNotify);
    SetPropertyBoolByNameValue(env, formInfoAni, "updateEnabled", formInfo.updateEnabled);
    SetPropertyBoolByNameValue(env, formInfoAni, "isDynamic", formInfo.isDynamic);
    SetPropertyBoolByNameValue(env, formInfoAni, "transparencyEnabled", formInfo.transparencyEnabled);
    // Set enum properties
    SetPropertyIntByName(env, formInfoAni, "renderingMode", static_cast<int>(formInfo.renderingMode));
    SetPropertyIntByName(env, formInfoAni, "type", static_cast<int>(formInfo.type));
    // Set unsigned integer properties
    SetPropertyIntByName(env, formInfoAni, "displayNameId", formInfo.displayNameId);
    SetPropertyIntByName(env, formInfoAni, "descriptionId", formInfo.descriptionId);
    // Set integer properties
    SetPropertyIntByName(env, formInfoAni, "updateDuration", formInfo.updateDuration);
    SetPropertyIntByName(env, formInfoAni, "defaultDimension", formInfo.defaultDimension);
    // Set string properties
    SetStringProperty(env, formInfoAni, "bundleName", formInfo.bundleName);
    SetStringProperty(env, formInfoAni, "moduleName", formInfo.moduleName);
    SetStringProperty(env, formInfoAni, "abilityName", formInfo.abilityName);
    SetStringProperty(env, formInfoAni, "name", formInfo.name);
    SetStringProperty(env, formInfoAni, "displayName", formInfo.displayName);
    SetStringProperty(env, formInfoAni, "description", formInfo.description);
    SetStringProperty(env, formInfoAni, "jsComponentName", formInfo.jsComponentName);
    SetStringProperty(env, formInfoAni, "formConfigAbility", formInfo.formConfigAbility);
    SetStringProperty(env, formInfoAni, "scheduledUpdateTime", formInfo.scheduledUpdateTime);
    SetStringProperty(env, formInfoAni, "groupId", formInfo.groupId);

    SetFormInfoArrayProperties(env, formInfoAni, formInfo);
    SetFormInfoFunInteractionParams(env, formInfoAni, formInfo.funInteractionParams);
    SetFormInfoSceneAnimationParams(env, formInfoAni, formInfo.sceneAnimationParams);
}

void SetRecordKeyValue(ani_env *env, ani_object &recordObject, std::string &key, ani_object &value)
{
    HILOG_DEBUG("Call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    ani_class recordCls;
    ani_status status = env->FindClass(CLASSNAME_RECORD, &recordCls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed status: %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    ani_method setFunc {};
    status = env->Class_FindMethod(recordCls, ANI_SETTER_MARKER, nullptr, &setFunc);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_FindMethod can not find: %{public}s", ANI_SETTER_MARKER);
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    ani_string ani_key {};
    status = env->String_NewUTF8(key.c_str(), key.length(), &ani_key);
    if (status != ANI_OK) {
        HILOG_ERROR("String_NewUTF8 failed, status: %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    status = env->Object_CallMethod_Void(recordObject, setFunc, ani_key, static_cast<ani_ref>(value));
    if (status != ANI_OK) {
        HILOG_ERROR("set key value failed, status: %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }
    HILOG_INFO("End");
}

void SetRunningFormInfoFields(ani_env *env, ani_object formInfoAni, AppExecFwk::RunningFormInfo &formInfo)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    // Set basic integer properties
    env->Object_SetPropertyByName_Int(formInfoAni, "dimension", formInfo.dimension);

    // Set string properties
    SetStringProperty(env, formInfoAni, "formId", std::to_string(formInfo.formId));
    SetStringProperty(env, formInfoAni, "formName", formInfo.formName);
    SetStringProperty(env, formInfoAni, "bundleName", formInfo.bundleName);
    SetStringProperty(env, formInfoAni, "moduleName", formInfo.moduleName);
    SetStringProperty(env, formInfoAni, "abilityName", formInfo.abilityName);
    SetStringProperty(env, formInfoAni, "formDescription", formInfo.description);
    SetStringProperty(env, formInfoAni, "hostBundleName", formInfo.hostBundleName);

    // Set enum properties
    env->Object_SetPropertyByName_Int(formInfoAni, "formLocation", static_cast<int>(formInfo.formLocation));
    env->Object_SetPropertyByName_Int(formInfoAni, "formUsageState", static_cast<int>(formInfo.formUsageState));
    env->Object_SetPropertyByName_Int(formInfoAni, "visibilityType", static_cast<int>(formInfo.formVisiblity));
}

bool ConvertStringArrayToInt64Vector(ani_env *env, const ani_object arrayObj, std::vector<int64_t> &int64Vector)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return false;
    }

    ani_size arrayLength = 0;
    ani_status status = env->Array_GetLength(reinterpret_cast<ani_array>(arrayObj), &arrayLength);
    if (status != ANI_OK) {
        HILOG_ERROR("Array_GetLength failed, status: %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
        return false;
    }

    for (size_t i = 0; i < static_cast<size_t>(arrayLength); i++) {
        ani_ref stringEntryRef;
        status = env->Object_CallMethodByName_Ref(arrayObj, ANI_GETTER_MARKER, "i:Y",
            &stringEntryRef, static_cast<ani_int>(i));
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethodByName_Ref failed, status: %{public}d", status);
            PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
            return false;
        }

        std::string stdFormID = AniStringToStdString(env, static_cast<ani_string>(stringEntryRef));
        int64_t formIdNum = 0;
        if (!ConvertStringToInt64(stdFormID, formIdNum)) {
            HILOG_ERROR("ConvertStringToInt64 failed for entry %zu", i);
            PrepareExceptionAndThrow(env, static_cast<int>(ERR_FORM_EXTERNAL_PARAM_INVALID));
            return false;
        }

        int64Vector.push_back(formIdNum);
    }

    return true;
}

} // namespace FormAniUtil
} // namespace AbilityRuntime
} // namespace OHOS
