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
 
#include "ani_helpers.h"

namespace OHOS {
namespace AbilityRuntime {
namespace FormAniHelpers {

int ConvertStringToInt(const std::string &strInfo)
{
    return static_cast<int>(strtoll(strInfo.c_str(), nullptr, BASE_REQUEST_CODE_NUM));
}

ani_object createInt(ani_env *env, int32_t value)
{
    ani_class cls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("std.core.Int", &cls)) != ANI_OK) {
        HILOG_ERROR("FindClass status : %{public}d", status);
        return nullptr;
    }
    ani_method ctor;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "i:", &ctor)) != ANI_OK) {
        HILOG_ERROR("Class_FindMethod status : %{public}d", status);
        return nullptr;
    }
    ani_object object;
    if ((status = env->Object_New(cls, ctor, &object, value)) != ANI_OK) {
        HILOG_ERROR("Object_New status : %{public}d", status);
        return nullptr;
    }
    return object;
}

bool ConvertStringToInt64(const std::string &strInfo, int64_t &int64Value)
{
    size_t strLength = strInfo.size();
    if (strLength == ZERO_VALUE) {
        int64Value = ZERO_VALUE;
        return true;
    }
    std::regex pattern("^0|-?[1-9][0-9]{0,18}$");
    std::smatch match;
    if (regex_match(strInfo, match, pattern)) {
        if (strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1) != "-") {
            if (strLength < INT_64_LENGTH) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            int maxSubValue = ConvertStringToInt(strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1));
            if (strLength == INT_64_LENGTH && maxSubValue < BASE_NUMBER) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            int64_t subValue = std::stoll(strInfo.substr(ZERO_VALUE + 1, INT_64_LENGTH - 1));
            if (strLength == INT_64_LENGTH && subValue <= (INT64_MAX - HEAD_BIT_NUM)) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            return false;
        }
        if (strLength < INT_64_LENGTH + 1) {
            int64Value = std::stoll(strInfo);
            return true;
        }
        if (strLength == INT_64_LENGTH + 1) {
            int minSubValue = ConvertStringToInt(strInfo.substr(1, 1));
            if (minSubValue < BASE_NUMBER) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            int64_t subValue = std::stoll(strInfo.substr(ZERO_VALUE + 2, INT_64_LENGTH - 1));
            if (subValue <= (INT64_MAX - HEAD_BIT_NUM + 1)) {
                int64Value = std::stoll(strInfo);
                return true;
            }
        }
    }
    HILOG_DEBUG("regex_match failed");
    return false;
}

int64_t SystemTimeMillis() noexcept
{
    struct timespec t;
    t.tv_sec = 0;
    t.tv_nsec = 0;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<int64_t>(((t.tv_sec) * NANOSECONDS + t.tv_nsec) / MICROSECONDS);
}

void PrepareExceptionAndThrow(ani_env *env, int32_t internalErrorCode)
{
    auto extErrCode = AppExecFwk::FormErrors::GetInstance().QueryExternalErrorCode(internalErrorCode);
    auto errMsg = AppExecFwk::FormErrors::GetInstance().GetErrorMessage(extErrCode);
    AbilityRuntime::EtsErrorUtil::ThrowError(env, extErrCode, errMsg);
}

std::string ANIUtils_ANIStringToStdString(ani_env *env, ani_string aniStr)
{
    HILOG_INFO("Call ANIUtils_ANIStringToStdString");
    ani_size strSize;
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
    HILOG_INFO("End ANIUtils_ANIStringToStdString");
    return content;
}

void ExtractProxyVector(ani_env *env, std::vector<AppExecFwk::FormDataProxy> &formDataProxies,
    ani_ref proxiesArrayRef)
{
    size_t formDataProxiesArrayLen = 0;
    env->Array_GetLength(static_cast<ani_array>(proxiesArrayRef), &formDataProxiesArrayLen);
    for (size_t i = 0; i < formDataProxiesArrayLen; i++) {
        HILOG_INFO("Iterating proxies");

        ani_ref element;
        if (ANI_OK != env->Object_CallMethodByName_Ref(
            static_cast<ani_array>(proxiesArrayRef), ANI_GETTER_MARKER, "i:C{std.core.Object}", &element, (ani_int)i)) {
            HILOG_ERROR("Object_CallMethodByName_Ref failed");
            return;
        }

        ani_ref key;
        ani_ref subscriberId;
        env->Object_GetPropertyByName_Ref(static_cast<ani_object>(element), "key", &key);
        env->Object_GetPropertyByName_Ref(static_cast<ani_object>(element), "subscriberId", &subscriberId);
        std::string stdKey = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(key));
        std::string stdSubscriberId  = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(subscriberId));
        HILOG_DEBUG("Key is %{public}s subscriberId %{public}s", stdKey.c_str(), stdSubscriberId.c_str());
        AppExecFwk::FormDataProxy fdp(stdKey, stdSubscriberId);
        formDataProxies.push_back(fdp);
    }
}

int64_t FormIdAniStrtoInt64(ani_env *env, ani_string formId)
{
    HILOG_INFO("Call FormIdAniStrtoInt64");

    std::string stdFormId = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(formId));
    if (stdFormId.empty()) {
        HILOG_ERROR("formId ANIUtils_ANIStringToStdString failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return INVALID_FORMID;
    }

    int64_t formIdNum = INVALID_FORMID;
    if (!ConvertStringToInt64(stdFormId, formIdNum)) {
        HILOG_ERROR("formId ConvertStringToInt64 failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return INVALID_FORMID;
    }

    HILOG_INFO("End FormIdAniStrtoInt64");
    return formIdNum;
}

ani_status GetEnumValueInt(ani_env *env, ani_object obj, ani_int &enumValue)
{
    HILOG_INFO("Call GetEnumValueInt");

    ani_size enumIndex = 0;
    ani_status enumIndexStatus = env->EnumItem_GetIndex(static_cast<ani_enum_item>(obj),
        &enumIndex);
    if (enumIndexStatus != ANI_OK) {
        HILOG_ERROR("EnumItem_GetIndex failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return ANI_ERROR;
    }

    ani_enum aniEnum;
    ani_status aniEnumStatus = env->EnumItem_GetEnum(static_cast<ani_enum_item>(obj), &aniEnum);
    if (aniEnumStatus != ANI_OK) {
        HILOG_ERROR("EnumItem_GetEnum failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return ANI_ERROR;
    }

    ani_enum_item aniEnumItem;
    ani_status aniEnumItemStatus = env->Enum_GetEnumItemByIndex(static_cast<ani_enum>(aniEnum),
        enumIndex, &aniEnumItem);
    if (aniEnumItemStatus != ANI_OK) {
        HILOG_ERROR("Enum_GetEnumItemByIndex failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return ANI_ERROR;
    }

    ani_status enumValueStatus = env->EnumItem_GetValue_Int(aniEnumItem, &enumValue);
    if (enumValueStatus != ANI_OK) {
        HILOG_ERROR("EnumItem_GetValue_Int failed");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return ANI_ERROR;
    }

    HILOG_INFO("End GetEnumValueInt");
    return ANI_OK;
}

void SetStringProperty(ani_env *env, ani_object obj, const char *propName, const std::string &value)
{
    ani_string anistr{};
    env->String_NewUTF8(value.c_str(), value.size(), &anistr);
    env->Object_SetPropertyByName_Ref(obj, propName, anistr);
}

bool AniParseInt32(ani_env *env, const ani_ref &aniInt, int32_t &out)
{
    ani_int tmp;
    ani_status status;
    if ((status = env->Object_CallMethodByName_Int(
        static_cast<ani_object>(aniInt), "toInt", nullptr, &tmp)) != ANI_OK) {
        HILOG_ERROR("Object_CallMethodByName_Int failed! %{public}d", status);
        return false;
    }
    out = static_cast<int32_t>(tmp);
    return true;
}


bool AniParseIntArray(ani_env *env, const ani_array &array, std::vector<int32_t> &out)
{
    ani_size size;
    if (env->Array_GetLength(array, &size) != ANI_OK) {
        HILOG_ERROR("Array_GetLength failed!");
        return false;
    }

    for (ani_size i = 0; i < size; ++i) {
        ani_ref elementRef;
        if (env->Array_Get(array, i, &elementRef) != ANI_OK) {
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

bool CreateFormCustomizeDataRecord(ani_env *env, ani_object &recordObject,
    const std::vector<AppExecFwk::FormCustomizeData> &customizeData)
{
    ani_status status = ANI_OK;
    ani_class recordCls;
    status = env->FindClass("escompat.Record", &recordCls);
    if (status != ANI_OK) {
        HILOG_ERROR("Find record class failed status: %{public}d", status);
        return false;
    }
    
    ani_method objectMethod;
    if ((status = env->Class_FindMethod(recordCls, "<ctor>", nullptr, &objectMethod)) != ANI_OK) {
        HILOG_ERROR("Class_FindMethod constructor failed: %{public}d", status);
        return false;
    }

    if ((status = env->Object_New(recordCls, objectMethod, &recordObject)) != ANI_OK) {
        HILOG_ERROR("Object_New failed: %{public}d", status);
        return false;
    }

    ani_method setFunc {};
    if (env->Class_FindMethod(recordCls, ANI_SETTER_MARKER, nullptr, &setFunc) != ANI_OK) {
        HILOG_ERROR("Get set method failed Lescompat/Record;");
        return false;
    }

    for (const auto &iter : customizeData) {
        std::string key = iter.name;
        ani_string ani_key{};
        if ((status = env->String_NewUTF8(key.c_str(), key.length(), &ani_key)) != ANI_OK) {
            HILOG_ERROR("String_NewUTF8 key failed status : %{public}d", status);
            return false;
        }
        std::string strvalue = iter.value;
        ani_string value{};
        if ((status = env->String_NewUTF8(strvalue.c_str(), strvalue.length(), &value)) != ANI_OK) {
            HILOG_ERROR("String_NewUTF8 value failed status : %{public}d", status);
            return false;
        }
        if (ANI_OK != (status = env->Object_CallMethod_Void(recordObject, setFunc, ani_key, (ani_ref)value))) {
            HILOG_ERROR("set key value faild. key: %{public}s value %{public}s status %{public}d",
                iter.name.c_str(), iter.value.c_str(), status);
            return false;
        }
    }
    return true;
}

ani_array CreateAniArrayIntFromStdVector(ani_env *env, std::vector<int32_t> vec)
{
    ani_array array = nullptr;
    ani_ref undefined_ref;
    if (env->GetUndefined(&undefined_ref) != ANI_OK) {
        HILOG_ERROR("GetUndefined failed");
    }
    
    if (!vec.empty()) {
        env->Array_New(vec.size(), undefined_ref, &array);
        ani_size index = 0;
        for (auto value : vec) {
            ani_object valueAni = createInt(env, value);
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

void SetRunningFormInfoFields(ani_env *env, ani_object formInfoAni, const AppExecFwk::RunningFormInfo &formInfo)
{
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

void SetFormInfoFields(ani_env *env, ani_object formInfoAni, const AppExecFwk::FormInfo &formInfo)
{
    // Set boolean properties
    env->Object_SetPropertyByName_Boolean(formInfoAni, "isDefault", formInfo.defaultFlag);
    env->Object_SetPropertyByName_Boolean(formInfoAni, "formVisibleNotify", formInfo.formVisibleNotify);
    env->Object_SetPropertyByName_Boolean(formInfoAni, "updateEnabled", formInfo.updateEnabled);
    env->Object_SetPropertyByName_Boolean(formInfoAni, "isStatic", formInfo.isStatic);
    env->Object_SetPropertyByName_Boolean(formInfoAni, "isDynamic", formInfo.isDynamic);
    env->Object_SetPropertyByName_Boolean(formInfoAni, "transparencyEnabled", formInfo.transparencyEnabled);
    env->Object_SetPropertyByName_Boolean(formInfoAni, "enableBlurBackground", formInfo.enableBlurBackground);
    // Set enum properties
    env->Object_SetPropertyByName_Int(formInfoAni, "renderingMode", static_cast<int>(formInfo.renderingMode));
    env->Object_SetPropertyByName_Int(formInfoAni, "type", static_cast<int>(formInfo.type));
    // Set unsigned integer properties
    env->Object_SetPropertyByName_Int(formInfoAni, "displayNameId", formInfo.displayNameId);
    env->Object_SetPropertyByName_Int(formInfoAni, "descriptionId", formInfo.descriptionId);
    // Set integer properties
    env->Object_SetPropertyByName_Int(formInfoAni, "updateDuration", formInfo.updateDuration);
    env->Object_SetPropertyByName_Int(formInfoAni, "defaultDimension", formInfo.defaultDimension);
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

ani_object CreateANIObject(ani_env *env, const char *className)
{
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        HILOG_ERROR("FindClass failed");
        return nullptr;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", ":", &ctor)) {
        HILOG_ERROR("Class_FindMethod failed");
        return nullptr;
    }

    ani_object obj = nullptr;
    ani_status status = env->Object_New(cls, ctor, &obj);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_New failed, error code: %{public}d", status);
        return nullptr;
    }

    return obj;
}

void CheckIfRefValidOrThrow(ani_env *env, ani_object obj)
{
    ani_boolean isUndefined = false;
    env->Reference_IsUndefined(obj, &isUndefined);
    if (isUndefined) {
        HILOG_ERROR("Object reference is not valid");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
    }
}

void CheckEnvOrThrow(ani_env *env)
{
    if (env == nullptr) {
        HILOG_ERROR("ani_env is nullptr");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
    }
}

bool ConvertStringArrayToInt64Vector(ani_env *env, const ani_object arrayObj, std::vector<int64_t> &int64Vector)
{
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return false;
    }

    ani_size arrayLength = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Array_GetLength(reinterpret_cast<ani_array>(arrayObj), &arrayLength)) != ANI_OK) {
        HILOG_ERROR("Array get length error");
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return false;
    }

    for (size_t i = 0; i < static_cast<size_t>(arrayLength); i++) {
        ani_ref stringEntryRef;
        if (ANI_OK != env->Object_CallMethodByName_Ref(arrayObj, ANI_GETTER_MARKER, "i:C{std.core.Object}",
            &stringEntryRef, static_cast<ani_int>(i))) {
            HILOG_ERROR("Object_CallMethodByName_Ref failed");
            PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
            return false;
        }

        std::string stdFormID = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(stringEntryRef));
        int64_t formIdNum;
        if (!ConvertStringToInt64(stdFormID, formIdNum)) {
            HILOG_ERROR("ConvertStringToInt64 failed");
            PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
            return false;
        }

        int64Vector.push_back(formIdNum);
    }

    return true;
}

ani_class GetANIClass(ani_env *env, const char *className)
{
    ani_status status = ANI_OK;
    ani_class cls{};
    status = env->FindClass(className, &cls);
    if (status != ANI_OK || cls == nullptr) {
        HILOG_ERROR("FindClass failed, error code: %{public}d", status);
    }
    return cls;
}

ani_ref GetMemberRef(ani_env *env, ani_object object, const char *class_name, const std::string &member)
{
    ani_status status = ANI_OK;
    ani_class cls = GetANIClass(env, class_name);
    ani_method getter{};
    status = env->Class_FindMethod(cls, ("<get>" + member).c_str(), nullptr, &getter);
    if (status != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed, error code: %{public}d", status);
        return nullptr;
    }

    ani_ref ref;
    status = env->Object_CallMethod_Ref(object, getter, &ref);
    if (status != ANI_OK) {
        HILOG_ERROR("Object_CallMethod_Ref failed, error code: %{public}d", status);
        return nullptr;
    }

    return ref;
}

ani_object GetANIArray(ani_env *env, size_t array_size)
{
    ani_class arrayCls = GetANIClass(env, "escompat.Array");
    ani_method arrayCtor;
    if (ANI_OK != env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor)) {
        HILOG_ERROR("FindMethod failed");
        return nullptr;
    }

    ani_object arrayObj;
    if (ANI_OK != env->Object_New(arrayCls, arrayCtor, &arrayObj, array_size)) {
        HILOG_ERROR("Object_New Array failed");
        return arrayObj;
    }
    return arrayObj;
}

void SetRecordKeyValue(ani_env *env, ani_object &recordObject, std::string &key, ani_object &value)
{
    HILOG_DEBUG("Call");
    ani_class recordCls;
    ani_status status = env->FindClass("escompat.Record", &recordCls);
    if (status != ANI_OK) {
        HILOG_ERROR("FindClass failed status: %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    ani_method setFunc {};
    if (env->Class_FindMethod(recordCls, ANI_SETTER_MARKER, nullptr, &setFunc) != ANI_OK) {
        HILOG_ERROR("Class_FindMethod can not find: %{public}s", ANI_SETTER_MARKER);
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    ani_string ani_key{};

    if ((status = env->String_NewUTF8(key.c_str(), key.length(), &ani_key)) != ANI_OK) {
        HILOG_ERROR("String_NewUTF8 failed, status: %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }

    if (ANI_OK != (status = env->Object_CallMethod_Void(
        recordObject, setFunc, ani_key, static_cast<ani_ref>(value)))) {
        HILOG_ERROR("set key value failed, status: %{public}d", status);
        PrepareExceptionAndThrow(env, static_cast<int>(AppExecFwk::ERR_FORM_EXTERNAL_PARAM_INVALID));
        return;
    }
    HILOG_INFO("End");
}

ani_object CreateFormInfoAniArrayFromVec(ani_env *env, const std::vector<AppExecFwk::FormInfo> &formInfos)
{
    ani_object array = GetANIArray(env, formInfos.size());
    ani_size index = 0;
    for (auto formInfo : formInfos) {
        ani_object formInfoAni = CreateANIObject(env, FORM_INFO_INNER_CLASS_NAME);
        CheckIfRefValidOrThrow(env, formInfoAni);
        SetFormInfoFields(env, formInfoAni, formInfo);
        ani_status status = env->Object_CallMethodByName_Void(array, ANI_SETTER_MARKER, "iC{std.core.Object}:",
            index, formInfoAni);
        if (status != ANI_OK) {
            HILOG_ERROR("Object_CallMethodByName_Void  $_set Failed. status code: %{public}d", status);
            break;
        }
        index++;
    }
    return array;
}
}  // namespace FormAniHelpers
}  // namespace AbilityRuntime
}  // namespace OHOS
