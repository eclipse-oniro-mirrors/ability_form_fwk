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

#include <cstring>

#include "ani_form_common_util.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* CLASSNAME_BOOL = "Lstd/core/Boolean;";
constexpr const char* CLASSNAME_ARRAY = "Lescompat/Array;";

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
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Z:V", &ctor)) != ANI_OK) {
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
    ani_class cls = nullptr;
    ani_status status = env->FindClass(className, &cls);
    if (status != ANI_OK) {
        HILOG_ERROR("find Context failed status: %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    status = env->Class_FindMethod(cls, "<ctor>", ":V", &method);
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

void SetPropertyStringByName(ani_env* env, ani_object object, const char* name, std::string string)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_string aniString = nullptr;
    env->String_NewUTF8(string.c_str(), string.size(), &aniString);
    if ((status = env->Object_SetPropertyByName_Ref(object, name, aniString)) != ANI_OK) {
        HILOG_ERROR("name is: %{public}s SetProperty status: %{public}d", name, status);
        return;
    }
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

void SetPropertyIntByName(ani_env *env, ani_object object, const char *name, int32_t value)
{
    if (env == nullptr) {
        HILOG_ERROR("null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Int(object, name, value)) != ANI_OK) {
        HILOG_ERROR("Object_SetFieldByName_Int status: %{public}d", status);
        return;
    }
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
    status = env->Class_FindMethod(arrayCls, "<ctor>", ":V", &arrayCtor);
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
        reinterpret_cast<ani_object>(field), "unboxed", nullptr, &aniValue)) != ANI_OK) {
        HILOG_ERROR("status: %{public}d", status);
        return false;
    }
    value = static_cast<bool>(aniValue);
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS
