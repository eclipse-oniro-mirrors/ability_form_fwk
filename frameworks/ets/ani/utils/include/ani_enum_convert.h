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
#ifndef OHOS_ABILITY_BASE_ANI_ENUM_CONVERT_UTILS_H
#define OHOS_ABILITY_BASE_ANI_ENUM_CONVERT_UTILS_H
#include <string>
#include "fms_log_wrapper.h"
#include "ani.h"
namespace OHOS {
namespace AbilityRuntime {

namespace AniEnumConvertUtil {
//enum convert
[[maybe_unused]] static bool GetStdString(ani_env *env, ani_string str, std::string &res)
{
    ani_size sz {};
    ani_status status = ANI_ERROR;
    if ((status = env->String_GetUTF8Size(str, &sz)) != ANI_OK) {
        HILOG_ERROR("status : %{public}d", status);
        return false;
    }
    res.resize(sz + 1);
    if ((status = env->String_GetUTF8SubString(str, 0, sz, res.data(), res.size(), &sz)) != ANI_OK) {
        HILOG_ERROR("status : %{public}d", status);
        return false;
    }
    res.resize(sz);
    return true;
}

template <class T>
static bool EnumConvert_EtsToNative(ani_env *env, ani_enum_item enumItem, T &result)
{
    ani_status status = ANI_ERROR;
    if constexpr (std::is_enum<T>::value || std::is_integral<T>::value) {
        ani_int intValue{};
        status = env->EnumItem_GetValue_Int(enumItem, &intValue);
        if (ANI_OK != status) {
            HILOG_ERROR("EnumConvert_EtsToNative failed, status : %{public}d", status);
            return false;
        }
        result = static_cast<T>(intValue);
        return true;
    } else if constexpr (std::is_same<T, std::string>::value) {
        ani_string strValue{};
        status = env->EnumItem_GetValue_String(enumItem, &strValue);
        if (ANI_OK != status) {
            HILOG_ERROR("EnumItem_GetValue_String failed, status : %{public}d", status);
            return false;
        }
        return GetStdString(env, strValue, result);
    } else {
        HILOG_ERROR("Enum convert failed: type not supported");
        return false;
    }
}

template<class T>
static bool EnumConvert_EtsToNative(ani_env *env, ani_object enumItem, T &result)
{
    return EnumConvert_EtsToNative<T>(env, static_cast<ani_enum_item>(enumItem), result);
}

template <class T>
static bool EnumConvert_NativeToEts(ani_env *env, const char *enumName, const T enumValue, ani_enum_item &result)
{
    ani_enum aniEnum{};
    ani_status status = env->FindEnum(enumName, &aniEnum);
    if (ANI_OK != status) {
        HILOG_ERROR("Enum convert FindEnum failed: %{public}s status: %{public}d", enumName, status);
        return false;
    }
    constexpr int32_t loopMaxNum = 1000;
    for (int32_t index = 0U; index < loopMaxNum; index++) {
        ani_enum_item enumItem{};
        status = env->Enum_GetEnumItemByIndex(aniEnum, index, &enumItem);
        if (ANI_OK != status) {
            HILOG_ERROR(
                "Enum convert Enum_GetEnumItemByIndex failed: enumName:%{public}s index:%{public}d status:%{public}d",
                enumName, index, status);
            return false;
        }
        // compare value
        T tmpValue{};
        if (EnumConvert_EtsToNative<T>(env, enumItem, tmpValue) && tmpValue == enumValue) {
            result = enumItem;
            return true;
        }
    }
    HILOG_ERROR("EnumConvert_NativeToEts failed enumName: %{public}s", enumName);
    return false;
}
}
} // namespace AAFwk
} // namespace OHOS
#endif // OHOS_ABILITY_BASE_ANI_ENUM_CONVERT_UTILS_H