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
#include <vector>
#include <cinttypes>
#include <regex>

#include "ani.h"
#include "fms_log_wrapper.h"
#include "js_runtime_utils.h"
#include "form_mgr.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
constexpr int ZERO_VALUE = 0;
constexpr int INT_64_LENGTH = 19;
constexpr int BASE_NUMBER = 9;
constexpr int BASE_REQUEST_CODE_NUM = 10;
constexpr int64_t HEAD_BIT_NUM = 9000000000000000000;

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
        if (strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1) != "-") {  // maximum: 9223372036854775807
            if (strLength < INT_64_LENGTH) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            int maxSubValue = ConvertStringToInt(strInfo.substr(ZERO_VALUE, ZERO_VALUE + 1));
            if (strLength == INT_64_LENGTH && maxSubValue < BASE_NUMBER) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            // Means 0x7FFFFFFFFFFFFFFF remove the first number:(2^63 - 1 - 9 * 10 ^ 19)
            int64_t subValue = std::stoll(strInfo.substr(ZERO_VALUE + 1, INT_64_LENGTH - 1));
            if (strLength == INT_64_LENGTH && subValue <= (INT64_MAX - HEAD_BIT_NUM)) {
                int64Value = std::stoll(strInfo);
                return true;
            }
            return false;
        }
        if (strLength < INT_64_LENGTH + 1) {  // The minimum value: -9223372036854775808
            int64Value = std::stoll(strInfo);
            return true;
        }
        if (strLength == INT_64_LENGTH + 1) {
            int minSubValue = ConvertStringToInt(strInfo.substr(1, 1));
            if (minSubValue < BASE_NUMBER) {
                int64Value = std::stoll(strInfo);
                return true;
            }

            // Means 0x8000000000000000 remove the first number:-(2^63 - 9 * 10 ^ 19)
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

std::string ANIUtils_ANIStringToStdString(ani_env *env, ani_string aniStr)
{
    HILOG_INFO("Call");
    ani_size strSize;
    if (env->String_GetUTF8Size(aniStr, &strSize) != ANI_OK) {
        HILOG_ERROR("String_GetUTF8Size Failed");
        return "";
    }

    std::vector<char> buffer(strSize + 1);
    char *utf8Buffer = buffer.data();

    ani_size bytesWritten = 0;
    if (env->String_GetUTF8(aniStr, utf8Buffer, strSize + 1, &bytesWritten) != ANI_OK) {
        HILOG_ERROR("String_GetUTF8 Failed");
        return "";
    }

    utf8Buffer[bytesWritten] = '\0';
    std::string content = std::string(utf8Buffer, bytesWritten);
    HILOG_INFO("End");
    return content;
}

void SetFormNextRefreshTime([[maybe_unused]] ani_env *env, ani_string formId, ani_int minute)
{
    HILOG_INFO("Call");

    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return;
    }
    ani_boolean isUndefined = false;
    env->Reference_IsUndefined(formId, &isUndefined);
    if (isUndefined) {
        HILOG_ERROR("formId is undefined");
        return;
    }

    std::string stdFormId = ANIUtils_ANIStringToStdString(env, static_cast<ani_string>(formId));
    if (stdFormId.empty()) {
        HILOG_ERROR("ANIUtils_ANIStringToStdString convert failed");
        return;
    }

    int64_t formIdNum;
    if (!ConvertStringToInt64(stdFormId, formIdNum)) {
        HILOG_ERROR("ConvertStringToInt64 failed");
        return;
    }
    HILOG_INFO("stdFormId: %{public}s, formIdNum: %{public}" PRId64, stdFormId.c_str(), formIdNum);

    int32_t ret = FormMgr::GetInstance().SetNextRefreshTime(formIdNum, minute);
    if (ret != 0) {
        HILOG_ERROR("SetNextRefreshTime failed");
        return;
    }
    HILOG_INFO("End");
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    HILOG_INFO("Call");
    if (vm == nullptr || result == nullptr) {
        HILOG_ERROR("vm or result is nullptr");
        return ANI_ERROR;
    }

    ani_env *env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        HILOG_ERROR("Unsupported ANI_VERSION_1");
        return ANI_OUT_OF_REF;
    }

    if (env == nullptr) {
        HILOG_ERROR("env is nullptr");
        return ANI_ERROR;
    }

    const char *spaceName = "@ohos.app.form.formProvider.formProvider";
    ani_namespace spc;

    ani_status ret = env->FindNamespace(spaceName, &spc);
    if (ret != ANI_OK) {
        HILOG_ERROR("Not found %{public}s, ret = %{public}d", spaceName, ret);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function{
            "setFormNextRefreshTime_inner", "C{std.core.String}i:", reinterpret_cast<void *>(SetFormNextRefreshTime)},
    };

    if (env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size()) != ANI_OK) {
        HILOG_ERROR("Cannot bind native methods to %{public}s ", spaceName);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    HILOG_INFO("End");
    return ANI_OK;
}
}
}  // namespace AbilityRuntime
}  // namespace OHOS
