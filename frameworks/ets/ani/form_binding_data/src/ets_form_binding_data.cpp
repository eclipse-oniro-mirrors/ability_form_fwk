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

#include "ani.h"
#include "fms_log_wrapper.h"

static ani_object CreateFormBindingData([[maybe_unused]] ani_env *env, ani_object paramObject)
{
    HILOG_INFO("CreateFormBindingData call");
    if (env == nullptr) {
        HILOG_ERROR("env is nullptr ");
        return nullptr;
    }
    ani_status status = ANI_OK;
    ani_class formBindingDataCls;
    if ((status = env->FindClass("@ohos.app.form.formBindingData.formBindingData.FormBindingDataInner",
        &formBindingDataCls)) != ANI_OK) {
        HILOG_ERROR("FindClass failed status %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    ani_method objectMethod;
    if ((status = env->Class_FindMethod(formBindingDataCls, "<ctor>", ":", &objectMethod)) != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed status %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    ani_object formBindingDataObj;
    if ((status = env->Object_New(formBindingDataCls, objectMethod, &formBindingDataObj)) != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed status %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    ani_boolean isUndefined = ANI_FALSE;
    status = env->Reference_IsUndefined(paramObject, &isUndefined);
    if (isUndefined || status != ANI_OK) {
        HILOG_ERROR("createFormBindingData failed %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    ani_class stringClass;
    if ((status = env->FindClass("std.core.String", &stringClass)) != ANI_OK) {
        HILOG_ERROR("FindClass failed status %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    ani_method setMethod;
    if ((status = env->Class_FindMethod(formBindingDataCls, "<set>data", nullptr, &setMethod)) != ANI_OK) {
        HILOG_ERROR("Class_FindMethod failed status %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    if ((status = env->Object_CallMethod_Void(formBindingDataObj, setMethod, paramObject)) != ANI_OK) {
        HILOG_ERROR("Object_CallMethod_Void failed status %{public}d ", static_cast<int>(status));
        return nullptr;
    }
    HILOG_INFO("CreateFormBindingData end");
    return formBindingDataObj;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    HILOG_INFO("ANI_Constructor call");
    if (vm == nullptr || result == nullptr) {
        HILOG_ERROR("vm or result is nullptr ");
        return ANI_ERROR;
    }

    ani_env *env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        HILOG_ERROR("Unsupported ANI_VERSION_1 ");
        return ANI_OUT_OF_REF;
    }

    if (env == nullptr) {
        HILOG_ERROR("env is nullptr ");
        return ANI_ERROR;
    }

    const char *spaceName = "@ohos.app.form.formBindingData.formBindingData";
    ani_namespace spc;
    if (env->FindNamespace(spaceName, &spc) != ANI_OK) {
        HILOG_ERROR("Not found %{public}s ", spaceName);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function { "createFormBindingData", nullptr, reinterpret_cast<void *>(CreateFormBindingData) },
    };

    if (env->Namespace_BindNativeFunctions(spc, methods.data(), methods.size()) != ANI_OK) {
        HILOG_ERROR("Cannot bind native methods to %{public}s ", spaceName);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    HILOG_INFO("ANI_Constructor end");
    return ANI_OK;
}
}