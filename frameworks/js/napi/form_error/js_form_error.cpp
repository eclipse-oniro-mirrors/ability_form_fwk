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
#include "js_form_error.h"

#include "fms_log_wrapper.h"
#include "js_runtime_utils.h"
#include "napi_form_util.h"

namespace OHOS {
namespace AbilityRuntime {
napi_value CreateJsFormError(napi_env env)
{
    napi_value objValue = nullptr;
    napi_create_object(env, &objValue);
    napi_set_named_property(env, objValue, "ERR_COMMON", CreateJsValue(env, ERR_COMMON));
    napi_set_named_property(env, objValue, "ERR_PERMISSION_DENY", CreateJsValue(env, ERR_PERMISSION_DENY));
    napi_set_named_property(env, objValue, "ERR_GET_INFO_FAILED", CreateJsValue(env, ERR_GET_INFO_FAILED));
    napi_set_named_property(env, objValue, "ERR_GET_BUNDLE_FAILED", CreateJsValue(env, ERR_GET_BUNDLE_FAILED));
    napi_set_named_property(env, objValue, "ERR_GET_LAYOUT_FAILED", CreateJsValue(env, ERR_GET_LAYOUT_FAILED));
    napi_set_named_property(env, objValue, "ERR_ADD_INVALID_PARAM", CreateJsValue(env, ERR_ADD_INVALID_PARAM));
    napi_set_named_property(env, objValue, "ERR_CFG_NOT_MATCH_ID", CreateJsValue(env, ERR_CFG_NOT_MATCH_ID));
    napi_set_named_property(env, objValue, "ERR_NOT_EXIST_ID", CreateJsValue(env, ERR_NOT_EXIST_ID));
    napi_set_named_property(env, objValue, "ERR_BIND_PROVIDER_FAILED", CreateJsValue(env, ERR_BIND_PROVIDER_FAILED));
    napi_set_named_property(env, objValue, "ERR_MAX_SYSTEM_FORMS", CreateJsValue(env, ERR_MAX_SYSTEM_FORMS));
    napi_set_named_property(
        env, objValue, "ERR_MAX_INSTANCES_PER_FORM", CreateJsValue(env, ERR_MAX_INSTANCES_PER_FORM));
    napi_set_named_property(
        env, objValue, "ERR_OPERATION_FORM_NOT_SELF", CreateJsValue(env, ERR_OPERATION_FORM_NOT_SELF));
    napi_set_named_property(env, objValue, "ERR_PROVIDER_DEL_FAIL", CreateJsValue(env, ERR_PROVIDER_DEL_FAIL));
    napi_set_named_property(env, objValue, "ERR_MAX_FORMS_PER_CLIENT", CreateJsValue(env, ERR_MAX_FORMS_PER_CLIENT));
    napi_set_named_property(env, objValue, "ERR_MAX_SYSTEM_TEMP_FORMS", CreateJsValue(env, ERR_MAX_SYSTEM_TEMP_FORMS));
    napi_set_named_property(env, objValue, "ERR_FORM_NO_SUCH_MODULE", CreateJsValue(env, ERR_FORM_NO_SUCH_MODULE));
    napi_set_named_property(env, objValue, "ERR_FORM_NO_SUCH_ABILITY", CreateJsValue(env, ERR_FORM_NO_SUCH_ABILITY));
    napi_set_named_property(
        env, objValue, "ERR_FORM_NO_SUCH_DIMENSION", CreateJsValue(env, ERR_FORM_NO_SUCH_DIMENSION));
    napi_set_named_property(env, objValue, "ERR_FORM_FA_NOT_INSTALLED", CreateJsValue(env, ERR_FORM_FA_NOT_INSTALLED));
    napi_set_named_property(
        env, objValue, "ERR_SYSTEM_RESPONSES_FAILED", CreateJsValue(env, ERR_SYSTEM_RESPONSES_FAILED));
    napi_set_named_property(env, objValue, "ERR_FORM_DUPLICATE_ADDED", CreateJsValue(env, ERR_FORM_DUPLICATE_ADDED));
    napi_set_named_property(
        env, objValue, "ERR_DISTRIBUTED_SCHEDULE_FAILED", CreateJsValue(env, ERR_DISTRIBUTED_SCHEDULE_FAILED));
    napi_set_named_property(env, objValue, "ERR_IN_RECOVERY", CreateJsValue(env, ERR_IN_RECOVERY));
    return objValue;
}

napi_value FormErrorInit(napi_env env, napi_value exportObj)
{
    HILOG_INFO("%{public}s called.", __func__);

    napi_set_named_property(env, exportObj, "FormError", CreateJsFormError(env));

    HILOG_INFO("%{public}s called end.", __func__);
    return exportObj;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
