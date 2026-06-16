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

#ifndef OHOS_FORM_FWK_ANI_FORM_COMMON_UTIL_H
#define OHOS_FORM_FWK_ANI_FORM_COMMON_UTIL_H

#include <string>
#include <vector>
#include <cinttypes>
#include <regex>
#include <climits>
#include "ani.h"
#include "ani_common_want.h"
#include "form_errors.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "form_instance.h"
#include "running_form_info.h"
#include "form_instances_filter.h"
#include "fms_log_wrapper.h"
#include "ets_error_utils.h"
#include "ani_form_error_util.h"

namespace OHOS {
namespace AbilityRuntime {
namespace FormAniUtil {

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

// Constants
constexpr int64_t INVALID_FORMID = -1;
constexpr const char *ANI_SETTER_MARKER = "$_set";
constexpr const char *ANI_GETTER_MARKER = "$_get";
constexpr const char *ANI_SET_SIGNATURE = "iY:";

// ============================================================================
// Type Conversion Functions
// ============================================================================

bool ConvertStringToInt64(const std::string &strInfo, int64_t &int64Value);
std::string AniStringToStdString(ani_env *env, ani_string aniStr);
bool GetStdString(ani_env *env, ani_string str, std::string &value);
ani_string GetAniString(ani_env *env, const std::string &str);

// ============================================================================
// Object Creation Functions
// ============================================================================

ani_object CreateAniObject(ani_env* env, const char *className);
ani_object CreateBool(ani_env *env, ani_boolean value);
ani_object CreateInt(ani_env *env, ani_int value);
ani_object GetAniArray(ani_env *env, size_t array_size);
ani_object NewRecordClass(ani_env *env);

// ============================================================================
// Property Setting Functions
// ============================================================================

bool SetPropertyStringByName(ani_env* env, ani_object object, const char *name, std::string string);
void SetPropertyBoolByName(ani_env *env, ani_object object, const char *name, bool value);
void SetPropertyBoolByNameValue(ani_env *env, ani_object object, const char *name, bool value);
void SetPropertyDoubleByName(ani_env *env, ani_object object, const char *name, double value);
bool SetPropertyIntByName(ani_env *env, ani_object object, const char *name, int32_t value);
void SetPropertyByName(ani_env *env, ani_object object, const char *name, ani_object value);
void SetRecordKeyValue(ani_env *env, ani_object &recordObject, std::string &key, ani_object &value);

// ============================================================================
// Property Getting Functions
// ============================================================================

bool GetStringProperty(ani_env *env, ani_object param, const char *name, std::string &value);
bool GetPropertyDoubleObject(ani_env *env, ani_object param, const char *name, double &value);
bool GetPropertyIntObject(ani_env *env, ani_object param, const char *name, int32_t &value);
bool GetPropertyBoolByName(ani_env *env, ani_object object, const char *name, bool &value);
bool AniParseIntArray(ani_env *env, const ani_array &array, std::vector<int32_t> &out);

// ============================================================================
// Parsing Functions
// ============================================================================

bool ConvertStringArrayToInt64Vector(ani_env *env, const ani_object arrayObj, std::vector<int64_t> &int64Vector);
void ExtractProxyVector(ani_env *env, std::vector<AppExecFwk::FormDataProxy> &formDataProxies,
    ani_ref proxiesArrayRef);
bool ParseProviderFilter(ani_env *env, ani_object aniProviderFilter, AppExecFwk::FormInstancesFilter &filter);

// ============================================================================
// Form Creation Functions
// ============================================================================

ani_object CreateFormInstances(ani_env *env, const std::vector<AppExecFwk::FormInstance> &formInstances);
ani_object CreateFormInstance(ani_env *env, const AppExecFwk::FormInstance &formInstance);
ani_object CreateRunningFormInfos(ani_env *env, const std::vector<AppExecFwk::RunningFormInfo> &runningFormInfos);
ani_object CreateRunningFormInfo(ani_env *env, const AppExecFwk::RunningFormInfo &runningFormInfo);
ani_object CreateFormInfoAniArrayFromVec(ani_env *env, const std::vector<AppExecFwk::FormInfo> &formInfos);
ani_object CreateFormStateInfo(ani_env *env, int32_t state, Want want);

// ============================================================================
// Form Field Setting Functions
// ============================================================================

void SetRunningFormInfoFields(ani_env *env, ani_object formInfoAni, AppExecFwk::RunningFormInfo &formInfo);
void SetFormInfoFields(ani_env *env, ani_object formInfoAni, const AppExecFwk::FormInfo &formInfo);

// ============================================================================
// Callback Functions
// ============================================================================

bool AsyncCallback(ani_env *env, const char *className, ani_object call, ani_object error, ani_object result);
bool Callback(ani_env *env, ani_object call, ani_object result, const char *name);
bool InvokeAsyncCallback(ani_env *env, ani_object obj, ani_object error, ani_object arg);
bool InvokeCallback(ani_env *env, ani_object obj, ani_object arg);
void InvokeAsyncWithBusinessError(ani_env *env, ani_object obj, int32_t internalErrorCode, ani_object arg);

// ============================================================================
// Validation and Check Functions
// ============================================================================

void CheckIfRefValidOrThrow(ani_env *env, ani_object obj);
bool IsRefUndefined(ani_env *env, ani_object obj);
bool VectorHasNegativeValue(const std::vector<int>& vec);
bool CheckCallerIsSystemApp();

// ============================================================================
// ANI Helper Functions
// ============================================================================

int64_t SystemTimeMillis() noexcept;
void PrepareExceptionAndThrow(ani_env *env, int32_t internalErrorCode);
int64_t FormIdAniStrtoInt64(ani_env *env, const ani_string &formId);
ani_status GetEnumValueInt(ani_env *env, ani_object obj, ani_int &enumValue);
ani_env *GetEnvFromVm(ani_vm *vm);

} // namespace FormAniUtil
} // namespace AbilityRuntime
} // namespace OHOS
#endif /* OHOS_FORM_FWK_ANI_FORM_COMMON_UTIL_H */
