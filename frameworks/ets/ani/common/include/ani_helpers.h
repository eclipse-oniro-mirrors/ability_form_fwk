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

#ifndef FORM_FWK_ANI_HELPERS_H
#define FORM_FWK_ANI_HELPERS_H

#include <string>
#include <vector>
#include <cinttypes>
#include <regex>
#include <climits>

#include "ani.h"
#include "form_errors.h"
#include "form_mgr.h"
#include "fms_log_wrapper.h"
#include "ets_error_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace FormAniHelpers {

constexpr int64_t INVALID_FORMID = -1;
constexpr int ZERO_VALUE = 0;
constexpr int INT_64_LENGTH = 19;
constexpr int BASE_NUMBER = 9;
constexpr int BASE_REQUEST_CODE_NUM = 10;
constexpr int64_t HEAD_BIT_NUM = 9000000000000000000;
static const char* FORM_INFO_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.FormInfo";
static const char* FORM_INFO_INNER_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.formInfoInner";
static const char* RUNNING_FORM_INFO_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.RunningFormInfo";
static const char* RUNNING_FORM_INFO_INNER_CLASS_NAME = "@ohos.app.form.formInfo.formInfo.runningFormInfoInner";
static const char* FORM_BINDING_DATA_CLASS_NAME = "@ohos.app.form.formBindingData.formBindingData.FormBindingData";
static const char* ANI_SETTER_MARKER = "$_set";
static const char* ANI_GETTER_MARKER = "$_get";
constexpr int64_t NANOSECONDS = 1000000000;
constexpr int64_t MICROSECONDS = 1000000;

int ConvertStringToInt(const std::string &strInfo);

ani_object createInt(ani_env *env, ani_int value);

bool ConvertStringToInt64(const std::string &strInfo, int64_t &int64Value);

int64_t SystemTimeMillis() noexcept;

void PrepareExceptionAndThrow(ani_env *env, int32_t internalErrorCode);

std::string ANIUtils_ANIStringToStdString(ani_env *env, ani_string aniStr);

void ExtractProxyVector(ani_env *env, std::vector<AppExecFwk::FormDataProxy> &formDataProxies,
    ani_ref proxiesArrayRef);

int64_t FormIdAniStrtoInt64(ani_env *env, ani_string formId);

ani_status GetEnumValueInt(ani_env *env, ani_object obj, ani_int& enumValue);

void SetStringProperty(ani_env *env, ani_object obj, const char* propName, const std::string& value);

bool AniParseInt32(ani_env* env, const ani_ref& aniInt, int32_t& out);

bool AniParseIntArray(ani_env* env, const ani_array_ref& array, std::vector<int32_t>& out);

bool CreateFormCustomizeDataRecord(ani_env *env, ani_object &recordObject,
    const std::vector<AppExecFwk::FormCustomizeData> &customizeData);

ani_array_ref CreateAniArrayIntFromStdVector(ani_env *env, std::vector<int32_t> vec);

void SetRunningFormInfoFields(ani_env *env, ani_object formInfoAni, const AppExecFwk::RunningFormInfo& formInfo);

void SetFormInfoFields(ani_env* env, ani_object formInfoAni, const AppExecFwk::FormInfo& formInfo);

ani_object CreateANIObject(ani_env *env, const char* className);

void CheckIfRefValidOrThrow(ani_env *env, ani_object obj);

void CheckEnvOrThrow(ani_env* env);

bool ConvertStringArrayToInt64Vector(ani_env *env, const ani_object arrayObj, std::vector<int64_t> &int64Vector);

ani_class GetANIClass(ani_env *env, const char* className);

ani_ref GetMemberRef(ani_env *env, ani_object object, const char* class_name, const std::string& member);

ani_object GetANIArray(ani_env *env, size_t array_size);

void SetRecordKeyValue(ani_env *env, ani_object &recordObject, std::string &key, ani_object &value);

ani_object NewRecordClass(ani_env *env);

ani_object CreateFormInfoAniArrayFromVec(ani_env *env, const std::vector<AppExecFwk::FormInfo> &formInfos);

}  // namespace FormAniHelpers
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // FORM_FWK_ANI_HELPERS_H