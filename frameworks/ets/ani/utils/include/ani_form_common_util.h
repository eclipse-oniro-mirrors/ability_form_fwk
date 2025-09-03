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
#include "ani.h"

namespace OHOS {
namespace AbilityRuntime {
ani_object CreateAniObject(ani_env* env, const char* className);
ani_object CreateArrayObject(ani_env *env);
void SetPropertyStringByName(ani_env* env, ani_object object, const char* name, std::string string);
void SetPropertyBoolByName(ani_env *env, ani_object object, const char *name, bool value);
void SetPropertyBoolByNameValue(ani_env *env, ani_object object, const char *name, bool value);
void SetPropertyDoubleByName(ani_env *env, ani_object object, const char *name, double value);
void SetPropertyIntByName(ani_env *env, ani_object object, const char *name, int32_t value);
void SetPropertyByName(ani_env *env, ani_object object, const char *name, ani_object value);

bool GetStdString(ani_env *env, ani_string str, std::string &value);
bool GetPropertyDoubleObject(ani_env *env, ani_object param, const char *name, double &value);
bool GetPropertyIntObject(ani_env *env, ani_object param, const char *name, int32_t &value);
bool GetPropertyBoolByName(ani_env *env, ani_object object, const char *name, bool &value);

} // namespace AbilityRuntime
} // namespace OHOS
#endif /* OHOS_FORM_FWK_ANI_FORM_ERROR_UTIL_H */