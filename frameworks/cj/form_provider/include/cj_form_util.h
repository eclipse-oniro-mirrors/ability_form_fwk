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

#ifndef CJ_FORM_UTIL_FFI_H
#define CJ_FORM_UTIL_FFI_H

#include <stdint.h>
#include "ability.h"
#include "form_binding_data_defination.h"
#include "form_info.h"
#include "form_info_filter.h"
#include "form_provider_info.h"
#include "running_form_info.h"
#include "want.h"
#include <vector>

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

struct CArrI32 {
    int32_t* head;
    int64_t size;
};

struct CArrUI32 {
    uint32_t* head;
    int64_t size;
};

struct CFormFilter {
    char* moduleName;
};

struct CFormCustomizeData {
    char* name;
    char* value;
};

struct CArrCFormCustomizeData {
    CFormCustomizeData* head;
    int64_t size;
};

struct CFormInfo {
    char* bundleName;
    char* moduleName;
    char* abilityName;
    char* name;
    char* displayName;
    uint32_t displayNameId;
    char* description;
    uint32_t descriptionId;
    int32_t type;
    char* jsComponentName;
    int32_t colorMode;
    bool isDefault;
    bool updateEnabled;
    bool formVisibleNotify;
    char* scheduledUpdateTime;
    char* formConfigAbility;
    int32_t updateDuration;
    int32_t defaultDimension;
    CArrI32 supportDimensions;
    CArrCFormCustomizeData customizeData;
    bool isDynamic;
    bool transparencyEnabled;
    CArrI32 supportedShapes;
    CArrUI32 previewImages;
    bool enableBlurBackground;
    int32_t renderingMode;
};

struct CArrCFormInfo {
    CFormInfo* head;
    int64_t size;
};

int32_t CreateErrorByInternalErrorCode(int32_t internalErrorCode);
char* CreateCStringFromString(const std::string& source);
CFormInfo ConvertFormInfo2CFormInfo(FormInfo formInfo);
void FreeCFormInfo(CFormInfo formInfo);
bool ConvertFromDataProxies(CArrProxyData cArrProxyData, std::vector<FormDataProxy> &formDataProxies);
bool ConvertFormDataProxy(CProxyData cProxyData, FormDataProxy &formDataProxy);

}
}

#endif // CJ_FORM_UTIL_FFI_H

