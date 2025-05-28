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

#include "cj_form_util.h"

#include <cinttypes>
#include <vector>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_mgr.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "running_form_info.h"
#include "runtime.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

int32_t CreateErrorByInternalErrorCode(int32_t internalErrorCode)
{
    int32_t externalErrorCode = 0;
    std::string externalErrorMessage;
    FormMgr::GetInstance().GetExternalError(internalErrorCode, externalErrorCode, externalErrorMessage);
    return externalErrorCode;
}

char* CreateCStringFromString(const std::string& source)
{
    if (source.size() == 0) {
        return nullptr;
    }
    size_t length = source.size() + 1;
    auto res = static_cast<char*>(malloc(length));
    if (res == nullptr) {
        HILOG_ERROR("null res");
        return nullptr;
    }
    if (strcpy_s(res, length, source.c_str()) != 0) {
        free(res);
        HILOG_ERROR("Strcpy failed");
        return nullptr;
    }
    return res;
}

int32_t GetFormType(const FormInfo& formInfo)
{
    if (formInfo.uiSyntax == FormType::ETS) {
        return static_cast<int32_t>(FormType::ETS);
    }
    return static_cast<int32_t>(formInfo.type);
}

CArrI32 ConvertArrI32(const std::vector<int32_t>& infos)
{
    CArrI32 ret = { .head = nullptr, .size = 0 };
    int32_t* head = static_cast<int32_t*>(malloc(sizeof(int32_t) * infos.size()));
    if (head == nullptr) {
        return ret;
    }
    uint32_t index = 0;
    for (const auto& info : infos) {
        head[index] = info;
        index++;
    }
    ret.head = head;
    ret.size = static_cast<int64_t>(infos.size());
    return ret;
}

CArrUI32 ConvertArrUI32(const std::vector<uint32_t>& infos)
{
    CArrUI32 ret = { .head = nullptr, .size = 0 };
    uint32_t* head = static_cast<uint32_t*>(malloc(sizeof(uint32_t) * infos.size()));
    if (head == nullptr) {
        return ret;
    }
    uint32_t index = 0;
    for (const auto& info : infos) {
        head[index] = info;
        index++;
    }
    ret.head = head;
    ret.size = static_cast<int64_t>(infos.size());
    return ret;
}

CArrCFormCustomizeData ConvertArrFormCustomizeData(const std::vector<FormCustomizeData>& infos)
{
    CArrCFormCustomizeData ret = { .head = nullptr, .size = 0 };
    CFormCustomizeData* head = static_cast<CFormCustomizeData*>(malloc(sizeof(CFormCustomizeData) * infos.size()));
    if (head == nullptr) {
        return ret;
    }
    uint32_t index = 0;
    for (const auto& info : infos) {
        head[index].name = CreateCStringFromString(info.name);
        head[index].value = CreateCStringFromString(info.value);
        index++;
    }
    ret.head = head;
    ret.size = static_cast<int64_t>(infos.size());
    return ret;
}

void FreeCArrFormCustomizeData(CArrCFormCustomizeData& infos)
{
    if (infos.head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < infos.size; i++) {
        free(infos.head[i].name);
        infos.head[i].name = nullptr;
        free(infos.head[i].value);
        infos.head[i].value = nullptr;
    }
    free(infos.head);
    infos.head = nullptr;
}

void FreeCFormInfo(CFormInfo& formInfo)
{
    free(formInfo.bundleName);
    formInfo.bundleName = nullptr;
    free(formInfo.moduleName);
    formInfo.moduleName = nullptr;
    free(formInfo.abilityName);
    formInfo.abilityName = nullptr;
    free(formInfo.name);
    formInfo.name = nullptr;
    free(formInfo.displayName);
    formInfo.displayName = nullptr;
    free(formInfo.description);
    formInfo.description = nullptr;
    free(formInfo.jsComponentName);
    formInfo.jsComponentName = nullptr;
    free(formInfo.scheduledUpdateTime);
    formInfo.scheduledUpdateTime = nullptr;
    free(formInfo.formConfigAbility);
    formInfo.formConfigAbility = nullptr;
    free(formInfo.supportDimensions.head);
    formInfo.supportDimensions.head = nullptr;
    FreeCArrFormCustomizeData(formInfo.customizeData);
    free(formInfo.supportedShapes.head);
    formInfo.supportedShapes.head = nullptr;
    free(formInfo.previewImages.head);
    formInfo.previewImages.head = nullptr;
}

CFormInfo ConvertFormInfo2CFormInfo(const FormInfo& formInfo)
{
    CFormInfo ret = {};
    ret.bundleName = CreateCStringFromString(formInfo.bundleName);
    ret.moduleName = CreateCStringFromString(formInfo.moduleName);
    ret.abilityName = CreateCStringFromString(formInfo.abilityName);
    ret.name = CreateCStringFromString(formInfo.name);
    ret.displayName = CreateCStringFromString(formInfo.displayName);
    ret.displayNameId = formInfo.displayNameId;
    ret.description = CreateCStringFromString(formInfo.description);
    ret.descriptionId = formInfo.descriptionId;
    ret.type = GetFormType(formInfo);
    ret.jsComponentName = CreateCStringFromString(formInfo.jsComponentName);
    ret.colorMode = static_cast<int32_t>(formInfo.colorMode);
    ret.isDefault = formInfo.defaultFlag;
    ret.updateEnabled = formInfo.updateEnabled;
    ret.formVisibleNotify = formInfo.formVisibleNotify;
    ret.scheduledUpdateTime = CreateCStringFromString(formInfo.scheduledUpdateTime);
    ret.formConfigAbility = CreateCStringFromString(formInfo.formConfigAbility);
    ret.updateDuration = formInfo.updateDuration;
    ret.defaultDimension = formInfo.defaultDimension;
    ret.supportDimensions = ConvertArrI32(formInfo.supportDimensions);
    ret.customizeData = ConvertArrFormCustomizeData(formInfo.customizeDatas);
    ret.isDynamic = formInfo.isDynamic;
    ret.transparencyEnabled = formInfo.transparencyEnabled;
    ret.supportedShapes = ConvertArrI32(formInfo.supportShapes);
    ret.previewImages = ConvertArrUI32(formInfo.formPreviewImages);
    ret.enableBlurBackground = formInfo.enableBlurBackground;
    ret.renderingMode = static_cast<int32_t>(formInfo.renderingMode);
    return ret;
}

bool ConvertFromDataProxies(const CArrProxyData& cArrProxyData, std::vector<FormDataProxy>& formDataProxies)
{
    if (cArrProxyData.head == nullptr) {
        HILOG_ERROR("null head");
        return false;
    }
    int32_t len = cArrProxyData.size;
    for (uint32_t i = 0; i < len; i++) {
        FormDataProxy formDataProxy("", "");
        CProxyData element = cArrProxyData.head[i];
        if (!ConvertFormDataProxy(element, formDataProxy)) {
            HILOG_ERROR("GetElement [%{public}u] error", i);
            continue;
        }
        formDataProxies.push_back(formDataProxy);
    }
    return true;
}

bool ConvertFormDataProxy(const CProxyData& cProxyData, FormDataProxy& formDataProxy)
{
    if (cProxyData.key == nullptr || cProxyData.subscribeId == nullptr) {
        return false;
    }
    formDataProxy.key = std::string(cProxyData.key);
    formDataProxy.subscribeId = std::string(cProxyData.subscribeId);
    return true;
}

} // namespace AbilityRuntime
} // namespace OHOS