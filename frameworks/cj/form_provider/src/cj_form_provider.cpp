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

#include "cj_form_provider.h"

#include <cinttypes>
#include <vector>

#include "cj_form_util.h"
#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_mgr.h"
#include "napi_form_util.h"
#include "running_form_info.h"
#include "ipc_skeleton.h"
#include "runtime.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

const size_t MAX_SIZE = 1024;

int32_t OnGetFormsInfo(CFormFilter cfilter, CArrCFormInfo* cArrformInfo)
{
    FormInfoFilter formInfoFilter;
    formInfoFilter.moduleName = std::string(cfilter.moduleName);
    std::vector<FormInfo> formInfos;
    auto ret = FormMgr::GetInstance().GetFormsInfo(formInfoFilter, formInfos);
    if (ret != ERR_OK) {
        return CreateErrorByInternalErrorCode(ret);
    }
    if (formInfos.size() < 0 || formInfos.size() > MAX_SIZE) {
        return ERR_FORM_EXTERNAL_FORM_NUM_EXCEEDS_UPPER_BOUND;
    }
    CFormInfo* head = static_cast<CFormInfo*>(malloc(sizeof(CFormInfo) * formInfos.size()));
    if (head == nullptr) {
        return ERR_FORM_EXTERNAL_KERNEL_MALLOC_ERROR;
    }
    uint32_t index = 0;
    for (const auto &formInfo : formInfos) {
        head[index] = ConvertFormInfo2CFormInfo(formInfo);
        index++;
    }
    cArrformInfo->head = head;
    cArrformInfo->size = static_cast<int64_t>(formInfos.size());
    return ret;
}

int32_t OnSetFormNextRefreshTime(char* cFormId, int32_t time)
{
    HILOG_DEBUG("call");
    int64_t formId = 0;
    std::string strFormId = std::string(cFormId);
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert form string failed");
        return ERR_FORM_EXTERNAL_PARAM_INVALID;
    }
    int32_t ret = FormMgr::GetInstance().SetNextRefreshTime(formId, time);
    if (ret != ERR_OK) {
        return CreateErrorByInternalErrorCode(ret);
    }
    return ret;
}

int32_t OnUpdateForm(char* cFormId, CFormBindingData cFormBindingData)
{
    HILOG_DEBUG("call");
    int64_t formId = 0;
    std::string strFormId = std::string(cFormId);
    if (!ConvertStringToInt64(strFormId, formId)) {
        HILOG_ERROR("convert form string failed");
        return ERR_FORM_EXTERNAL_PARAM_INVALID;
    }
    auto formProviderData = std::make_shared<OHOS::AppExecFwk::FormProviderData>();
    std::string formDataStr = std::string(cFormBindingData.data);
    formProviderData->SetDataString(formDataStr);
    formProviderData->ParseImagesData();

    std::vector<AppExecFwk::FormDataProxy> formDataProxies;
    CArrProxyData nativeProxies = cFormBindingData.cArrProxyData;
    ConvertFromDataProxies(nativeProxies, formDataProxies);
    int32_t ret = FormMgr::GetInstance().UpdateForm(formId, *formProviderData, formDataProxies);
    if (ret != ERR_OK) {
        return CreateErrorByInternalErrorCode(ret);
    }
    return ret;
}

void FreeCArrCFormInfo(CArrCFormInfo* cArrformInfo)
{
    if (cArrformInfo == nullptr || cArrformInfo->head == nullptr) {
        return;
    }
    for (int64_t i = 0; i < cArrformInfo->size; i++) {
        FreeCFormInfo((cArrformInfo->head)[i]);
    }
    free(cArrformInfo->head);
}

extern "C" {
CJ_EXPORT int32_t FFIFormProviderGetFormsInfo(CFormFilter cfilter, CArrCFormInfo* cArrformInfo)
{
    if (cfilter.moduleName == nullptr || cArrformInfo == nullptr) {
        HILOG_ERROR("input param is nullptr");
        return ERR_FORM_EXTERNAL_PARAM_INVALID;
    }
    return OnGetFormsInfo(cfilter, cArrformInfo);
}

CJ_EXPORT void FFIFormProviderFreeCArrCFormInfo(CArrCFormInfo* cArrformInfo)
{
    if (cArrformInfo == nullptr) {
        HILOG_ERROR("input param is nullptr");
        return;
    }
    FreeCArrCFormInfo(cArrformInfo);
}

CJ_EXPORT int32_t FFIFormProviderSetFormNextRefreshTime(char* cFormId, int32_t time)
{
    if (cFormId == nullptr) {
        HILOG_ERROR("input param is nullptr");
        return ERR_FORM_EXTERNAL_PARAM_INVALID;
    }
    return OnSetFormNextRefreshTime(cFormId, time);
}

CJ_EXPORT int32_t FFIFormProviderUpdateForm(char* cFormId, CFormBindingData cFormBindingData)
{
    if (cFormId == nullptr) {
        HILOG_ERROR("input param is nullptr");
        return ERR_FORM_EXTERNAL_PARAM_INVALID;
    }
    return OnUpdateForm(cFormId, cFormBindingData);
}

} // extern "C"

}
}