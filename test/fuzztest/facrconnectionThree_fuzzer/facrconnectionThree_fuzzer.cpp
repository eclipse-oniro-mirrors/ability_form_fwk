/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "facrconnectionThree_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "form_constants.h"
#include "form_supply_stub.h"
#include "form_surface_info.h"

#define private public
#define protected public
#include "form_render_service_mgr.h"
#include "status_mgr_center/form_render_status_mgr.h"
#include "status_mgr_center/form_render_status_task_mgr.h"
#include "data_center/form_basic_info_mgr.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::string abilityName = fdp->ConsumeRandomLengthString();
    std::string bundleName = fdp->ConsumeRandomLengthString();
    std::string moduleName = fdp->ConsumeRandomLengthString();
    std::string formName = fdp->ConsumeRandomLengthString();
    std::string packageName = fdp->ConsumeRandomLengthString();
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    FormBasicInfo basicInfo;
    basicInfo.formId = formId;
    FormBasicInfoMgr::GetInstance().AddFormBasicInfo(basicInfo);
    FormBasicInfoMgr::GetInstance().UpdateAbilityName(formId, abilityName);
    FormBasicInfoMgr::GetInstance().UpdateBundleName(formId, bundleName);
    FormBasicInfoMgr::GetInstance().UpdateModuleName(formId, moduleName);
    FormBasicInfoMgr::GetInstance().UpdateFormName(formId, formName);
    FormBasicInfoMgr::GetInstance().UpdatePackageName(formId, packageName);
    FormBasicInfoMgr::GetInstance().GetBasicInfoCount();
    FormBasicInfoMgr::GetInstance().GetBasicInfoByFormId(formId, basicInfo);
    FormBasicInfoMgr::GetInstance().GetFormAbilityName(formId);
    FormBasicInfoMgr::GetInstance().GetFormBundleName(formId);
    FormBasicInfoMgr::GetInstance().GetFormModuleName(formId);
    FormBasicInfoMgr::GetInstance().GetFormName(formId);
    FormBasicInfoMgr::GetInstance().GetFormPackageName(formId);
    FormBasicInfoMgr::GetInstance().DeleteFormBasicInfo(formId);
    FormBasicInfoMgr::GetInstance().ClearFormBasicInfo();
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}