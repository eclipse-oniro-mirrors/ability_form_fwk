/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "facrconnection_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "form_constants.h"

#define private public
#define protected public
#include "form_render_service_mgr.h"
#include "status_mgr_center/form_render_status_mgr.h"
#include "data_center/form_basic_info_mgr.h"
#undef private
#undef protected
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
void FormBasicInfoMgrTest(FuzzedDataProvider *fdp)
{
    std::string abilityName = fdp->ConsumeRandomLengthString();
    std::string bundleName = fdp->ConsumeRandomLengthString();
    std::string moduleName = fdp->ConsumeRandomLengthString();
    std::string formName = fdp->ConsumeRandomLengthString();
    std::string packageName = fdp->ConsumeRandomLengthString();
    int64_t formId = fdp->ConsumeIntegralInRange(0, 1000);
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
}

void FormRenderStatusMgrTest(FuzzedDataProvider *fdp)
{
    OHOS::FormBasicInfoMgrTest(fdp);
    FormRenderServiceMgr::GetInstance().RunCachedConfigurationUpdated();
    FormRenderServiceMgr::GetInstance().OnUnlock();
    FormRenderServiceMgr::GetInstance().GetFormSupplyClient();
    FormRenderServiceMgr::GetInstance().OnConfigurationUpdatedInner();
    int64_t formId = fdp->ConsumeIntegralInRange(0, 1000);
    FormFsmEvent event = FormFsmEvent::RELOAD_FORM;
    std::function<int32_t()> func = []() { return 1; };
    FormRenderStatusMgr::GetInstance().PostFormEvent(formId, event, func);
    FormRenderStatusMgr::GetInstance().GetFormEventId(formId);
    std::string eventId = fdp->ConsumeRandomLengthString();
    FormRenderStatusMgr::GetInstance().SetFormEventId(formId, eventId);
    FormRenderStatusMgr::GetInstance().DeleteFormEventId(formId);
    FormFsmStatus status = FormFsmStatus::UNPROCESSABLE;
    FormFsmProcessType processType = FormFsmProcessType::PROCESS_TASK_DELETE;
    FormRenderStatusMgr::GetInstance().ExecFormTask(processType, formId, event, status, func);
    FormRenderStatusMgr::GetInstance().ProcessTaskDirect(func);
    FormRenderStatusMgr::GetInstance().ProcessTaskDelete(formId);
    FormRenderStatusMgr::GetInstance().PrintTaskInfo(formId, event, status);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    std::string str1 = fdp->ConsumeRandomLengthString(10);
    std::string str2 = fdp->ConsumeRandomLengthString(10);
    std::string str3 = fdp->ConsumeRandomLengthString(5);
    int32_t num1 = fdp->ConsumeIntegralInRange(0, 1000);
    int64_t num2 = fdp->ConsumeIntegralInRange(0, 1000);
    float num3 = fdp->ConsumeIntegralInRange(0, 1000);
    std::string str = fdp->ConsumeRandomLengthString();
    bool isTrue = str.size() % 2;
    FormJsInfo formJsInfo;
    formJsInfo.formId = num2;
    sptr<IRemoteObject> callerToken;
    Want want;
    want.SetParam(Constants::FORM_CONNECT_ID, num1);
    want.SetParam(Constants::FORM_STATUS_EVENT_ID, str1);
    want.SetParam(Constants::FORM_SUPPLY_UID, str3);
    want.SetParam(Constants::PARAM_FORM_HOST_TOKEN, callerToken);
    FormRenderServiceMgr::GetInstance().RenderForm(formJsInfo, want, callerToken);
    FormRenderServiceMgr::GetInstance().StopRenderingForm(formJsInfo, want, callerToken);
    FormRenderServiceMgr::GetInstance().CleanFormHost(callerToken);
    std::vector<FormJsInfo> formJsInfos;
    formJsInfos.push_back(formJsInfo);
    formJsInfos.push_back(formJsInfo);
    FormRenderServiceMgr::GetInstance().ReloadForm(std::move(formJsInfos), want);
    std::shared_ptr<OHOS::AppExecFwk::Configuration> configuration = std::make_shared<Configuration>();
    configuration->AddItem(str1, str2);
    FormRenderServiceMgr::GetInstance().OnConfigurationUpdated(configuration);
    FormRenderServiceMgr::GetInstance().SetConfiguration(configuration);
    FormRenderServiceMgr::GetInstance().ReleaseRenderer(num2, str1, str2, want);
    FormRenderServiceMgr::GetInstance().SetVisibleChange(num2, isTrue, want);
    FormRenderServiceMgr::GetInstance().RecycleForm(num2, want);
    FormRenderServiceMgr::GetInstance().RecoverForm(formJsInfo, want);
    FormRenderServiceMgr::GetInstance().UpdateFormSize(num2, num3, num3, num3, str1);
    sptr<IFormSupply> formSupplyClient;
    FormRenderServiceMgr::GetInstance().SetFormSupplyClient(formSupplyClient);
    FormRenderServiceMgr::GetInstance().FormRenderGCTask(str1);
    FormRenderServiceMgr::GetInstance().FormRenderGC(str1);
    FormRenderServiceMgr::GetInstance().ConfirmUnlockState(want);
    FormRenderServiceMgr::GetInstance().UpdateRenderRecordByUid(str1, want, formJsInfo, formSupplyClient);
    FormRenderServiceMgr::GetInstance().IsRenderRecordExist(str1);
    std::shared_ptr<FormRenderRecord> search;
    FormRenderServiceMgr::GetInstance().GetRenderRecordById(search, str1);
    FormRenderServiceMgr::GetInstance().RecoverFormByUid(formJsInfo, want, str1, str2);
    FormRenderServiceMgr::GetInstance().RecycleFormByUid(str1, str2, num2);
    FormRenderServiceMgr::GetInstance().DeleteRenderRecordByUid(str1, search);
    OHOS::FormRenderStatusMgrTest(fdp);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    free(ch);
    ch = nullptr;
    return 0;
}

