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
constexpr int16_t MAX_SIZE = 10;

class FormSupplyStubFuzzTest : public FormSupplyStub {
public:
    FormSupplyStubFuzzTest() = default;
    virtual ~FormSupplyStubFuzzTest() = default;
    int OnAcquire(const FormProviderInfo &formInfo, const Want &want) override
    {
        return 0;
    }
    int OnEventHandle(const Want &want) override
    {
        return 0;
    }
    int OnAcquireStateResult(FormState state, const std::string &provider,
        const Want &wantArg, const Want &want) override
    {
        return 0;
    }
    void OnShareAcquire(int64_t formId, const std::string &remoteDeviceId,
        const AAFwk::WantParams &wantParams, int64_t requestCode, const bool &result) override
    {}
    int32_t OnRenderTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int32_t OnStopRenderingTaskDone(int64_t formId, const Want &want) override
    {
        return ERR_OK;
    }
    int OnAcquireDataResult(const AAFwk::WantParams &wantParams, int64_t requestCode) override
    {
        return ERR_OK;
    }
};

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    std::string str1 = fdp->ConsumeRandomLengthString(MAX_SIZE);
    std::string str2 = fdp->ConsumeRandomLengthString(MAX_SIZE);
    std::string str3 = fdp->ConsumeRandomLengthString(MAX_SIZE);
    int32_t num1 = fdp->ConsumeIntegral<int32_t>();
    int64_t num2 = fdp->ConsumeIntegral<int64_t>();
    bool isTrue = fdp->ConsumeBool();
    FormJsInfo formJsInfo;
    formJsInfo.formId = num2;
    FormSurfaceInfo formSurfaceInfo;
    sptr<IRemoteObject> callerToken;
    callerToken = new (std::nothrow) FormSupplyStubFuzzTest();
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
    FormRenderServiceMgr::GetInstance().UpdateFormSize(num2, formSurfaceInfo, str1, formJsInfo);
    sptr<IFormSupply> formSupplyClient = nullptr;
    FormRenderServiceMgr::GetInstance().SetFormSupplyClient(formSupplyClient);
    FormRenderServiceMgr::GetInstance().ConfirmUnlockState(want);
    FormRenderServiceMgr::GetInstance().UpdateRenderRecordByUid(str1, want, formJsInfo, formSupplyClient);
    std::shared_ptr<FormRenderRecord> search;
    FormRenderServiceMgr::GetInstance().GetRenderRecordById(search, str1);
    FormRenderServiceMgr::GetInstance().RecoverFormByUid(formJsInfo, want, str1, str2);
    FormRenderServiceMgr::GetInstance().RecycleFormByUid(str1, str2, num2);
    FormRenderServiceMgr::GetInstance().DeleteRenderRecordByUid(str1, search);
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