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

#include "formrenderservicemgrtwo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_render_service_mgr.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 15;
constexpr int32_t MAX_NUM = 10000;
constexpr int32_t MIN_NUM = 0;
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    int64_t formId = fdp->ConsumeIntegralInRange(MIN_NUM, MAX_NUM);
    std::string compId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    Want want;
    FormJsInfo formJsInfo = {};
    formJsInfo.formId = formId;
    formJsInfo.CopyFormJsInfoWithoutFormData();
    sptr<IRemoteObject> callerToken = nullptr;

    FormRenderServiceMgr::GetInstance().RenderForm(formJsInfo, want, callerToken);
    FormRenderServiceMgr::GetInstance().StopRenderingForm(formJsInfo, want, callerToken);
    FormRenderServiceMgr::GetInstance().CleanFormHost(callerToken);

    std::vector<FormJsInfo> formJsInfos = {};
    FormRenderServiceMgr::GetInstance().ReloadForm(std::move(formJsInfos), want);

    std::shared_ptr<OHOS::AppExecFwk::Configuration> config = nullptr;
    FormRenderServiceMgr::GetInstance().OnConfigurationUpdated(config);
    FormRenderServiceMgr::GetInstance().SetConfiguration(config);
    FormRenderServiceMgr::GetInstance().RunCachedConfigurationUpdated();

    FormRenderServiceMgr::GetInstance().ReleaseRenderer(formId, compId, uid, want);
    FormRenderServiceMgr::GetInstance().OnUnlock();

    bool isVisible = fdp->ConsumeBool();
    FormRenderServiceMgr::GetInstance().SetVisibleChange(formId, isVisible, want);

    FormRenderServiceMgr::GetInstance().RecycleForm(formId, want);
    FormRenderServiceMgr::GetInstance().RecoverForm(formJsInfo, want);

    FormSurfaceInfo formSurfaceInfo = {};
    FormRenderServiceMgr::GetInstance().UpdateFormSize(formId, formSurfaceInfo, uid, formJsInfo);

    sptr<IFormSupply> formSupplyClient = nullptr;
    FormRenderServiceMgr::GetInstance().SetFormSupplyClient(formSupplyClient);
    FormRenderServiceMgr::GetInstance().GetFormSupplyClient();

    FormRenderServiceMgr::GetInstance().SetCriticalTrueOnFormActivity();

    std::function<void()> gcCb = []() {};
    FormRenderServiceMgr::GetInstance().SetMainGcCb(std::move(gcCb));
    FormRenderServiceMgr::GetInstance().MainThreadForceFullGC();

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
