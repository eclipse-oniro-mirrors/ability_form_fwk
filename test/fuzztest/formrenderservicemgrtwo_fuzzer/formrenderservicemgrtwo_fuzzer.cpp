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
#include "ffrt.h"
#undef private
#undef protected
#include "configuration.h"

extern "C" ffrt_task_handle_t ffrt_queue_submit_h(
    ffrt_queue_t queue, ffrt_function_header_t* f, const ffrt_task_attr_t* attr)
{
    return nullptr;
}

extern "C" int WatchParameter(const char *, void (*)(const char *, const char *, void *), void *)
{
    return 0;
}

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace OHOS {

constexpr int32_t MAX_LENGTH = 256;

void CreateFormJsInfo(FuzzedDataProvider *fdp, FormJsInfo &formJsInfo)
{
    formJsInfo.formId = fdp->ConsumeIntegral<int64_t>();
    formJsInfo.formName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formJsInfo.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formJsInfo.abilityName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formJsInfo.moduleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formJsInfo.formTempFlag = fdp->ConsumeBool();
    formJsInfo.jsFormCodePath = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formJsInfo.formData = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formJsInfo.formSrc = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formJsInfo.versionCode = fdp->ConsumeIntegral<uint32_t>();
    formJsInfo.versionName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    formJsInfo.compatibleVersion = fdp->ConsumeIntegral<uint32_t>();
    formJsInfo.isDynamic = fdp->ConsumeBool();
    formJsInfo.transparencyEnabled = fdp->ConsumeBool();
}

void CreateWantWithParams(FuzzedDataProvider *fdp, Want &want, const std::string &uid, const std::string &compId,
    const std::string &eventId)
{
    if (!uid.empty()) {
        want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    }
    if (!compId.empty()) {
        want.SetParam(Constants::FORM_RENDER_COMP_ID, compId);
    }
    if (!eventId.empty()) {
        want.SetParam(Constants::FORM_STATUS_EVENT_ID, eventId);
    }
    want.SetParam(Constants::FORM_CONNECT_ID, fdp->ConsumeIntegral<int64_t>());
    want.SetParam(Constants::FORM_IS_RECOVER_FORM_TO_HANDLE_CLICK_EVENT, fdp->ConsumeBool());
}

std::shared_ptr<Configuration> CreateFuzzedConfig(FuzzedDataProvider *fdp)
{
    auto config = std::make_shared<Configuration>();
    int32_t itemCount = fdp->ConsumeIntegralInRange<int32_t>(0, 5);
    for (int32_t i = 0; i < itemCount; i++) {
        std::string key = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        std::string value = fdp->ConsumeRandomLengthString(MAX_LENGTH);
        if (!key.empty()) {
            config->AddItem(key, value);
        }
    }
    return config;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    std::string compId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string eventId = fdp->ConsumeRandomLengthString(MAX_LENGTH);

    FormJsInfo formJsInfo;
    CreateFormJsInfo(fdp, formJsInfo);

    Want want;
    CreateWantWithParams(fdp, want, uid, compId, eventId);

    sptr<IRemoteObject> callerToken = nullptr;

    FormRenderServiceMgr::GetInstance().RenderForm(formJsInfo, want, callerToken);
    FormRenderServiceMgr::GetInstance().StopRenderingForm(formJsInfo, want, callerToken);
    FormRenderServiceMgr::GetInstance().CleanFormHost(callerToken);

    int32_t infoCount = fdp->ConsumeIntegralInRange<int32_t>(0, 3);
    std::vector<FormJsInfo> formJsInfos;
    for (int32_t i = 0; i < infoCount; i++) {
        FormJsInfo info;
        CreateFormJsInfo(fdp, info);
        formJsInfos.push_back(std::move(info));
    }
    Want reloadWant;
    std::string reloadUid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    reloadWant.SetParam(Constants::PARAM_BUNDLE_NAME_KEY,
        fdp->ConsumeRandomLengthString(MAX_LENGTH));
    reloadWant.SetParam(Constants::FORM_SUPPLY_UID, reloadUid);
    FormRenderServiceMgr::GetInstance().ReloadForm(std::move(formJsInfos), reloadWant);

    bool useFuzzedConfig = fdp->ConsumeBool();
    if (useFuzzedConfig) {
        auto config = CreateFuzzedConfig(fdp);
        FormRenderServiceMgr::GetInstance().OnConfigurationUpdated(config);
        FormRenderServiceMgr::GetInstance().SetConfiguration(config);
    } else {
        std::shared_ptr<Configuration> nullConfig = nullptr;
        FormRenderServiceMgr::GetInstance().OnConfigurationUpdated(nullConfig);
        FormRenderServiceMgr::GetInstance().SetConfiguration(nullConfig);
    }
    FormRenderServiceMgr::GetInstance().RunCachedConfigurationUpdated();

    FormRenderServiceMgr::GetInstance().ReleaseRenderer(formId, compId, uid, want);
    FormRenderServiceMgr::GetInstance().OnUnlock();

    bool isVisible = fdp->ConsumeBool();
    FormRenderServiceMgr::GetInstance().SetVisibleChange(formId, isVisible, want);

    FormRenderServiceMgr::GetInstance().RecycleForm(formId, want);
    FormRenderServiceMgr::GetInstance().RecoverForm(formJsInfo, want);

    FormSurfaceInfo formSurfaceInfo = {};
    formSurfaceInfo.width = fdp->ConsumeFloatingPoint<float>();
    formSurfaceInfo.height = fdp->ConsumeFloatingPoint<float>();
    formSurfaceInfo.borderWidth = fdp->ConsumeFloatingPoint<float>();
    formSurfaceInfo.formViewScale = fdp->ConsumeFloatingPoint<float>();
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
