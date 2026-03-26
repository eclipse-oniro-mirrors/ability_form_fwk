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

#include "formrenderservicemgrthree_fuzzer.h"

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

void CreateFormSurfaceInfo(FuzzedDataProvider *fdp, FormSurfaceInfo &formSurfaceInfo)
{
    formSurfaceInfo.width = fdp->ConsumeFloatingPoint<float>();
    formSurfaceInfo.height = fdp->ConsumeFloatingPoint<float>();
    formSurfaceInfo.borderWidth = fdp->ConsumeFloatingPoint<float>();
    formSurfaceInfo.formViewScale = fdp->ConsumeFloatingPoint<float>();
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

void TestProcessStopRenderingForm(FuzzedDataProvider *fdp)
{
    FormJsInfo formJsInfo;
    CreateFormJsInfo(fdp, formJsInfo);
    
    Want want;
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string compId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string eventId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    CreateWantWithParams(fdp, want, uid, compId, eventId);
    
    bool isRenderGroupEmptyOut = false;
    FormRenderServiceMgr::GetInstance().ProcessStopRenderingForm(formJsInfo, want, isRenderGroupEmptyOut);
}

void TestReleaseRenderer(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    std::string compId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    
    Want want;
    CreateWantWithParams(fdp, want, uid, compId, "test_event_id");
    
    FormRenderServiceMgr::GetInstance().ReleaseRenderer(formId, compId, uid, want);
}

void TestProcessReleaseRenderer(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    std::string compId = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    
    Want want;
    CreateWantWithParams(fdp, want, uid, compId, "test_event_id");
    
    FormRenderServiceMgr::GetInstance().ProcessReleaseRenderer(formId, compId, uid, want);
}

void TestOnUnlock()
{
    FormRenderServiceMgr::GetInstance().OnUnlock();
}

void TestSetRenderGroupEnableFlag(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    bool isEnable = fdp->ConsumeBool();
    
    Want want;
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    CreateWantWithParams(fdp, want, uid, "comp_id", "event_id");
    
    FormRenderServiceMgr::GetInstance().SetRenderGroupEnableFlag(formId, isEnable, want);
}

void TestOnConfigurationUpdated()
{
    std::shared_ptr<OHOS::AppExecFwk::Configuration> config = nullptr;
    FormRenderServiceMgr::GetInstance().OnConfigurationUpdated(config);
}

void TestRunCachedConfigurationUpdated()
{
    FormRenderServiceMgr::GetInstance().RunCachedConfigurationUpdated();
}

void TestProcessRecycleForm(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    
    Want want;
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    CreateWantWithParams(fdp, want, uid, "comp_id", "event_id");
    
    std::string statusDataOut;
    FormRenderServiceMgr::GetInstance().ProcessRecycleForm(formId, want, statusDataOut);
}

void TestRecoverForm(FuzzedDataProvider *fdp)
{
    FormJsInfo formJsInfo;
    CreateFormJsInfo(fdp, formJsInfo);
    
    Want want;
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    CreateWantWithParams(fdp, want, uid, "comp_id", "event_id");
    
    FormRenderServiceMgr::GetInstance().RecoverForm(formJsInfo, want);
}

void TestUpdateFormSize(FuzzedDataProvider *fdp)
{
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    
    FormJsInfo formJsInfo;
    CreateFormJsInfo(fdp, formJsInfo);
    
    FormSurfaceInfo formSurfaceInfo;
    CreateFormSurfaceInfo(fdp, formSurfaceInfo);
    
    FormRenderServiceMgr::GetInstance().UpdateFormSize(formId, formSurfaceInfo, uid, formJsInfo);
}

void TestGetRenderRecordById(FuzzedDataProvider *fdp)
{
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::shared_ptr<FormRenderRecord> search = nullptr;
    FormRenderServiceMgr::GetInstance().GetRenderRecordById(search, uid);
}

void TestRecoverFormByUid(FuzzedDataProvider *fdp)
{
    FormJsInfo formJsInfo;
    CreateFormJsInfo(fdp, formJsInfo);
    
    Want want;
    std::string uid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::string statusData = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    CreateWantWithParams(fdp, want, uid, "comp_id", "event_id");
    
    FormRenderServiceMgr::GetInstance().RecoverFormByUid(formJsInfo, want, uid, statusData);
}

void TestSetCriticalFalseOnAllFormInvisible()
{
    FormRenderServiceMgr::GetInstance().SetCriticalFalseOnAllFormInvisible();
}

void TestSetCriticalTrueOnFormActivity()
{
    FormRenderServiceMgr::GetInstance().SetCriticalTrueOnFormActivity();
}

void TestProcessStopRenderingFormEdgeCases(FuzzedDataProvider *fdp)
{
    FormJsInfo formJsInfo;
    CreateFormJsInfo(fdp, formJsInfo);
    
    Want want;
    bool isRenderGroupEmptyOut = false;
    
    formJsInfo.formId = 0;
    CreateWantWithParams(fdp, want, "", "comp_id", "event_id");
    FormRenderServiceMgr::GetInstance().ProcessStopRenderingForm(formJsInfo, want, isRenderGroupEmptyOut);
    
    formJsInfo.formId = -1;
    CreateWantWithParams(fdp, want, "uid", "comp_id", "event_id");
    isRenderGroupEmptyOut = true;
    FormRenderServiceMgr::GetInstance().ProcessStopRenderingForm(formJsInfo, want, isRenderGroupEmptyOut);
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }

    uint8_t testType = fdp->ConsumeIntegral<uint8_t>();

    switch (testType % 14) {
        case 0:
            TestProcessStopRenderingForm(fdp);
            break;
        case 1:
            TestReleaseRenderer(fdp);
            break;
        case 2:
            TestProcessReleaseRenderer(fdp);
            break;
        case 3:
            TestOnUnlock();
            break;
        case 4:
            TestSetRenderGroupEnableFlag(fdp);
            break;
        case 5:
            TestOnConfigurationUpdated();
            break;
        case 6:
            TestRunCachedConfigurationUpdated();
            break;
        case 7:
            TestProcessRecycleForm(fdp);
            break;
        case 8:
            TestRecoverForm(fdp);
            break;
        case 9:
            TestUpdateFormSize(fdp);
            break;
        case 10:
            TestGetRenderRecordById(fdp);
            break;
        case 11:
            TestRecoverFormByUid(fdp);
            break;
        case 12:
            TestSetCriticalFalseOnAllFormInvisible();
            break;
        case 13:
            TestSetCriticalTrueOnFormActivity();
            break;
        case 14:
            TestProcessStopRenderingFormEdgeCases(fdp);
            break;
        default:
            TestProcessStopRenderingFormEdgeCases(fdp);
            break;
    }

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
