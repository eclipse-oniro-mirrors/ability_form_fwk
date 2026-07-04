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

#include "formrenderservicemgr_fuzzer.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <thread>

#define private public
#define protected public
#include "form_render_service_mgr.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::FormRender;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
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
    FormRenderServiceMgr::GetInstance().ProcessReleaseRenderer(formId, compId, uid, want);

    std::vector<FormJsInfo> formJsInfos = {};
    want.SetParam(Constants::FORM_SUPPLY_UID, uid);
    FormRenderServiceMgr::GetInstance().ReloadFormRecord(std::move(formJsInfos), want);

    bool flag = fdp->ConsumeBool();
    FormRenderServiceMgr::GetInstance().SetRenderGroupEnableFlag(formId, flag, want);

    std::string statusDataOut = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    FormRenderServiceMgr::GetInstance().ProcessRecycleForm(formId, want, statusDataOut);
    FormJsInfo formJsInfo = {};
    FormRenderServiceMgr::GetInstance().ProcessRecoverForm(formJsInfo, want);

    FormRenderServiceMgr::GetInstance().SetCriticalFalseOnAllFormInvisible();
    FormRenderServiceMgr::GetInstance().CacheAppliedConfig();
    FormRenderServiceMgr::GetInstance().SetRenderGroupParams(formId, want);

    // Test ConfirmUnlockState
    Want renderWant;
    FormRenderServiceMgr::GetInstance().ConfirmUnlockState(renderWant);

    // Test UpdateRenderRecordByUid
    std::string updateUid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    Want formRenderWant;
    FormJsInfo updateFormJsInfo = {};
    updateFormJsInfo.formId = fdp->ConsumeIntegralInRange<int64_t>(MIN_NUM, MAX_NUM);
    updateFormJsInfo.bundleName = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    sptr<IFormSupply> formSupplyClient = nullptr;
    FormRenderServiceMgr::GetInstance().UpdateRenderRecordByUid(updateUid, formRenderWant, updateFormJsInfo, formSupplyClient);

    // Test DeleteRenderRecordByUid
    std::string deleteUid = fdp->ConsumeRandomLengthString(MAX_LENGTH);
    std::shared_ptr<FormRenderRecord> searchRecord = nullptr;
    FormRenderServiceMgr::GetInstance().DeleteRenderRecordByUid(deleteUid, searchRecord);

    return true;
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}