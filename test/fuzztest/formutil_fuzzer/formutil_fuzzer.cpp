/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "formutil_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "form_constants.h"
#define private public
#define protected public
#include "feature/free_install/free_install_status_callback_proxy.h"
#include "feature/free_install/free_install_status_callback_stub.h"
#include "common/util/form_util.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
class FreeInstallStatusCallBackStubFuzzTest : public FreeInstallStatusCallBackStub {
public:
    FreeInstallStatusCallBackStubFuzzTest() = default;
    virtual ~FreeInstallStatusCallBackStubFuzzTest() = default;
    void OnInstallFinished(int32_t resultCode, const Want &want, int32_t userId) override
    {}
};
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    FormUtil formUtil;
    std::string formName = fdp->ConsumeRandomLengthString();
    int32_t specificationId = fdp->ConsumeIntegral<int32_t>();
    bool isTemporaryForm = fdp->ConsumeBool();
    Want want;
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, formName);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, specificationId);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, isTemporaryForm);
    std::string uri = fdp->ConsumeRandomLengthString();
    int32_t connectId = fdp->ConsumeIntegral<int32_t>();
    want.SetParam(Constants::FORM_CONNECT_ID, connectId);
    want.SetParam(Constants::FORM_SUPPLY_INFO, uri);
    int64_t udidHash = fdp->ConsumeIntegral<int64_t>();
    formUtil.GenerateFormId(udidHash);
    uint64_t formId = fdp->ConsumeIntegral<uint64_t>();
    uint64_t udidHashs = fdp->ConsumeIntegral<uint64_t>();
    formUtil.PaddingUdidHash(formId, udidHashs);
    formUtil.GetCurrentNanosecond();
    formUtil.GetCurrentMillisecond();
    formUtil.GetCurrentAccountId();
    formUtil.GetNowMillisecond();
    formUtil.DeleteFormId(udidHash);
    int radix = fdp->ConsumeIntegral<int>();
    formUtil.ConvertStringToInt(formName, radix);
    formUtil.ConvertStringToLongLong(formName, radix);
    std::string strInfo = fdp->ConsumeRandomLengthString();
    int64_t convertValue = fdp->ConsumeIntegral<int64_t>();
    formUtil.ConvertStringToInt64(strInfo, convertValue);
    sptr<IRemoteObject> impl = nullptr;
    FreeInstallStatusCallBackProxy freeInstallStatusCallBackProxy(impl);
    FreeInstallStatusCallBackStubFuzzTest freeInstallStatusCallBackStubFuzzTest;
    MessageParcel datas;
    MessageParcel reply;
    freeInstallStatusCallBackStubFuzzTest.OnInstallFinishedInner(datas, reply);
    uint32_t code = fdp->ConsumeIntegral<uint32_t>();
    MessageOption option;
    freeInstallStatusCallBackStubFuzzTest.OnRemoteRequest(code, datas, reply, option);
    return formUtil.GenerateUdidHash(udidHash);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}