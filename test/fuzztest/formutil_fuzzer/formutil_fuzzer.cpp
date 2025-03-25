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

#include "form_constants.h"
#include "common/util/form_util.h"
#define private public
#define protected public
#include "feature/free_install/free_install_status_callback_proxy.h"
#include "feature/free_install/free_install_status_callback_stub.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
class FreeInstallStatusCallBackStubFuzzTest : public FreeInstallStatusCallBackStub {
public:
    FreeInstallStatusCallBackStubFuzzTest() = default;
    virtual ~FreeInstallStatusCallBackStubFuzzTest() = default;
    void OnInstallFinished(int32_t resultCode, const Want &want, int32_t userId) override
    {}
};
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormUtil formUtil;
    std::string formName(data, size);
    int32_t specificationId = static_cast<int32_t>(GetU32Data(data));
    bool isTemporaryForm = *data % ENABLE;
    Want want;
    want.SetParam(Constants::PARAM_FORM_NAME_KEY, formName);
    want.SetParam(Constants::PARAM_FORM_DIMENSION_KEY, specificationId);
    want.SetParam(Constants::PARAM_FORM_TEMPORARY_KEY, isTemporaryForm);

    std::string uri(data, size);
    int32_t connectId = static_cast<int32_t>(GetU32Data(data));
    want.SetParam(Constants::FORM_CONNECT_ID, connectId);
    want.SetParam(Constants::FORM_SUPPLY_INFO, uri);
    
    int64_t udidHash = static_cast<int64_t>(GetU32Data(data));
    formUtil.GenerateFormId(udidHash);
    uint64_t formId = static_cast<uint64_t>(GetU32Data(data));
    uint64_t udidHashs = static_cast<uint64_t>(GetU32Data(data));
    formUtil.PaddingUdidHash(formId, udidHashs);
    formUtil.GetCurrentNanosecond();
    formUtil.GetCurrentMillisecond();
    formUtil.GetCurrentAccountId();
    formUtil.GetNowMillisecond();
    std::string strInfo(data, size);
    int64_t convertValue = static_cast<int64_t>(GetU32Data(data));
    formUtil.ConvertStringToInt64(strInfo, convertValue);
    sptr<IRemoteObject> impl = nullptr;
    FreeInstallStatusCallBackProxy freeInstallStatusCallBackProxy(impl);
    FreeInstallStatusCallBackStubFuzzTest freeInstallStatusCallBackStubFuzzTest;
    MessageParcel datas;
    MessageParcel reply;
    freeInstallStatusCallBackStubFuzzTest.OnInstallFinishedInner(datas, reply);
    uint32_t code = static_cast<uint32_t>(GetU32Data(data));
    MessageOption option;
    freeInstallStatusCallBackStubFuzzTest.OnRemoteRequest(code, datas, reply, option);
    return formUtil.GenerateUdidHash(udidHash);
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

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

