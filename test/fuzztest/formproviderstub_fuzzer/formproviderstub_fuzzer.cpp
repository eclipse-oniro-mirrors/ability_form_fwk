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

#include "formproviderstub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "form_provider_stub.h"
#include "message_parcel.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t THRESHOLD = 10;
constexpr int32_t OFFSET = 4;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.appexecfwk.FormMgr";

class FormProviderStubFuzzTest : public FormProviderStub {
public:
    FormProviderStubFuzzTest() = default;
    virtual ~FormProviderStubFuzzTest() = default;
    int AcquireProviderFormInfo(const FormJsInfo &formJsInfo, const Want &want,
        const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int NotifyFormDelete(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int NotifyFormsDelete(const std::vector<int64_t> &formIds, const Want &want,
        const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int NotifyFormUpdate(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int EventNotify(const std::vector<int64_t> &formIds, const int32_t formVisibleType,
        const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int NotifyFormCastTempForm(const int64_t formId, const Want &want, const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int FireFormEvent(const int64_t formId, const std::string &message, const Want &want,
        const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }

    int AcquireState(const Want &wantArg, const std::string &provider, const Want &want,
        const sptr<IRemoteObject> &callerToken) override
    {
        return 0;
    }
    int32_t AcquireShareFormData(int64_t formId, const std::string &remoteDeviceId,
        const sptr<IRemoteObject> &formSupplyCallback, int64_t requestCode) override
    {
        return 0;
    }
};

uint32_t Convert2Uint32(const uint8_t* ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    // 将第0个数字左移24位，将第1个数字左移16位，将第2个数字左移8位，第3个数字不左移
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }
    uint32_t code = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;

    MessageParcel data;
    data.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;

    std::shared_ptr<FormProviderStub> formproviderstub = std::make_shared<FormProviderStubFuzzTest>();

    formproviderstub->OnRemoteRequest(code, data, reply, option);

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::THRESHOLD) {
        return 0;
    }

    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
