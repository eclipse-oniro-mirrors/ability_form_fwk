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

#include "formhostdelegatestub_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "form_host_delegate_stub.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
const std::u16string FORMMGR_INTERFACE_TOKEN = u"ohos.appexecfwk.FormMgr";
class FormHostDelegateStubFuzzTest : public FormHostDelegateStub {
public:
    FormHostDelegateStubFuzzTest() = default;
    virtual ~FormHostDelegateStubFuzzTest() = default;
    int32_t RouterEvent(const int64_t formId, const Want &want) override
    {
        return 0;
    }
    ErrCode RequestOverflow(const int64_t formId, const OverflowInfo &overflowInfo, bool isOverflow) override
    {
        return ERR_OK;
    }
    ErrCode ChangeSceneAnimationState(const int64_t formId, int32_t state) override
    {
        return ERR_OK;
    }
    ErrCode GetFormRect(const int64_t formId, Rect &rect) override
    {
        return ERR_OK;
    }
    ErrCode GetLiveFormStatus(std::unordered_map<std::string, std::string> &liveFormStatusMap) override
    {
        return ERR_OK;
    }
    ErrCode TemplateFormDetailInfoChange(
        const std::vector<AppExecFwk::TemplateFormDetailInfo> &templateFormInfo) override
    {
        return ERR_OK;
    }
};
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    FormHostDelegateStubFuzzTest formHostDelegateStub;
    uint32_t code = GetU32Data(data);
    MessageParcel datas;
    datas.WriteInterfaceToken(FORMMGR_INTERFACE_TOKEN);
    datas.WriteBuffer(data, size);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    formHostDelegateStub.OnRemoteRequest(code, datas, reply, option);
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

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}

