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

#include "formcachemgr_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "data_center/form_cache_mgr.h"
#include "common/event/form_event_handler.h"
#include "common/util/form_serial_queue.h"
#undef private
#undef protected
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr int64_t EVENT_MSG = 1;
constexpr int64_t EVENT_ID = 2;
bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    int64_t formId = fdp->ConsumeIntegral<int64_t>();
    std::string datas = fdp->ConsumeRandomLengthString();
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    FormCacheMgr::GetInstance().GetData(formId, datas, imageDataMap);

    FormProviderData formProviderData;
    formProviderData.SetDataString(datas);
    FormCacheMgr::GetInstance().AddData(formId, formProviderData);

    FormCacheMgr::GetInstance().DeleteData(formId);
    FormEventHandler formEventHandler(nullptr);
    AppExecFwk::InnerEvent::Pointer event = AppExecFwk::InnerEvent::Get();
    formEventHandler.ProcessEvent(EVENT_MSG, EVENT_ID);
    formEventHandler.GetEventId();
    std::shared_ptr<FormEventTimeoutObserver> observer = nullptr;
    formEventHandler.RegisterEventTimeoutObserver(observer);
    formEventHandler.UnregisterEventTimeoutObserver(observer);
    return FormCacheMgr::GetInstance().NeedAcquireProviderData(formId);
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