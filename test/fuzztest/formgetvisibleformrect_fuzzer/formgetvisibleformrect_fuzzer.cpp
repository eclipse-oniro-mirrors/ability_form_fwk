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

#include "formgetvisibleformrect_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#define protected public
#include "form_mgr.h"
#include "form_instance.h"
#undef private
#undef protected

using namespace OHOS::AppExecFwk;

namespace OHOS {
constexpr int32_t MAX_LENGTH = 256;
constexpr int64_t MAX_FORM_ID = 10000;
constexpr int64_t MIN_FORM_ID = -10000;    // negative ids exercise the guard branch
constexpr double MAX_COORD = 1e9;
constexpr double MIN_COORD = -1e9;

int64_t GenerateFormId(FuzzedDataProvider *fdp)
{
    return fdp->ConsumeIntegralInRange<int64_t>(MIN_FORM_ID, MAX_FORM_ID);
}

Rect GenerateRect(FuzzedDataProvider *fdp)
{
    Rect rect;
    rect.left = fdp->ConsumeFloatingPointInRange<double>(MIN_COORD, MAX_COORD);
    rect.top = fdp->ConsumeFloatingPointInRange<double>(MIN_COORD, MAX_COORD);
    rect.width = fdp->ConsumeFloatingPointInRange<double>(MIN_COORD, MAX_COORD);
    rect.height = fdp->ConsumeFloatingPointInRange<double>(MIN_COORD, MAX_COORD);
    return rect;
}

bool DoSomethingInterestingWithMyAPI(FuzzedDataProvider *fdp)
{
    if (fdp == nullptr) {
        return true;
    }
    int64_t formId = GenerateFormId(fdp);
    Rect rect = GenerateRect(fdp);
    // Rect parcel round-trip against fuzzed payload
    // (Parcelable path fully reused by the new API)
    MessageParcel parcel;
    if (rect.Marshalling(parcel)) {
        parcel.RewindRead(0);
        Rect *read = Rect::Unmarshalling(parcel);
        if (read != nullptr) {
            delete read;
        }
    }
    // Kit entry: negative/invalid ids must be rejected without IPC
    FormMgr::GetInstance().GetVisibleFormRect(formId, rect);
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    OHOS::DoSomethingInterestingWithMyAPI(&fdp);
    return 0;
}
