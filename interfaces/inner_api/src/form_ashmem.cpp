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

#include "form_ashmem.h"

#include "fms_log_wrapper.h"
#include "message_parcel.h"

namespace OHOS {
namespace AppExecFwk {
FormAshmem::~FormAshmem()
{
    if (ashmem_ != nullptr) {
        ashmem_->CloseAshmem();
    }
    HILOG_INFO("formAshmem destroy");
}

bool FormAshmem::Marshalling(Parcel &parcel) const
{
    MessageParcel* messageParcel = (MessageParcel*)&parcel;
    if (!messageParcel->WriteAshmem(ashmem_)) {
        HILOG_ERROR("WriteAshmem failed");
        return false;
    }
    return true;
}

bool FormAshmem::ReadFromParcel(Parcel &parcel)
{
    MessageParcel* messageParcel = (MessageParcel*)&parcel;
    ashmem_ = messageParcel->ReadAshmem();
    if (ashmem_ == nullptr) {
        return false;
    }
    HILOG_INFO("fd:%{public}d,size:%{public}d", ashmem_->GetAshmemFd(), ashmem_->GetAshmemSize());
    return true;
}

FormAshmem* FormAshmem::Unmarshalling(Parcel &parcel)
{
    FormAshmem* formAshmem = new (std::nothrow) FormAshmem();
    if (formAshmem != nullptr && !formAshmem->ReadFromParcel(parcel)) {
        delete formAshmem;
        formAshmem = nullptr;
    }
    return formAshmem;
}

bool FormAshmem::WriteToAshmem(std::string name, char *data, int32_t size)
{
    if (size <= 0) {
        HILOG_ERROR("invalid param, size= %{public}d", size);
    }

    ashmem_ = Ashmem::CreateAshmem(name.c_str(), size);
    if (ashmem_ == nullptr) {
        HILOG_ERROR("create shared memory fail");
        return false;
    }

    bool ret = ashmem_->MapReadAndWriteAshmem();
    if (!ret) {
        HILOG_ERROR("map shared memory fail");
        return false;
    }

    ret = ashmem_->WriteToAshmem(data, size, 0);
    if (!ret) {
        ashmem_->UnmapAshmem();
        HILOG_ERROR("write image data to shared memory fail");
        return false;
    }

    ashmem_->UnmapAshmem();
    return true;
}

sptr<Ashmem> FormAshmem::GetAshmem() const
{
    return ashmem_;
}

int32_t FormAshmem::GetAshmemSize()
{
    if (ashmem_ == nullptr) {
        return 0;
    }
    return ashmem_->GetAshmemSize();
}

int32_t FormAshmem::GetAshmemFd()
{
    if (ashmem_ == nullptr) {
        return -1;
    }
    return ashmem_->GetAshmemFd();
}

int FormAshmem::TestFormId1(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId2(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId3(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId4(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId5(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId6(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId7(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId8(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId9(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId10(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId11(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId12(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId13(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId14(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}

int FormAshmem::TestFormId15(int &formId)
{
    switch (formId) {
        case int(TestNum::Num1): return formId;
        case int(TestNum::Num2): return formId;
        case int(TestNum::Num3): return formId;
        case int(TestNum::Num4): return formId;
        case int(TestNum::Num5): return formId;
        case int(TestNum::Num6): return formId;
        case int(TestNum::Num7): return formId;
        case int(TestNum::Num8): return formId;
        case int(TestNum::Num9): return formId;
        case int(TestNum::Num10): return formId;
        case int(TestNum::Num11): return formId;
        case int(TestNum::Num12): return formId;
        case int(TestNum::Num13): return formId;
        case int(TestNum::Num14): return formId;
        case int(TestNum::Num15): return formId;
        case int(TestNum::Num16): return formId;
        case int(TestNum::Num17): return formId;
        case int(TestNum::Num18): return formId;
        case int(TestNum::Num19): return formId;
        case int(TestNum::Num20): return formId;
        case int(TestNum::Num21): return formId;
        case int(TestNum::Num22): return formId;
        case int(TestNum::Num23): return formId;
        case int(TestNum::Num24): return formId;
        case int(TestNum::Num25): return formId;
        case int(TestNum::Num26): return formId;
        case int(TestNum::Num27): return formId;
        case int(TestNum::Num28): return formId;
        case int(TestNum::Num29): return formId;
        case int(TestNum::Num30): return formId;
        case int(TestNum::Num31): return formId;
        case int(TestNum::Num32): return formId;
        case int(TestNum::Num33): return formId;
        case int(TestNum::Num34): return formId;
        case int(TestNum::Num35): return formId;
        case int(TestNum::Num36): return formId;
        case int(TestNum::Num37): return formId;
        case int(TestNum::Num38): return formId;
        case int(TestNum::Num39): return formId;
        case int(TestNum::Num40): return formId;
        default: return formId;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
