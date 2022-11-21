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

#include "form_provider_data.h"

using Parcel = OHOS::Parcel;

namespace OHOS {

int32_t Parcel::ReadInt32()
{
    return 1;
}

bool Parcel::WriteInt32(int32_t value)
{
    if(value) {
        return false;
    } else{
        return true;
    }
}

namespace AppExecFwk {
namespace {
bool g_mockConvertRawImageDataRet = true;
bool g_mockGetImageDataMapRet = true;
}

void MockConvertRawImageData(bool mockRet)
{
    g_mockConvertRawImageDataRet = mockRet;
}

void MockGetImageDataMap(bool mockRet)
{
    g_mockGetImageDataMapRet = mockRet;
}

bool FormProviderData::ConvertRawImageData()
{
    return g_mockConvertRawImageDataRet;
}

std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> FormProviderData::GetImageDataMap() const
{
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    int32_t a = 1;
    int32_t maxNumber = 130;
    int32_t normalNumber = 100;
    if (g_mockGetImageDataMapRet) {
        for (int32_t i = 0; i < maxNumber; i++) {
            imageDataMap.emplace("aa" + std::to_string(i), std::make_pair(formAshmem, a));
        }
    } else {
        for (int32_t i = 0; i < normalNumber; i++) {
            imageDataMap.emplace("aa" + std::to_string(i), std::make_pair(formAshmem, a));
        }
    }
    return imageDataMap;
}
} // namespace AppExecFwk
} // namespace OHOS
