/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_js_info.h"
#include "fms_log_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool FormJsInfo::ReadFromParcel(Parcel &parcel)
{
    formId = parcel.ReadInt64();
    formName = Str16ToStr8(parcel.ReadString16());
    bundleName = Str16ToStr8(parcel.ReadString16());
    abilityName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());

    formTempFlag = parcel.ReadBool();
    jsFormCodePath = Str16ToStr8(parcel.ReadString16());
    formData = Str16ToStr8(parcel.ReadString16());

    formSrc = Str16ToStr8(parcel.ReadString16());
    formWindow.designWidth = parcel.ReadInt32();
    formWindow.autoDesignWidth = parcel.ReadBool();

    versionCode = parcel.ReadUint32();
    versionName = Str16ToStr8(parcel.ReadString16());
    compatibleVersion = parcel.ReadUint32();
    int32_t typeData = parcel.ReadInt32();
    type = static_cast<FormType>(typeData);
    uiSyntax = static_cast<FormType>(parcel.ReadInt32());
    isDynamic = parcel.ReadBool();
    transparencyEnabled = parcel.ReadBool();

    std::unique_ptr<FormProviderData> bindingData(parcel.ReadParcelable<FormProviderData>());
    if (bindingData == nullptr) {
        return false;
    }
    formProviderData = *bindingData;

    ReadImageData(parcel);
    ReadPkgNameMap(parcel);
    return true;
}

FormJsInfo *FormJsInfo::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormJsInfo> formJsInfo = std::make_unique<FormJsInfo>();
    if (formJsInfo && !formJsInfo->ReadFromParcel(parcel)) {
        formJsInfo = nullptr;
    }
    return formJsInfo.release();
}

bool FormJsInfo::Marshalling(Parcel &parcel) const
{
    // write formId
    if (!parcel.WriteInt64(formId)) {
        return false;
    }
    // write formName
    if (!parcel.WriteString16(Str8ToStr16(formName))) {
        return false;
    }
    // write bundleName
    if (!parcel.WriteString16(Str8ToStr16(bundleName))) {
        return false;
    }
    // write abilityName
    if (!parcel.WriteString16(Str8ToStr16(abilityName))) {
        return false;
    }

    // write moduleName
    if (!parcel.WriteString16(Str8ToStr16(moduleName))) {
        return false;
    }

    // write tempFlag
    if (!parcel.WriteBool(formTempFlag)) {
        return false;
    }

    // write jsFormCodePath
    if (!parcel.WriteString16(Str8ToStr16(jsFormCodePath))) {
        return false;
    }

    // write formData and formSrc
    if (!parcel.WriteString16(Str8ToStr16(formData)) || !parcel.WriteString16(Str8ToStr16(formSrc))) {
        return false;
    }

    // write formWindow
    if (!parcel.WriteInt32(formWindow.designWidth) || !parcel.WriteBool(formWindow.autoDesignWidth)) {
        return false;
    }

    // write version
    if (!parcel.WriteUint32(versionCode) ||
        !parcel.WriteString16(Str8ToStr16(versionName)) ||
        !parcel.WriteUint32(compatibleVersion)) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(type))) {
        return false;
    }
    if (!parcel.WriteInt32(static_cast<int32_t>(uiSyntax))) {
        return false;
    }
    if (!parcel.WriteBool(isDynamic) || !parcel.WriteBool(transparencyEnabled)) {
        return false;
    }
    if (!WriteObjects(parcel)) {
        return false;
    }
    return true;
}

bool FormJsInfo::WriteObjects(Parcel &parcel) const
{
    // write formProviderData
    if (!parcel.WriteParcelable(&formProviderData)) {
        return false;
    }

    if (!WriteImageData(parcel)) {
        return false;
    }

    if (!WritePkgNameMap(parcel)) {
        return false;
    }
    return true;
}

bool FormJsInfo::WriteImageData(Parcel &parcel) const
{
    HILOG_DEBUG("%{public}s called", __func__);
    auto imageDateState = formProviderData.GetImageDataState();
    if (!parcel.WriteInt32(imageDateState)) {
        return false;
    }
    HILOG_DEBUG("%{public}s imageDateState is %{public}d", __func__, imageDateState);
    switch (imageDateState) {
        case FormProviderData::IMAGE_DATA_STATE_ADDED: {
            auto sharedImageMap = formProviderData.GetImageDataMap();
            auto size = sharedImageMap.size();
            if (!parcel.WriteInt32(size)) {
                return false;
            }
            if (size > IMAGE_DATA_THRESHOLD) {
                HILOG_INFO("%{public}s unexpected image number %{public}zu", __func__, size);
                break;
            }
            for (auto entry : sharedImageMap) {
                if (!parcel.WriteParcelable(entry.second.first)) {
                    return false;
                }
                if (!parcel.WriteString16(Str8ToStr16(entry.first))) {
                    return false;
                }
            }
            break;
        }
        case FormProviderData::IMAGE_DATA_STATE_NO_OPERATION:
            break;
        case FormProviderData::IMAGE_DATA_STATE_REMOVED:
            break;
        default: {
            HILOG_WARN("%{public}s unexpected imageDateState %{public}d", __func__, imageDateState);
            break;
        }
    }
    HILOG_DEBUG("%{public}s end", __func__);
    return true;
}

void FormJsInfo::ReadImageData(Parcel &parcel)
{
    HILOG_DEBUG("%{public}s called", __func__);
    auto imageDateState = parcel.ReadInt32();
    HILOG_DEBUG("%{public}s imageDateState is %{public}d", __func__, imageDateState);
    switch (imageDateState) {
        case FormProviderData::IMAGE_DATA_STATE_ADDED: {
            auto size = parcel.ReadInt32();
            HILOG_INFO("%{public}s image numer is %{public}d",  __func__, size);
            if (size > IMAGE_DATA_THRESHOLD) {
                HILOG_WARN("%{public}s unexpected image number %{public}d", __func__, size);
                break;
            }
            for (auto i = 0; i < size; i++) {
                sptr<FormAshmem> formAshmem = parcel.ReadParcelable<FormAshmem>();
                if (formAshmem == nullptr) {
                    HILOG_ERROR("failed, ashmem is nullptr");
                    return;
                }
                auto picName = Str16ToStr8(parcel.ReadString16());
                HILOG_INFO("picName: %{public}s", picName.c_str());
                imageDataMap[picName] = formAshmem;
            }
            break;
        }
        case FormProviderData::IMAGE_DATA_STATE_NO_OPERATION:
            break;
        case FormProviderData::IMAGE_DATA_STATE_REMOVED:
            break;
        default: {
            HILOG_WARN("%{public}s unexpected imageDateState %{public}d", __func__, imageDateState);
            break;
        }
    }
    HILOG_DEBUG("%{public}s end", __func__);
    return;
}

bool FormJsInfo::ConvertRawImageData()
{
    HILOG_DEBUG("%{public}s called", __func__);
    if (!formProviderData.ConvertRawImageData()) {
        return false;
    }
    auto sharedImageMap = formProviderData.GetImageDataMap();
    auto size = sharedImageMap.size();
    if (size > IMAGE_DATA_THRESHOLD) {
        HILOG_ERROR("%{public}s unexpected image number %{public}zu", __func__, size);
        return false;
    }
    for (const auto &entry : sharedImageMap) {
        imageDataMap[entry.first] = entry.second.first;
    }
    return true;
}

bool FormJsInfo::WritePkgNameMap(Parcel &parcel) const
{
    HILOG_DEBUG("called");
    std::vector<std::string> keys;
    std::vector<std::string> values;

    for (const auto &pkgNameInfo : modulePkgNameMap) {
        keys.emplace_back(pkgNameInfo.first);
        values.emplace_back(pkgNameInfo.second);
    }

    parcel.WriteStringVector(keys);
    parcel.WriteStringVector(values);
    return true;
}

void FormJsInfo::ReadPkgNameMap(Parcel &parcel)
{
    HILOG_DEBUG("called");
    std::vector<std::string> keys;
    std::vector<std::string> values;
    if (!parcel.ReadStringVector(&keys)) {
        HILOG_ERROR("ReadStringVector for keys failed.");
        return;
    }
    if (!parcel.ReadStringVector(&values)) {
        HILOG_ERROR("ReadStringVector for values failed.");
        return;
    }
    size_t keySize = keys.size();
    size_t valueSize = values.size();
    if (keySize != valueSize) {
        HILOG_ERROR("ReadFromParcel failed, invalid size.");
        return;
    }

    std::string key;
    std::string val;
    for (size_t index = 0; index < keySize; index++) {
        key = keys.at(index);
        val = values.at(index);
        modulePkgNameMap.emplace(key, val);
    }
}
} // namespace AppExecFwk
} // namespace OHOS