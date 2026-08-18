/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <sys/mman.h>
#include <unistd.h>

#include "ashmem.h"
#include "fms_log_wrapper.h"
#include "ipc_file_descriptor.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
constexpr int32_t MAX_FORM_DATA_BUFFER_SIZE = 128 * 1024 * 1024; // 128M

namespace {
bool ReadStringField(Parcel &parcel, const char *fieldName, std::string &out, std::u16string &tmp)
{
    if (!parcel.ReadString16(tmp)) {
        HILOG_ERROR("read %{public}s failed", fieldName);
        return false;
    }
    out = Str16ToStr8(tmp);
    return true;
}

bool ReadInt32Field(Parcel &parcel, const char *fieldName, int32_t &out)
{
    if (!parcel.ReadInt32(out)) {
        HILOG_ERROR("read %{public}s failed", fieldName);
        return false;
    }
    return true;
}

bool ReadBoolField(Parcel &parcel, const char *fieldName, bool &out)
{
    if (!parcel.ReadBool(out)) {
        HILOG_ERROR("read %{public}s failed", fieldName);
        return false;
    }
    return true;
}

bool ReadUint32Field(Parcel &parcel, const char *fieldName, uint32_t &out)
{
    if (!parcel.ReadUint32(out)) {
        HILOG_ERROR("read %{public}s failed", fieldName);
        return false;
    }
    return true;
}
}

bool FormJsInfo::ReadFromParcel(Parcel &parcel)
{
    std::u16string strValue;
    if (!parcel.ReadInt64(formId)) {
        HILOG_ERROR("read formId failed");
        return false;
    }
    if (!ReadStringField(parcel, "formName", formName, strValue) ||
        !ReadStringField(parcel, "bundleName", bundleName, strValue) ||
        !ReadStringField(parcel, "abilityName", abilityName, strValue) ||
        !ReadStringField(parcel, "moduleName", moduleName, strValue) ||
        !ReadBoolField(parcel, "formTempFlag", formTempFlag) ||
        !ReadStringField(parcel, "jsFormCodePath", jsFormCodePath, strValue)) {
        return false;
    }
    int32_t formDataLength = 0;
    if (!ReadInt32Field(parcel, "formDataLength", formDataLength)) {
        return false;
    }
    HILOG_INFO("ReadFromParcel data length is %{public}d , formId:%{public}" PRId64, formDataLength, formId);
    if (formDataLength > BIG_DATA) {
        if (!ReadAshmemFormData(parcel, formDataLength, formData)) {
            return false;
        }
    } else {
        if (!ReadStringField(parcel, "formData", formData, strValue)) {
            return false;
        }
    }
    if (!ReadFormFields(parcel, strValue)) {
        return false;
    }
    std::unique_ptr<FormProviderData> bindingData(parcel.ReadParcelable<FormProviderData>());
    if (bindingData == nullptr) {
        return false;
    }
    formProviderData = *bindingData;
    ReadImageData(parcel);
    ReadPkgNameMap(parcel);
    return true;
}

bool FormJsInfo::ReadFormFields(Parcel &parcel, std::u16string &strValue)
{
    if (!ReadStringField(parcel, "formSrc", formSrc, strValue) ||
        !ReadInt32Field(parcel, "designWidth", formWindow.designWidth) ||
        !ReadBoolField(parcel, "autoDesignWidth", formWindow.autoDesignWidth) ||
        !ReadUint32Field(parcel, "versionCode", versionCode) ||
        !ReadStringField(parcel, "versionName", versionName, strValue) ||
        !ReadUint32Field(parcel, "compatibleVersion", compatibleVersion)) {
        return false;
    }
    int32_t typeData = 0;
    int32_t uiSyntaxData = 0;
    if (!ReadInt32Field(parcel, "type", typeData) ||
        !ReadInt32Field(parcel, "uiSyntax", uiSyntaxData) ||
        !ReadBoolField(parcel, "isDynamic", isDynamic) ||
        !ReadBoolField(parcel, "transparencyEnabled", transparencyEnabled) ||
        !ReadStringField(parcel, "templateFormImperativeFwk", templateFormImperativeFwk, strValue)) {
        return false;
    }
    type = static_cast<FormType>(typeData);
    uiSyntax = static_cast<FormType>(uiSyntaxData);
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
    if (!WriteFormData(parcel) || !parcel.WriteString16(Str8ToStr16(formSrc))) {
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
    if (!parcel.WriteString16(Str8ToStr16(templateFormImperativeFwk))) {
        return false;
    }
    if (!WriteObjects(parcel)) {
        return false;
    }
    return true;
}

bool FormJsInfo::WriteFormData(Parcel &parcel) const
{
    int32_t formDataLength = static_cast<int32_t>(formData.length());
    if (!parcel.WriteInt32(formDataLength)) {
        HILOG_ERROR("WriteInt32 formDataLength failed");
        return false;
    }
    if (formDataLength > BIG_DATA) {
        HILOG_INFO("WriteFormData data length is %{public}d", formDataLength);
        return WriteAshmemFormData(parcel, formDataLength, formData.c_str());
    } else {
        return parcel.WriteString16(Str8ToStr16(formData));
    }
}

bool FormJsInfo::WriteAshmemFormData(Parcel &parcel, int32_t size, const char *dataPtr) const
{
    if (dataPtr == nullptr || size <= 0 || size > MAX_FORM_DATA_BUFFER_SIZE) {
        HILOG_ERROR("invalid param, dataPtr is null or size is %{public}d", size);
        return false;
    }
    std::string name = "FormJsInfoFormData";
    int fd = AshmemCreate(name.c_str(), size);
    if (fd < 0) {
        HILOG_ERROR("AshmemCreate failed, size:%{public}d", size);
        return false;
    }
    fdsan_exchange_owner_tag(fd, 0, Constants::FORM_DOMAIN_ID);
    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    if (result < 0) {
        HILOG_ERROR("AshmemSetProt failed, result:%{public}d", result);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return false;
    }
    void *ptr = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        HILOG_ERROR("mmap failed, errno:%{public}d", errno);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return false;
    }
    if (memcpy_s(ptr, size, dataPtr, size) != EOK) {
        ::munmap(ptr, size);
        HILOG_ERROR("memcpy_s failed, errno:%{public}d, size:%{public}d", errno, size);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return false;
    }
    ::munmap(ptr, size);
    if (AshmemSetProt(fd, PROT_READ) < 0) {
        HILOG_WARN("AshmemSetProt PROT_READ failed, errno:%{public}d", errno);
    }
    if (!WriteFdToParcel(parcel, fd)) {
        HILOG_ERROR("WriteFdToParcel failed");
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return false;
    }
    fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
    HILOG_INFO("WriteAshmemFormData success, size:%{public}d", size);
    return true;
}

bool FormJsInfo::WriteFdToParcel(Parcel &parcel, int fd) const
{
    if (fd < 0) {
        HILOG_ERROR("invalid fd:%{public}d", fd);
        return false;
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        HILOG_ERROR("dup failed, fd:%{public}d", fd);
        return false;
    }
    sptr<IPCFileDescriptor> descriptor = new IPCFileDescriptor(dupFd);
    bool result = parcel.WriteObject<IPCFileDescriptor>(descriptor);
    if (!result) {
        fdsan_exchange_owner_tag(dupFd, 0, Constants::FORM_DOMAIN_ID);
        fdsan_close_with_tag(dupFd, Constants::FORM_DOMAIN_ID);
    }
    return result;
}

int FormJsInfo::ReadFdFromParcel(Parcel &parcel)
{
    sptr<IPCFileDescriptor> descriptor = parcel.ReadObject<IPCFileDescriptor>();
    if (descriptor == nullptr) {
        HILOG_ERROR("ReadObject IPCFileDescriptor failed");
        return -1;
    }
    int fd = descriptor->GetFd();
    if (fd < 0) {
        HILOG_ERROR("get fd failed, fd:%{public}d", fd);
        return -1;
    }
    return dup(fd);
}

bool FormJsInfo::CheckAshmemSize(int fd, int32_t bufferSize)
{
    if (fd < 0) {
        return false;
    }
    int32_t ashmemSize = AshmemGetSize(fd);
    return bufferSize == ashmemSize;
}

bool FormJsInfo::ReadAshmemFormData(Parcel &parcel, int32_t formDataLength, std::string &outFormData)
{
    int fd = ReadFdFromParcel(parcel);
    if (fd < 0) {
        HILOG_ERROR("ReadFdFromParcel failed");
        return false;
    }
    fdsan_exchange_owner_tag(fd, 0, Constants::FORM_DOMAIN_ID);
    if (formDataLength <= 0 || formDataLength > MAX_FORM_DATA_BUFFER_SIZE) {
        HILOG_ERROR("invalid formDataLength:%{public}d", formDataLength);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return false;
    }
    if (!CheckAshmemSize(fd, formDataLength)) {
        HILOG_ERROR("CheckAshmemSize failed, formDataLength:%{public}d", formDataLength);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return false;
    }
    void *ptr = ::mmap(nullptr, formDataLength, PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        HILOG_ERROR("mmap failed, errno:%{public}d", errno);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return false;
    }
    outFormData = std::string(static_cast<const char*>(ptr), formDataLength);
    ::munmap(ptr, formDataLength);
    fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
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
    HILOG_DEBUG("call");
    auto imageDateState = formProviderData.GetImageDataState();
    if (!parcel.WriteInt32(imageDateState)) {
        return false;
    }
    HILOG_DEBUG("imageDateState is %{public}d", imageDateState);
    switch (imageDateState) {
        case FormProviderData::IMAGE_DATA_STATE_ADDED: {
            auto sharedImageMap = formProviderData.GetImageDataMap();
            auto size = sharedImageMap.size();
            if (!parcel.WriteInt32(size)) {
                return false;
            }
            if (size > IMAGE_DATA_THRESHOLD) {
                HILOG_ERROR("unexpected image number %{public}zu", size);
                return false;
            }
            for (const auto &entry : sharedImageMap) {
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
            HILOG_WARN("unexpected imageDateState %{public}d", imageDateState);
            break;
        }
    }
    HILOG_DEBUG("end");
    return true;
}

void FormJsInfo::ReadImageData(Parcel &parcel)
{
    HILOG_DEBUG("call");
    int32_t imageDateState = 0;
    if (!parcel.ReadInt32(imageDateState)) {
        HILOG_ERROR("read imageDataState failed");
        return;
    }
    HILOG_DEBUG("imageDateState is %{public}d", imageDateState);
    switch (imageDateState) {
        case FormProviderData::IMAGE_DATA_STATE_ADDED:
            ReadAddedImages(parcel);
            break;
        case FormProviderData::IMAGE_DATA_STATE_NO_OPERATION:
            break;
        case FormProviderData::IMAGE_DATA_STATE_REMOVED:
            break;
        default:
            HILOG_WARN("unexpected imageDateState %{public}d", imageDateState);
            break;
    }
    HILOG_DEBUG("end");
}

void FormJsInfo::ReadAddedImages(Parcel &parcel)
{
    int32_t size = 0;
    if (!parcel.ReadInt32(size)) {
        HILOG_ERROR("read image size failed");
        return;
    }
    HILOG_INFO("image number is %{public}d", size);
    if (size > IMAGE_DATA_THRESHOLD) {
        HILOG_WARN("unexpected image number %{public}d", size);
        return;
    }
    for (int32_t i = 0; i < size; i++) {
        if (!ReadSingleImage(parcel)) {
            return;
        }
    }
}

bool FormJsInfo::ReadSingleImage(Parcel &parcel)
{
    sptr<FormAshmem> formAshmem = parcel.ReadParcelable<FormAshmem>();
    if (formAshmem == nullptr) {
        HILOG_ERROR("null ashmem");
        return false;
    }
    std::u16string picNameStr;
    if (!parcel.ReadString16(picNameStr)) {
        HILOG_ERROR("read picName failed");
        return false;
    }
    auto picName = Str16ToStr8(picNameStr);
    HILOG_INFO("picName:%{public}s", picName.c_str());
    imageDataMap[picName] = formAshmem;
    return true;
}

bool FormJsInfo::ConvertRawImageData()
{
    HILOG_DEBUG("call");
    if (!formProviderData.ConvertRawImageData()) {
        return false;
    }
    auto sharedImageMap = formProviderData.GetImageDataMap();
    auto size = sharedImageMap.size();
    if (size > IMAGE_DATA_THRESHOLD) {
        HILOG_ERROR("unexpected image number %{public}zu", size);
        return false;
    }
    for (const auto &entry : sharedImageMap) {
        imageDataMap[entry.first] = entry.second.first;
    }
    return true;
}

bool FormJsInfo::WritePkgNameMap(Parcel &parcel) const
{
    HILOG_DEBUG("call");
    std::vector<std::string> keys;
    std::vector<std::string> values;

    for (const auto &pkgNameInfo : modulePkgNameMap) {
        keys.emplace_back(pkgNameInfo.first);
        values.emplace_back(pkgNameInfo.second);
    }

    if (!parcel.WriteStringVector(keys)) {
        HILOG_ERROR("WriteStringVector for keys failed");
        return false;
    }
    if (!parcel.WriteStringVector(values)) {
        HILOG_ERROR("WriteStringVector for values failed");
        return false;
    }
    return true;
}

void FormJsInfo::ReadPkgNameMap(Parcel &parcel)
{
    HILOG_DEBUG("call");
    std::vector<std::string> keys;
    std::vector<std::string> values;
    if (!parcel.ReadStringVector(&keys)) {
        HILOG_ERROR("ReadStringVector for keys failed");
        return;
    }
    if (!parcel.ReadStringVector(&values)) {
        HILOG_ERROR("ReadStringVector for values failed");
        return;
    }
    size_t keySize = keys.size();
    size_t valueSize = values.size();
    if (keySize != valueSize) {
        HILOG_ERROR("ReadFromParcel failed, invalid size");
        return;
    }
    for (size_t index = 0; index < keySize; index++) {
        modulePkgNameMap.emplace(keys.at(index), values.at(index));
    }
}

FormJsInfo FormJsInfo::CopyFormJsInfoWithoutFormData() const
{
    FormJsInfo copyFormJsInfo;
    copyFormJsInfo.formId = formId;
    copyFormJsInfo.formName = formName;
    copyFormJsInfo.bundleName = bundleName;
    copyFormJsInfo.abilityName = abilityName;
    copyFormJsInfo.moduleName = moduleName;
    copyFormJsInfo.modulePkgNameMap = modulePkgNameMap;
    copyFormJsInfo.formTempFlag = formTempFlag;
    copyFormJsInfo.jsFormCodePath = jsFormCodePath;
    copyFormJsInfo.formData = "";
    copyFormJsInfo.imageDataMap = {};
    copyFormJsInfo.formProviderData = FormProviderData();
    copyFormJsInfo.formSrc = "";
    copyFormJsInfo.formWindow = formWindow;
    copyFormJsInfo.versionCode = versionCode;
    copyFormJsInfo.versionName = versionName;
    copyFormJsInfo.compatibleVersion = compatibleVersion;
    copyFormJsInfo.type = type;
    copyFormJsInfo.uiSyntax = uiSyntax;
    copyFormJsInfo.isDynamic = isDynamic;
    copyFormJsInfo.transparencyEnabled = transparencyEnabled;
    copyFormJsInfo.templateFormImperativeFwk = templateFormImperativeFwk;
    return copyFormJsInfo;
}
} // namespace AppExecFwk
} // namespace OHOS