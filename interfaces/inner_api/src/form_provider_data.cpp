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

#include "form_provider_data.h"

#include <cinttypes>
#include <fstream>
#include <iostream>
#include <sys/types.h>
#include <unistd.h>

#include "fms_log_wrapper.h"
#include "form_constants.h"
#include "message_parcel.h"
#include "string_ex.h"

#include <sys/mman.h>
#include "ashmem.h"
#include "buffer_handle_parcel.h"
#include "ipc_file_descriptor.h"

namespace OHOS {
namespace AppExecFwk {
const std::string JSON_EMPTY_STRING = "{}";
const std::string JSON_IMAGES_STRING = "formImages";
constexpr int32_t READ_PARCEL_MAX_IMAGE_DATA_NUM_SIZE = 1000;
constexpr int32_t MAX_IMAGE_BYTE_SIZE = 50 * 1024 * 1024;
constexpr int32_t MAX_BUFFER_SIZE = 32 * 1024 * 1024;
constexpr int32_t BIG_DATA = 32 * 1024;
constexpr int32_t SHARE_MEM_ALLOC = 2;
/**
 * @brief Constructor.
 */
FormProviderData::FormProviderData()
{
    jsonFormProviderData_.clear();
}

/**
 * @brief A constructor used to create a {@code FormProviderData} instance with data of
 * the {@code nlohmann::json} type specified.
 * @param jsonData Indicates the data to be carried in the new {@code FormProviderData} instance,
 *             in {@code nlohmann::json} format.
 */
FormProviderData::FormProviderData(nlohmann::json &jsonData)
{
    if (!jsonData.is_object()) {
        HILOG_ERROR("jsonData not object");
        return;
    }
    jsonFormProviderData_ = jsonData;
    ParseImagesData();
}

/**
 * @brief A constructor used to create a {@code FormProviderData} instance with data of the {@code String} type
 * specified.
 * @param jsonDataString Indicates the data to be carried in the new {@code FormProviderData} instance,
 * in JSON string format.
 */
FormProviderData::FormProviderData(std::string jsonDataString)
{
    SetDataString(jsonDataString);
    ParseImagesData();
}

/**
 * @brief A constructor used to create a {@code FormProviderData} instance with data of the {@code String} type
 * specified.
 * @param jsonDataString Indicates the data to be carried in the new {@code FormProviderData} instance, in JSON
 * string format.
 * @param isUsedInFRS Indicates is used in frs
 */
FormProviderData::FormProviderData(std::string jsonDataString, bool isUsedInFRS)
{
    SetDataString(jsonDataString);
    if (!isUsedInFRS) {
        ParseImagesData();
    }
}

/**
 * @brief Updates form data in this {@code FormProviderData} object.
 * @param jsonData Indicates the new data to use, in {@code ZSONObject} format.
 */
void FormProviderData::UpdateData(nlohmann::json &jsonData)
{
    jsonFormProviderData_ = jsonData;
}
/**
 * @brief Obtains the form data stored in this {@code FormProviderData} object.
 * @return Returns json data
 */
nlohmann::json FormProviderData::GetData() const
{
    return jsonFormProviderData_;
}
/**
 * @brief Obtains the form data stored in this {@code FormProviderData} object.
 * @return Returns json string format
 */
std::string FormProviderData::GetDataString() const
{
    HILOG_DEBUG("get data string");
    std::string dataStr = jsonFormProviderData_.empty() ? "" : jsonFormProviderData_.dump();
    HILOG_DEBUG("data: %{private}s", dataStr.c_str());
    return dataStr;
}

/**
 * @brief Adds an image to this {@code FormProviderData} instance.
 * @param picName Indicates the name of the image to add.
 * @param data Indicates the binary data of the image content.
 */
void FormProviderData::AddImageData(const std::string &picName, const std::shared_ptr<char> &data, int32_t size)
{
    if ((picName.length() == 0) || (!data)) {
        HILOG_ERROR("null inputParam");
        return;
    }

    rawImageBytesMap_[picName] = std::make_pair(data, size);

    imageDataState_ = IMAGE_DATA_STATE_ADDED;
}

bool FormProviderData::isValidSize(off_t offSize)
{
    if (offSize <= 0) {
        HILOG_ERROR("Get file size failed");
        return false;
    }
    if (offSize > INT32_MAX) {
        HILOG_ERROR("File size exceeds int32_t limit");
        return false;
    }
    return true;
}

/**
 * @brief Adds an image to this {@code FormProviderData} instance.
 * @param picName Indicates the name of the image to add.
 * @param data Indicates the binary data of the image content.
 */
void FormProviderData::AddImageData(const std::string &picName, int fd)
{
    HILOG_BRIEF("fd is %{public}d, picName:%{public}s", fd, picName.c_str());
    if (fd < 0) {
        HILOG_ERROR("invalid fd");
        return;
    }

    off_t offSize = lseek(fd, 0L, SEEK_END);
    if (!isValidSize(offSize)) {
        close(fd);
        return;
    }
    int32_t size = static_cast<int32_t>(offSize);
    HILOG_BRIEF("File size is %{public}d", size);
    if (lseek(fd, 0L, SEEK_SET) == -1) {
        close(fd);
        return;
    }
    if (size > MAX_IMAGE_BYTE_SIZE) {
        HILOG_ERROR("File is too large");
        close(fd);
        return;
    }
    char* bytes = new (std::nothrow) char[size];
    if (bytes == nullptr) {
        HILOG_ERROR("malloc memory failed, errno is %{public}d", errno);
        return;
    }
    size_t totalRead = 0;
    while (totalRead < size) {
        ssize_t bytesRead = read(fd, bytes + totalRead, size - totalRead);
        if (bytesRead == -1) {
            delete[] bytes;
            close(fd);
            HILOG_ERROR("Read error: errno is %{public}d", errno);
            return;
        } else if (bytesRead == 0) {
            HILOG_ERROR("Unexpected end of file");
            delete[] bytes;
            close(fd);
            return;
        }
        totalRead += bytesRead;
    }
    std::shared_ptr<char> data(bytes, DeleteBytes());
    AddImageData(picName, data, size);
}

void FormProviderData::ParseImagesData()
{
    if (jsonFormProviderData_ == nullptr) {
        HILOG_ERROR("null jsonFormProviderData_");
        return;
    }
    if (!jsonFormProviderData_.contains(JSON_IMAGES_STRING)) {
        return;
    }
    nlohmann::json jsonImages = jsonFormProviderData_.at(JSON_IMAGES_STRING);
    for (auto iter = jsonImages.begin(); iter != jsonImages.end(); iter++) {
        if (iter->is_number_integer()) {
            AddImageData(iter.key(), iter.value());
        } else {
            HILOG_ERROR("fd not integer");
        }
    }
}

/**
 * @brief Removes data of an image with the specified {@code picName} from this {@code FormProviderData} instance.
 * @param picName Indicates the name of the image to remove.
 */
void FormProviderData::RemoveImageData(std::string picName)
{
    rawImageBytesMap_.erase(picName);
}

/**
 * @brief Set the form data stored from string string.
 * @param Returns string string.
 */
void FormProviderData::SetDataString(std::string &jsonDataString)
{
    if (jsonDataString.empty()) {
        jsonDataString = JSON_EMPTY_STRING;
    }
    nlohmann::json jsonObject = nlohmann::json::parse(jsonDataString, nullptr, false);
    if (jsonObject.is_discarded()) {
        HILOG_ERROR("fail parse jsonDataString: %{private}s.", jsonDataString.c_str());
        return;
    }
    if (!jsonObject.is_object()) {
        HILOG_ERROR("jsonDataString not object");
        return;
    }
    jsonFormProviderData_ = jsonObject;
}
/**
 * @brief Merge new data to FormProviderData.
 * @param addJsonData data to merge to FormProviderData
 */
void FormProviderData::MergeData(const nlohmann::json &addJsonData)
{
    HILOG_DEBUG("merge data");
    if (addJsonData.empty()) {
        return;
    }

    if (jsonFormProviderData_.empty()) {
        jsonFormProviderData_ = addJsonData;
        return;
    }

    for (auto && [key, value] : addJsonData.items()) {
        jsonFormProviderData_[key] = value;
    }
}

/**
 * @brief Obtains the imageDataMap stored in this {@code FormProviderData} object.
 * @return Returns the map that contains shared image data.
 */
std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> FormProviderData::GetImageDataMap() const
{
    return imageDataMap_;
}

/**
 * @brief Obtains the add/remove state stored in this {@code FormProviderData} object.
 * @return Returns the add/remove state of shared image data.
 */
int32_t FormProviderData::GetImageDataState() const
{
    return imageDataState_;
}

/**
 * @brief Updates imageDataState in this {@code FormProviderData} object.
 * @param imageDataState Indicates the imageDataState to update.
 */
void FormProviderData::SetImageDataState(int32_t imageDataState)
{
    imageDataState_ = imageDataState;
}

/**
 * @brief Updates imageDataMap in this {@code FormProviderData} object.
 * @param imageDataMap Indicates the imageDataMap to update.
 */
void FormProviderData::SetImageDataMap(std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap)
{
    imageDataMap_ = imageDataMap;
    if (!imageDataMap.empty()) {
        imageDataState_ = IMAGE_DATA_STATE_ADDED;
    } else {
        imageDataState_ = IMAGE_DATA_STATE_NO_OPERATION;
    }
}

/**
 * Read this {@code FormProviderData} object from a Parcel.
 * @param parcel the parcel
 * @return Returns {@code true} if the marshalling is successful; returns {@code false} otherwise.
 */
bool FormProviderData::ReadFromParcel(Parcel &parcel)
{
    int32_t formDataLength = parcel.ReadInt32();
    HILOG_DEBUG("ReadFromParcel data length is %{public}d ", formDataLength);
    std::string jsonDataString;
    if (formDataLength > BIG_DATA) {
        void *rawData = ReadAshmemDataFromParcel(parcel, formDataLength);
        if (rawData == nullptr) {
            HILOG_INFO("rawData is nullptr");
            return false;
        }
        jsonDataString = std::string(static_cast<const char*>(rawData), formDataLength);
        free(rawData);
        rawData = nullptr;
    } else {
        jsonDataString = Str16ToStr8(parcel.ReadString16());
    }
    nlohmann::json jsonObject = nlohmann::json::parse(jsonDataString, nullptr, false);
    if (jsonObject.is_discarded()) {
        HILOG_ERROR("fail parse jsonDataString: %{private}s.", jsonDataString.c_str());
        return false;
    }
    jsonFormProviderData_ = jsonObject;

    imageDataState_ = parcel.ReadInt32();
    HILOG_DEBUG("imageDateState is %{public}d", imageDataState_);
    switch (imageDataState_) {
        case IMAGE_DATA_STATE_ADDED: {
            if (!HandleImageDataStateAdded(parcel)) {
                return false;
            }
            break;
        }
        case IMAGE_DATA_STATE_NO_OPERATION:
        case IMAGE_DATA_STATE_REMOVED:
            break;
        default:
            HILOG_WARN("unexpected imageDataState_ %{public}d", imageDataState_);
            break;
    }
    return true;
}

int FormProviderData::ReadFileDescriptor(Parcel &parcel)
{
    sptr<IPCFileDescriptor> descriptor = parcel.ReadObject<IPCFileDescriptor>();
    if (descriptor == nullptr) {
        HILOG_INFO("ReadFileDescriptor get descriptor failed");
        return -1;
    }
    int fd = descriptor->GetFd();
    if (fd < 0) {
        HILOG_INFO("ReadFileDescriptor get fd failed, fd:[%{public}d].", fd);
        return -1;
    }
    return dup(fd);
}

void FormProviderData::ReleaseMemory(int32_t allocType, void *addr, void *context, uint32_t size)
{
    if (allocType == SHARE_MEM_ALLOC) {
        if (context != nullptr) {
            int *fd = static_cast<int *>(context);
            if (addr != nullptr) {
                ::munmap(addr, size);
            }
            if (fd != nullptr) {
                fdsan_close_with_tag(*fd, Constants::FORM_DOMAIN_ID);
            }
            context = nullptr;
            addr = nullptr;
        }
    }
}

char *FormProviderData::ReadAshmemDataFromParcel(Parcel &parcel, int32_t bufferSize)
{
    char *base = nullptr;
    int fd = ReadFileDescriptor(parcel);
    if (fd < 0) {
        HILOG_ERROR("ReadFileDescriptor Error");
        return nullptr;
    }
    fdsan_exchange_owner_tag(fd, 0, Constants::FORM_DOMAIN_ID);
    if (!CheckAshmemSize(fd, bufferSize)) {
        HILOG_INFO("ReadAshmemDataFromParcel check ashmem size failed, fd:[%{public}d].", fd);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return nullptr;
    }
    if (bufferSize <= 0 || bufferSize > MAX_BUFFER_SIZE) {
        HILOG_INFO("malloc parameter bufferSize:[%{public}d] error.", bufferSize);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return nullptr;
    }

    void *ptr = ::mmap(nullptr, bufferSize, PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        HILOG_INFO("ReadImageData map failed, errno:%{public}d", errno);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return nullptr;
    }

    base = static_cast<char *>(malloc(bufferSize));
    if (base == nullptr) {
        ::munmap(ptr, bufferSize);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        HILOG_INFO("alloc output pixel memory size:[%{public}d] error.", bufferSize);
        return nullptr;
    }
    if (memcpy_s(base, bufferSize, ptr, bufferSize) != 0) {
        ::munmap(ptr, bufferSize);
        free(base);
        base = nullptr;
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        HILOG_INFO("memcpy pixel data size:[%{public}d] error.", bufferSize);
        return nullptr;
    }

    ReleaseMemory(SHARE_MEM_ALLOC, ptr, &fd, bufferSize);
    return base;
}

bool FormProviderData::HandleImageDataStateAdded(Parcel &parcel)
{
    int32_t imageDataNum = parcel.ReadInt32();
    if (imageDataNum > READ_PARCEL_MAX_IMAGE_DATA_NUM_SIZE) {
        return false;
    }
    HILOG_INFO("imageDataNum is %{public}d", imageDataNum);
    for (int32_t i = 0; i < imageDataNum; i++) {
        sptr<FormAshmem> formAshmem = parcel.ReadParcelable<FormAshmem>();
        if (formAshmem == nullptr) {
            HILOG_ERROR("null ashmem");
            return false;
        }
        int32_t len = parcel.ReadInt32();
        std::pair<sptr<FormAshmem>, int32_t> imageDataRecord = std::make_pair(formAshmem, len);
        auto picName = Str16ToStr8(parcel.ReadString16());
        imageDataMap_[picName] = imageDataRecord;
    }
    return true;
}

bool FormProviderData::WriteFileDescriptor(Parcel &parcel, int fd) const
{
    if (fd < 0) {
        HILOG_INFO("WriteFileDescriptor get fd failed, fd:[%{public}d].", fd);
        return false;
    }
    int dupFd = dup(fd);
    if (dupFd < 0) {
        HILOG_INFO("WriteFileDescriptor dup fd failed, dupFd:[%{public}d].", dupFd);
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

bool FormProviderData::WriteAshmemDataToParcel(Parcel &parcel, size_t size, const char* dataPtr) const
{
    const char *data = dataPtr;
    std::string name = "formAshmemData";
    int fd = AshmemCreate(name.c_str(), size);
    HILOG_INFO("AshmemCreate:[%{public}d].", fd);
    if (fd < 0) {
        return false;
    }
    fdsan_exchange_owner_tag(fd, 0, Constants::FORM_DOMAIN_ID);
    int result = AshmemSetProt(fd, PROT_READ | PROT_WRITE);
    HILOG_INFO("AshmemSetProt:[%{public}d].", result);
    if (result < 0) {
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        return false;
    }
    void *ptr = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        HILOG_INFO("WriteAshmemData map failed, errno:%{public}d", errno);
        return false;
    }
    HILOG_INFO("mmap success");

    if (memcpy_s(ptr, size, data, size) != EOK) {
        ::munmap(ptr, size);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        HILOG_INFO("WriteAshmemData memcpy_s error");
        return false;
    }

    if (!FormProviderData::WriteFileDescriptor(parcel, fd)) {
        ::munmap(ptr, size);
        fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
        HILOG_INFO("WriteAshmemData WriteFileDescriptor error");
        return false;
    }
    HILOG_INFO("WriteAshmemData WriteFileDescriptor success");
    ::munmap(ptr, size);
    fdsan_close_with_tag(fd, Constants::FORM_DOMAIN_ID);
    return true;
}

bool FormProviderData::WriteFormData(Parcel &parcel) const
{
    std::string formData = jsonFormProviderData_.empty() ?
        JSON_EMPTY_STRING : jsonFormProviderData_.dump();
    int32_t formDataLength = static_cast<int32_t>(formData.length());
    parcel.WriteInt32(formDataLength);
    if (formDataLength > BIG_DATA) {
        const char* dataPtr = formData.c_str();
        HILOG_INFO("FormProviderData::WriteFormData data length is %{public}d", formDataLength);
        return WriteAshmemDataToParcel(parcel, formDataLength, dataPtr);
    } else {
        return parcel.WriteString16(Str8ToStr16(formData));
    }
}

/**
 * @brief Marshals this {@code FormProviderData} object into a {@link ohos.utils.Parcel} object.
 * @param parcel Indicates the {@code Parcel} object for marshalling.
 * @return Returns {@code true} if the marshalling is successful; returns {@code false} otherwise.
 */
bool FormProviderData::Marshalling(Parcel &parcel) const
{
    HILOG_DEBUG("jsonFormProviderData_ is private");
    if (!WriteFormData(parcel)) {
        return false;
    }

    parcel.WriteInt32(imageDataState_);
    HILOG_DEBUG("imageDateState is %{public}d", imageDataState_);
    switch (imageDataState_) {
        case IMAGE_DATA_STATE_ADDED: {
            parcel.WriteInt32(rawImageBytesMap_.size()); // firstly write the number of shared image to add
            for (auto &entry : rawImageBytesMap_) {
                if (!WriteImageDataToParcel(parcel, entry.first, entry.second.first, entry.second.second)) {
                    HILOG_ERROR("the picture name is %{public}s", entry.first.c_str());
                    return false;
                }
                parcel.WriteInt32(sizeof(entry.second));
                parcel.WriteString16(Str8ToStr16(entry.first));
            }
            break;
        }
        case IMAGE_DATA_STATE_NO_OPERATION:
        case IMAGE_DATA_STATE_REMOVED:
            break;
        default:
            HILOG_WARN("unexpected imageDataState_ %{public}d", imageDataState_);
            break;
    }
    return true;
}

/**
 * @brief Unmarshals this {@code FormProviderData} object from a {@link ohos.utils.Parcel} object.
 * @param parcel Indicates the {@code Parcel} object for unmarshalling.
 * @return FormProviderData.
 */
FormProviderData* FormProviderData::Unmarshalling(Parcel &parcel)
{
    std::unique_ptr<FormProviderData> formProviderData = std::make_unique<FormProviderData>();
    if (formProviderData && !formProviderData->ReadFromParcel(parcel)) {
        formProviderData = nullptr;
    }
    return formProviderData.release();
}

/**
 * @brief Clear imageDataMap, rawImageBytesMap_, imageDataState_ and jsonFormProviderData_.
 */
void FormProviderData::ClearData()
{
    jsonFormProviderData_.clear();
}

bool FormProviderData::WriteImageDataToParcel(Parcel &parcel, const std::string &picName,
    const std::shared_ptr<char> &data, int32_t size) const
{
    FormAshmem formAshmem;
    if (!formAshmem.WriteToAshmem(picName, data.get(), size)) {
        return false;
    }

    // write formAshmem
    if (!parcel.WriteParcelable(&formAshmem)) {
        HILOG_ERROR("write FormAshmem fail,the picture name is %{public}s", picName.c_str());
        return false;
    }

    HILOG_INFO("write FormAshmem success, picName:%{public}s, size:%{public}d", picName.c_str(), size);
    return true;
}

bool FormProviderData::ConvertRawImageData()
{
    HILOG_INFO("call");
    for (auto &entry : rawImageBytesMap_) {
        sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
        if (formAshmem == nullptr) {
            HILOG_ERROR("alloc shmem failed");
            return false;
        }
        if (!formAshmem->WriteToAshmem(entry.first, entry.second.first.get(), entry.second.second)) {
            HILOG_ERROR("write to shmem failed");
            return false;
        }
        std::pair<sptr<FormAshmem>, int32_t> imageDataRecord = std::make_pair(formAshmem, entry.second.second);
        imageDataMap_[entry.first] = imageDataRecord;
    }
    rawImageBytesMap_.clear();
    HILOG_INFO("end");
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
