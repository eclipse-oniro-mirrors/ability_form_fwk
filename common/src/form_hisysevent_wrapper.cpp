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

#include "form_hisysevent_wrapper.h"

#include <cstring>
#include "securec.h"
#include "fms_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

bool FormHiSysEventBuilder::CheckParamCount()
{
    if (params_.size() >= MAX_PARAM_COUNT) {
        HILOG_ERROR("param count exceeds limit %{public}zu", MAX_PARAM_COUNT);
        return false;
    }
    return true;
}

HiSysEventParam FormHiSysEventBuilder::PrepareParam(const std::string &key, HiSysEventParamType type)
{
    HiSysEventParam param = {};
    if (!CheckParamCount()) {
        return param;
    }
    param.t = type;
    param.arraySize = 0;
    SetParamName(param, key);
    return param;
}

void FormHiSysEventBuilder::SetParamName(HiSysEventParam &param, const std::string &key)
{
    int32_t ret = memset_s(param.name, MAX_LENGTH_OF_PARAM_NAME, 0, MAX_LENGTH_OF_PARAM_NAME);
    if (ret != EOK) {
        HILOG_ERROR("memset_s failed, ret=%{public}d", ret);
        param.name[0] = '\0';
        return;
    }
    ret = strncpy_s(param.name, MAX_LENGTH_OF_PARAM_NAME, key.c_str(), MAX_LENGTH_OF_PARAM_NAME - 1);
    if (ret != EOK) {
        HILOG_ERROR("strncpy_s failed, ret=%{public}d", ret);
        param.name[0] = '\0';
    }
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, int64_t value)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_INT64);
    if (param.t != HISYSEVENT_INT64) {
        return;
    }
    param.v.i64 = value;
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, uint64_t value)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_UINT64);
    if (param.t != HISYSEVENT_UINT64) {
        return;
    }
    param.v.ui64 = value;
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, int32_t value)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_INT32);
    if (param.t != HISYSEVENT_INT32) {
        return;
    }
    param.v.i32 = value;
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, uint32_t value)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_UINT32);
    if (param.t != HISYSEVENT_UINT32) {
        return;
    }
    param.v.ui32 = value;
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, int8_t value)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_INT8);
    if (param.t != HISYSEVENT_INT8) {
        return;
    }
    param.v.i8 = value;
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, uint8_t value)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_UINT8);
    if (param.t != HISYSEVENT_UINT8) {
        return;
    }
    param.v.ui8 = value;
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, bool value)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_BOOL);
    if (param.t != HISYSEVENT_BOOL) {
        return;
    }
    param.v.b = value;
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, float value)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_FLOAT);
    if (param.t != HISYSEVENT_FLOAT) {
        return;
    }
    param.v.f = value;
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, double value)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_DOUBLE);
    if (param.t != HISYSEVENT_DOUBLE) {
        return;
    }
    param.v.d = value;
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const char *value)
{
    if (value == nullptr) {
        HILOG_ERROR("value is nullptr for key %{public}s", key.c_str());
        return;
    }

    HiSysEventParam param = PrepareParam(key, HISYSEVENT_STRING);
    if (param.t != HISYSEVENT_STRING) {
        return;
    }
    param.v.s = nullptr;
    
    size_t len = std::strlen(value) + 1;
    auto buffer = std::make_unique<char[]>(len);
    errno_t ret = strcpy_s(buffer.get(), len, value);
    if (ret != EOK) {
        HILOG_ERROR("strcpy_s failed, ret=%{public}d", ret);
        return;
    }
    param.v.s = buffer.get();
    stringBuffers_.emplace_back(std::move(buffer));
    
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::string &value)
{
    InsertParam(key, value.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<int64_t> &values)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_INT64_ARRAY);
    if (param.t != HISYSEVENT_INT64_ARRAY) {
        return;
    }
    param.v.array = nullptr;
    
    if (!values.empty()) {
        auto buffer = std::make_unique<int64_t[]>(values.size());
        errno_t ret = memcpy_s(buffer.get(), values.size() * sizeof(int64_t),
            values.data(), values.size() * sizeof(int64_t));
        if (ret != EOK) {
            HILOG_ERROR("memcpy_s failed, ret=%{public}d", ret);
            return;
        }
        param.v.array = static_cast<void*>(buffer.get());
        param.arraySize = values.size();
        int64ArrayBuffers_.emplace_back(std::move(buffer));
    }
    
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<uint64_t> &values)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_UINT64_ARRAY);
    if (param.t != HISYSEVENT_UINT64_ARRAY) {
        return;
    }
    param.v.array = nullptr;
    
    if (!values.empty()) {
        auto buffer = std::make_unique<uint64_t[]>(values.size());
        errno_t ret = memcpy_s(buffer.get(), values.size() * sizeof(uint64_t),
            values.data(), values.size() * sizeof(uint64_t));
        if (ret != EOK) {
            HILOG_ERROR("memcpy_s failed, ret=%{public}d", ret);
            return;
        }
        param.v.array = static_cast<void*>(buffer.get());
        param.arraySize = values.size();
        uint64ArrayBuffers_.emplace_back(std::move(buffer));
    }
    
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<int32_t> &values)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_INT32_ARRAY);
    if (param.t != HISYSEVENT_INT32_ARRAY) {
        return;
    }
    param.v.array = nullptr;
    
    if (!values.empty()) {
        auto buffer = std::make_unique<int32_t[]>(values.size());
        errno_t ret = memcpy_s(buffer.get(), values.size() * sizeof(int32_t),
            values.data(), values.size() * sizeof(int32_t));
        if (ret != EOK) {
            HILOG_ERROR("memcpy_s failed, ret=%{public}d", ret);
            return;
        }
        param.v.array = static_cast<void*>(buffer.get());
        param.arraySize = values.size();
        int32ArrayBuffers_.emplace_back(std::move(buffer));
    }
    
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<uint32_t> &values)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_UINT32_ARRAY);
    if (param.t != HISYSEVENT_UINT32_ARRAY) {
        return;
    }
    param.v.array = nullptr;
    
    if (!values.empty()) {
        auto buffer = std::make_unique<uint32_t[]>(values.size());
        errno_t ret = memcpy_s(buffer.get(), values.size() * sizeof(uint32_t),
            values.data(), values.size() * sizeof(uint32_t));
        if (ret != EOK) {
            HILOG_ERROR("memcpy_s failed, ret=%{public}d", ret);
            return;
        }
        param.v.array = static_cast<void*>(buffer.get());
        param.arraySize = values.size();
        uint32ArrayBuffers_.emplace_back(std::move(buffer));
    }
    
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<uint8_t> &values)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_UINT8_ARRAY);
    if (param.t != HISYSEVENT_UINT8_ARRAY) {
        return;
    }
    param.v.array = nullptr;
    
    if (!values.empty()) {
        auto buffer = std::make_unique<uint8_t[]>(values.size());
        errno_t ret = memcpy_s(buffer.get(), values.size() * sizeof(uint8_t),
            values.data(), values.size() * sizeof(uint8_t));
        if (ret != EOK) {
            HILOG_ERROR("memcpy_s failed, ret=%{public}d", ret);
            return;
        }
        param.v.array = static_cast<void*>(buffer.get());
        param.arraySize = values.size();
        uint8ArrayBuffers_.emplace_back(std::move(buffer));
    }
    
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<bool> &values)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_BOOL_ARRAY);
    if (param.t != HISYSEVENT_BOOL_ARRAY) {
        return;
    }
    param.v.array = nullptr;
    
    if (!values.empty()) {
        auto buffer = std::make_unique<bool[]>(values.size());
        for (size_t i = 0; i < values.size(); ++i) {
            buffer[i] = values[i];
        }
        param.v.array = static_cast<void*>(buffer.get());
        param.arraySize = values.size();
        boolArrayBuffers_.emplace_back(std::move(buffer));
    }
    
    params_.emplace_back(param);
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<std::string> &values)
{
    HiSysEventParam param = PrepareParam(key, HISYSEVENT_STRING_ARRAY);
    if (param.t != HISYSEVENT_STRING_ARRAY) {
        return;
    }
    param.v.array = nullptr;
    
    if (!values.empty()) {
        size_t totalLen = 0;
        for (const auto &str : values) {
            totalLen += str.size() + 1;
        }
        auto buffer = std::make_unique<char[]>(totalLen);
        char *ptr = buffer.get();
        auto ptrArray = std::make_unique<char *[]>(values.size());
        
        for (size_t i = 0; i < values.size(); ++i) {
            errno_t ret = strcpy_s(ptr, values[i].size() + 1, values[i].c_str());
            if (ret != EOK) {
                HILOG_ERROR("strcpy_s failed at index %{public}zu, ret=%{public}d", i, ret);
                return;
            }
            ptrArray[i] = ptr;
            ptr += values[i].size() + 1;
        }
        
        param.v.array = static_cast<void*>(ptrArray.get());
        param.arraySize = values.size();
        stringArrayBuffers_.emplace_back(std::move(buffer));
        charPtrArrayBuffers_.emplace_back(std::move(ptrArray));
    }
    
    params_.emplace_back(param);
}

int FormHiSysEventBuilder::Write(const std::string &domain, const std::string &eventName,
    HiSysEventEventType eventType)
{
    int ret = OH_HiSysEvent_Write(domain.c_str(), eventName.c_str(), eventType,
        params_.data(), params_.size());
    
    Clear();
    
    return ret;
}

void FormHiSysEventBuilder::Clear()
{
    params_.clear();
    stringBuffers_.clear();
    stringArrayBuffers_.clear();
    charPtrArrayBuffers_.clear();
    int64ArrayBuffers_.clear();
    uint64ArrayBuffers_.clear();
    int32ArrayBuffers_.clear();
    uint32ArrayBuffers_.clear();
    uint8ArrayBuffers_.clear();
    boolArrayBuffers_.clear();
}

int FormHiSysEventWrapper::WriteEvent(const std::string &domain, const std::string &eventName,
    HiSysEventEventType eventType)
{
    return OH_HiSysEvent_Write(domain.c_str(), eventName.c_str(), eventType, nullptr, 0);
}
} // namespace AppExecFwk
} // namespace OHOS