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

#ifndef OHOS_FORM_FWK_FORM_HISYSEVENT_WRAPPER_H
#define OHOS_FORM_FWK_FORM_HISYSEVENT_WRAPPER_H

#include <string>
#include <vector>
#include <memory>
#include "hisysevent_c.h"

namespace OHOS {
namespace AppExecFwk {

constexpr size_t MAX_PARAM_COUNT = 64;

class FormHiSysEventBuilder {
public:
    FormHiSysEventBuilder() = default;
    ~FormHiSysEventBuilder() = default;
    
    void InsertParam(const std::string &key, int64_t value);
    void InsertParam(const std::string &key, uint64_t value);
    void InsertParam(const std::string &key, int32_t value);
    void InsertParam(const std::string &key, uint32_t value);
    void InsertParam(const std::string &key, int8_t value);
    void InsertParam(const std::string &key, uint8_t value);
    void InsertParam(const std::string &key, bool value);
    void InsertParam(const std::string &key, float value);
    void InsertParam(const std::string &key, double value);
    void InsertParam(const std::string &key, const char *value);
    void InsertParam(const std::string &key, const std::string &value);
    void InsertParam(const std::string &key, const std::vector<int64_t> &values);
    void InsertParam(const std::string &key, const std::vector<uint64_t> &values);
    void InsertParam(const std::string &key, const std::vector<int32_t> &values);
    void InsertParam(const std::string &key, const std::vector<uint32_t> &values);
    void InsertParam(const std::string &key, const std::vector<uint8_t> &values);
    void InsertParam(const std::string &key, const std::vector<bool> &values);
    void InsertParam(const std::string &key, const std::vector<std::string> &values);
    
    int Write(const std::string &domain, const std::string &eventName, HiSysEventEventType eventType);
    
    void Clear();

private:
    bool CheckParamCount();
    HiSysEventParam PrepareParam(const std::string &key, HiSysEventParamType type);
    void SetParamName(HiSysEventParam &param, const std::string &key);
    
    std::vector<HiSysEventParam> params_;
    
    // Buffer for single string parameters.
    // Each element holds a deep-copied string to ensure lifetime safety.
    std::vector<std::unique_ptr<char[]>> stringBuffers_;
    
    // Buffers for string array parameters.
    // Memory Management Strategy:
    // - stringArrayBuffers_: Stores contiguous memory containing all string contents.
    //   All strings from one array are placed in a single buffer sequentially.
    // - charPtrArrayBuffers_: Stores pointer arrays pointing to offsets within
    //   stringArrayBuffers_ (NOT independently allocated memory blocks).
    // - Clear() releases stringArrayBuffers_ first (string content), then
    //   charPtrArrayBuffers_ (pointer array), ensuring no memory leaks.
    // - This design eliminates dangling pointer risk by keeping all data
    //   within the builder until Write() completes.
    std::vector<std::unique_ptr<char[]>> stringArrayBuffers_;
    std::vector<std::unique_ptr<char *[]>> charPtrArrayBuffers_;
    
    // Buffers for numeric array parameters.
    // Each element holds a deep-copied array to ensure lifetime safety.
    std::vector<std::unique_ptr<int64_t[]>> int64ArrayBuffers_;
    std::vector<std::unique_ptr<uint64_t[]>> uint64ArrayBuffers_;
    std::vector<std::unique_ptr<int32_t[]>> int32ArrayBuffers_;
    std::vector<std::unique_ptr<uint32_t[]>> uint32ArrayBuffers_;
    std::vector<std::unique_ptr<uint8_t[]>> uint8ArrayBuffers_;
    std::vector<std::unique_ptr<bool[]>> boolArrayBuffers_;
};

class FormHiSysEventWrapper {
public:
    static int WriteEvent(const std::string &domain, const std::string &eventName, HiSysEventEventType eventType);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_FORM_FWK_FORM_HISYSEVENT_WRAPPER_H