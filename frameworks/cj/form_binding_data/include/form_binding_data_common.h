/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef FORM_BINDING_DATA_COMMON_H
#define FORM_BINDING_DATA_COMMON_H

#include <string>
#include <vector>

namespace OHOS {
namespace AbilityRuntime {
class ProxyData {
public:
    ProxyData(std::string key, std::string subscribeId = std::string()): key(key), subscribeId(subscribeId) {}

    std::string key;
    std::string subscribeId;
};

class FormBindingData {
public:
    FormBindingData(
        std::string data, std::vector<ProxyData> proxies = std::vector<ProxyData>()): data(data), proxies(proxies) {}
    ~FormBindingData() = default;

    std::string data;
    std::vector<ProxyData> proxies;
};
class CjFormBindingData {
public:
    CjFormBindingData() = default;
    ~CjFormBindingData() = default;

    static FormBindingData CreateFormBindingData(std::string obj)
    {
        return OnCreateFormBindingData(obj);
    }

private:
    static FormBindingData OnCreateFormBindingData(std::string obj);
};

char* MallocCString(const std::string &origin);
} // namespace AbilityRuntime
} // namespace OHOS
#endif