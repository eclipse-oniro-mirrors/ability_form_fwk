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
#ifndef FORM_BINDING_DATA_IMPL_H
#define FORM_BINDING_DATA_IMPL_H

#include <string>

#include "form_binding_data_common.h"
#include "form_binding_data_defination.h"
#include "form_binding_data_ffi.h"

namespace OHOS {
namespace AbilityRuntime {
class CjFormBindingDataImpl {
public:
    CjFormBindingDataImpl() = default;
    ~CjFormBindingDataImpl() = default;

    RetFormBindingData createFormBindingData(std::string obj);

private:
    CFormBindingData Convert2CFormBindingData(const FormBindingData in);
    CArrProxyData Convert2CArrProxyData(const std::vector<ProxyData> &in);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif