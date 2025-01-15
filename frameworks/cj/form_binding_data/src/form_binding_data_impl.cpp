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

#include "form_binding_data_impl.h"

#include "form_binding_data_common.h"
#include "form_binding_data_defination.h"

namespace OHOS {
namespace AbilityRuntime {
RetFormBindingData CjFormBindingDataImpl::createFormBindingData(std::string obj)
{
    RetFormBindingData ret {};
    FormBindingData formBindingData = CjFormBindingData::CreateFormBindingData(obj);
    ret.cFormBindingData = Convert2CFormBindingData(formBindingData);
    ret.errCode = ERR_CJ_OK;
    return ret;
}

CFormBindingData CjFormBindingDataImpl::Convert2CFormBindingData(const FormBindingData in)
{
    CFormBindingData cFormBindingData {};
    cFormBindingData.data = MallocCString(in.data);
    cFormBindingData.cArrProxyData = Convert2CArrProxyData(in.proxies);
    return cFormBindingData;
}

CArrProxyData CjFormBindingDataImpl::Convert2CArrProxyData(const std::vector<ProxyData> &in)
{
    CArrProxyData res{};
    if (in.size() <= 0) {
        return res;
    }
    res.head = static_cast<CProxyData *>(malloc(sizeof(CProxyData) * in.size()));
    if (res.head == nullptr) {
        return res;
    }
    int64_t i = 0;
    for (auto item : in) {
        res.head[i].key = MallocCString(item.key);
        res.head[i].subscribeId = MallocCString(item.subscribeId);
        i++;
    }
    res.size = i;
    return res;
}
} // namespace AbilityRuntime
} // namespace OHOS