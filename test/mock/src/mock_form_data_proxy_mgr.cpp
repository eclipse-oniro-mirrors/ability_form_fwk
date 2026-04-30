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

#include "data_center/form_data_proxy_mgr.h"

namespace OHOS {
namespace AppExecFwk {
FormDataProxyMgr::FormDataProxyMgr() {}
FormDataProxyMgr::~FormDataProxyMgr() {}

ErrCode FormDataProxyMgr::SubscribeFormData(int64_t formId,
    const std::vector<FormDataProxy> &formDataProxies,
    const AAFwk::Want &want, const int32_t userId)
{
    return 0;
}

ErrCode FormDataProxyMgr::UnsubscribeFormData(int64_t formId)
{
    return 0;
}

void FormDataProxyMgr::UpdateSubscribeFormData(int64_t formId,
    const std::vector<FormDataProxy> &formDataProxies) {}

void FormDataProxyMgr::ProduceFormDataProxies(int64_t formId,
    const std::vector<FormDataProxy> &formDataProxies) {}

bool FormDataProxyMgr::ConsumeFormDataProxies(int64_t formId,
    std::vector<FormDataProxy> &formDataProxies)
{
    return false;
}

void FormDataProxyMgr::EnableSubscribeFormData(const std::vector<int64_t> &formIds) {}
void FormDataProxyMgr::DisableSubscribeFormData(const std::vector<int64_t> &formIds) {}
void FormDataProxyMgr::RetryFailureSubscribes() {}

void FormDataProxyMgr::GetFormSubscribeInfo(const int64_t formId,
    std::vector<std::string> &subscribedKeys, int32_t &count) {}

std::shared_ptr<FormDataProxyRecord> FormDataProxyMgr::GetFormDataProxyRecord(int64_t formId)
{
    return nullptr;
}

void FormDataProxyMgr::UnsubscribeFormDataById(int64_t formId) {}

void FormDataProxyMgr::RetrySubscribeProxy(int64_t formId,
    const std::vector<FormDataProxy> &formDataProxies,
    uint32_t tokenId, const AAFwk::Want &want, int32_t leftRetryTimes) {}
} // namespace AppExecFwk
} // namespace OHOS
