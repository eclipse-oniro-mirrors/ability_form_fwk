/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_FORM_DATA_PROXY_MGR_H
#define OHOS_FORM_FWK_FORM_DATA_PROXY_MGR_H

#include <memory>
#include <singleton.h>

#include "data_center/form_data_proxy_record.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormDataProxyMgr
 * data proxy form mananger.
 */
class FormDataProxyMgr final : public DelayedRefSingleton<FormDataProxyMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormDataProxyMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormDataProxyMgr);

    ErrCode SubscribeFormData(int64_t formId, const std::vector<FormDataProxy> &formDataProxies,
        const AAFwk::Want &want, const int32_t userId);
    ErrCode UnsubscribeFormData(int64_t formId);
    void UpdateSubscribeFormData(int64_t formId, const std::vector<FormDataProxy> &formDataProxies);
    void ProduceFormDataProxies(int64_t formId, const std::vector<FormDataProxy> &formDataProxies);
    bool ConsumeFormDataProxies(int64_t formId, std::vector<FormDataProxy> &formDataProxies);
    void EnableSubscribeFormData(const std::vector<int64_t> &formIds);
    void DisableSubscribeFormData(const std::vector<int64_t> &formIds);
    // will run only once
    void RetryFailureSubscribes();
    void GetFormSubscribeInfo(const int64_t formId, std::vector<std::string> &subscribedKeys, int32_t &count);
    std::shared_ptr<FormDataProxyRecord> GetFormDataProxyRecord(int64_t formId);

private:
    void UnsubscribeFormDataById(int64_t formId);
    // when data share connect fail, try again
    void RetrySubscribeProxy(int64_t formId, const std::vector<FormDataProxy> &formDataProxies,
        uint32_t tokenId, const AAFwk::Want &want, int32_t leftRetryTimes);

private:
    std::mutex formDataProxyRecordMutex_;
    std::map<int64_t, std::shared_ptr<FormDataProxyRecord>> formDataProxyRecordMap_; // formId:FormDataProxyRecord
    std::mutex formDataProxiesMutex_;
    std::map<int64_t, std::vector<FormDataProxy>> formDataProxiesMap_; // formId:FormDataProxies
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_DATA_PROXY_MGR_H