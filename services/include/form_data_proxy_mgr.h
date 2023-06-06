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

#include "form_data_proxy_record.h"

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

    ErrCode SubscribeFormData(int64_t formId, const std::vector<FormDataProxy> &formDataProxies);
    ErrCode UnsubscribeFormData(int64_t formId);
private:
    std::mutex formDataProxyRecordMutex_;
    std::map<int64_t, std::shared_ptr<FormDataProxyRecord>> formDataProxyRecordMap_; // formId:FormDataProxyRecord
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_DATA_PROXY_MGR_H