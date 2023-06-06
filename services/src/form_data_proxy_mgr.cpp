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

#include "form_data_proxy_mgr.h"

#include "form_data_mgr.h"
#include "form_mgr_errors.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
FormDataProxyMgr::FormDataProxyMgr()
{}

FormDataProxyMgr::~FormDataProxyMgr()
{}

ErrCode FormDataProxyMgr::SubscribeFormData(int64_t formId, const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_DEBUG("subscribe form data. formId: %{public}s, proxy data size: %{public}zu",
        std::to_string(formId).c_str(), formDataProxies.size());
    if (formDataProxies.empty()) {
        HILOG_DEBUG("formDataProxies is empty.");
        return ERR_OK;
    }

    FormRecord formRecord;
    if (!FormDataMgr::GetInstance().GetFormRecord(formId, formRecord)) {
        HILOG_ERROR("not exist such form:%{public}" PRId64 ".", formId);
        return ERR_APPEXECFWK_FORM_NOT_EXIST_ID;
    }

    if (!formRecord.isDataProxy) {
        HILOG_DEBUG("not data proxy form, formId:%{public}" PRId64 ".", formId);
        return ERR_OK;
    }

    std::lock_guard<std::mutex> lock(formDataProxyRecordMutex_);
    auto search = formDataProxyRecordMap_.find(formId);
    if (search != formDataProxyRecordMap_.end()) {
        if (search->second != nullptr) {
            HILOG_DEBUG("the form has already subscribed, formId: %{public}s.", std::to_string(formId).c_str());
            return ERR_OK;
        } else {
            HILOG_WARN("formDataProxyRecord is nullptr.");
            formDataProxyRecordMap_.erase(formId);
        }
    }

    std::shared_ptr<FormDataProxyRecord> formDataProxyRecord =
        std::make_shared<FormDataProxyRecord>(formId, formRecord.bundleName, formRecord.moduleName);
    auto ret = formDataProxyRecord->SubscribeFormData(formDataProxies);
    if (ret != ERR_OK) {
        HILOG_ERROR("SubscribeFormData failed.");
        return ret;
    }
    formDataProxyRecordMap_.emplace(formId, formDataProxyRecord);
    return ERR_OK;
}

ErrCode FormDataProxyMgr::UnsubscribeFormData(int64_t formId)
{
    HILOG_DEBUG("unsubscribe form data. formId: %{public}s", std::to_string(formId).c_str());
    std::lock_guard<std::mutex> lock(formDataProxyRecordMutex_);
    auto search = formDataProxyRecordMap_.find(formId);
    if (search != formDataProxyRecordMap_.end()) {
        if (search->second != nullptr) {
            search->second->UnsubscribeFormData();
        }
        formDataProxyRecordMap_.erase(formId);
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS
