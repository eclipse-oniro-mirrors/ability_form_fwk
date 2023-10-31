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

#ifndef OHOS_FORM_FWK_FORM_DATA_PROXY_RECORD_H
#define OHOS_FORM_FWK_FORM_DATA_PROXY_RECORD_H

#include <vector>

#include "datashare_helper.h"
#include "form_ashmem.h"
#include "form_provider_data_proxy.h"
#include "form_info_base.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormDataSharerRecord
 * data share form record.
 */
class FormDataProxyRecord : public std::enable_shared_from_this<FormDataProxyRecord> {
public:
    FormDataProxyRecord(int64_t formId, const std::string &bundleName,
        FormType uiSyntax, uint32_t tokenId, const int32_t uid);
    ~FormDataProxyRecord();

    ErrCode SubscribeFormData(const std::vector<FormDataProxy> &formDataProxies);
    ErrCode UnsubscribeFormData();
    void UpdateSubscribeFormData(const std::vector<FormDataProxy> &formDataProxies);
    void EnableSubscribeFormData();
    void DisableSubscribeFormData();
    void RetryFailureSubscribes();
private:
    struct FormDataProxyRequest {
        int64_t subscribeId;
        std::vector<std::string> uris;
    };
    struct SubscribeResultRecord {
        std::string uri;
        int64_t subscribeId;
        int ret;
        bool retry;
        int retryRet;
    };
    void ParseFormDataProxies(const std::vector<FormDataProxy> &formDataProxies);
    void ConvertSubscribeMapToRequests(std::map<std::string, std::string> &subscribeMap,
        std::vector<FormDataProxyRequest> &formDataProxyRequests);
    void UpdatePublishedDataForm(const std::vector<DataShare::PublishedDataItem> &data);
    void UpdateRdbDataForm(const std::vector<std::string> &data);
    ErrCode SubscribeRdbFormData(std::map<std::string, std::string> &rdbSubscribeMap);
    ErrCode SubscribePublishFormData(std::map<std::string, std::string> &publishSubscribeMap);
    ErrCode UnsubscribeFormData(std::map<std::string, std::string> &rdbSubscribeMap,
        std::map<std::string, std::string> &publishSubscribeMap);
    void OnRdbDataChange(const DataShare::RdbChangeNode &changeNode);
    void OnPublishedDataChange(const DataShare::PublishedDataChangeNode &changeNode);

    void UpdateSubscribeMap(const std::vector<FormDataProxy> &formDataProxies,
        std::map<std::string, std::string> &originRdbMap,
        std::map<std::string, std::string> &newRdbMap,
        std::map<std::string, std::string> &originPublishMap,
        std::map<std::string, std::string> &newPublishMap);

    ErrCode SetRdbSubsState(std::map<std::string, std::string> &rdbSubscribeMap, bool subsState);
    ErrCode SetPublishSubsState(std::map<std::string, std::string> &publishSubscribeMap, bool subsState);

    bool PrepareImageData(const DataShare::PublishedDataItem &data, nlohmann::json &jsonObj,
        std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap);
    void AddSubscribeResultRecord(SubscribeResultRecord record, bool isRdbType);
    void RemoveSubscribeResultRecord(const std::string& uri, int64_t subscribeId, bool isRdbType);
    void PrintSubscribeState(const std::string& uri, int64_t subscribeId, bool isRdbType);
    void RetryFailureRdbSubscribes(SubscribeResultRecord& record);
    void RetryFailurePublishedSubscribes(SubscribeResultRecord& record);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
    int64_t formId_ = -1;
    std::string bundleName_;
    FormType uiSyntax_;
    int32_t tokenId_;
    int32_t uid_;
    std::map<std::string, std::string> rdbSubscribeMap_; // key: subscribeId
    std::map<std::string, std::string> publishSubscribeMap_; // key: subscribeId
    std::map<std::string, std::map<int64_t, SubscribeResultRecord>> rdbSubscribeResultMap_;
    std::map<std::string, std::map<int64_t, SubscribeResultRecord>> publishSubscribeResultMap_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_DATA_PROXY_RECORD_H