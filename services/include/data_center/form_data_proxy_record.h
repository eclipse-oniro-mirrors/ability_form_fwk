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

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "datashare_helper.h"
#include "form_ashmem.h"
#include "form_provider_data_proxy.h"
#include "form_info_base.h"
#include "nlohmann/json.hpp"
#include "perm_state_change_callback_customize.h"
#include "want.h"

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
    void GetFormSubscribeInfo(std::vector<std::string> &subscribedKeys, int32_t &count);
    void UnRegisterPermissionListener();
    void PermStateChangeCallback(const int32_t permStateChangeType, const std::string permissionName);
    void SetWant(const AAFwk::Want &want);
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

    // map from key to vector of subscriberId
    using SubscribeMap = std::unordered_map<std::string, std::unordered_set<std::string>>;

    void ParseFormDataProxies(const std::vector<FormDataProxy> &formDataProxies, SubscribeMap &rdbSubscribeMap,
        SubscribeMap &publishSubscribeMap);
    void ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys(
        const std::vector<FormDataProxy> &formDataProxies, const std::unordered_set<std::string> &expectedKeys,
        bool keyCheckingNeeded, SubscribeMap &subscribeMap);
    void ConvertSubscribeMapToRequests(const SubscribeMap &subscribeMap,
        std::vector<FormDataProxyRequest> &formDataProxyRequests);
    void UpdatePublishedDataForm(const std::vector<DataShare::PublishedDataItem> &data);
    void UpdateRdbDataForm(const std::vector<std::string> &data);
    ErrCode SubscribeRdbFormData(const SubscribeMap &rdbSubscribeMap);
    ErrCode SubscribePublishFormData(const SubscribeMap &publishSubscribeMap);
    ErrCode UnsubscribeFormData(SubscribeMap &rdbSubscribeMap, SubscribeMap &publishSubscribeMap);
    void OnRdbDataChange(const DataShare::RdbChangeNode &changeNode);
    void OnPublishedDataChange(const DataShare::PublishedDataChangeNode &changeNode);

    void UpdateSubscribeMap(const std::vector<FormDataProxy> &formDataProxies,
        SubscribeMap &originRdbMap, SubscribeMap &newRdbMap,
        SubscribeMap &originPublishMap, SubscribeMap &newPublishMap);

    ErrCode SetRdbSubsState(const SubscribeMap &rdbSubscribeMap, bool subsState);
    ErrCode SetPublishSubsState(const SubscribeMap &publishSubscribeMap, bool subsState);

    bool PrepareImageData(const DataShare::PublishedDataItem &data, nlohmann::json &jsonObj,
        std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap);
    void AddSubscribeResultRecord(SubscribeResultRecord record, bool isRdbType);
    void RemoveSubscribeResultRecord(const std::string &uri, int64_t subscribeId, bool isRdbType);
    void PrintSubscribeState(const std::string &uri, int64_t subscribeId, bool isRdbType);
    void RetryFailureRdbSubscribes(SubscribeResultRecord &record);
    void RetryFailurePublishedSubscribes(SubscribeResultRecord &record);
    void GetFormSubscribeKeys(std::vector<std::string> &subscribedKeys, bool isRdbType);
    
    void RegisterPermissionListener(const std::vector<FormDataProxy> &formDataProxies);
    ErrCode SubscribeFormData(const std::vector<FormDataProxy> &formDataProxies, SubscribeMap &rdbSubscribeMap,
        SubscribeMap &publicSubscribeMap);
    void GetSubscribeFormDataProxies(const FormDataProxy formdataProxy,
        std::vector<FormDataProxy> &subscribeFormDataProxies, std::vector<FormDataProxy> &unsubscribeFormDataProxies);

    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper_;
    std::shared_ptr<Security::AccessToken::PermStateChangeCallbackCustomize> callbackPtr_;
    int64_t formId_ = -1;
    std::string bundleName_;
    FormType uiSyntax_;
    int32_t tokenId_;
    int32_t uid_;
    AAFwk::Want wantCache_;
    SubscribeMap rdbSubscribeMap_;
    SubscribeMap publishSubscribeMap_;
    std::mutex rdbSubscribeResultMapMutex_;
    std::mutex publishSubscribeResultMapMutex_;
    std::map<std::string, std::map<int64_t, SubscribeResultRecord>> rdbSubscribeResultMap_;
    std::map<std::string, std::map<int64_t, SubscribeResultRecord>> publishSubscribeResultMap_;
    std::map<std::string, std::vector<FormDataProxy>> formDataPermissionProxyMap_;
    int32_t receivedDataCount_ = 0;
    const int32_t PERMISSION_GRANTED_OPER = 1;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_DATA_PROXY_RECORD_H