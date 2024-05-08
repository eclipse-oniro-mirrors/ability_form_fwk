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

#include "form_data_proxy_record.h"

#include <cstddef>
#include <string>
#include <vector>

#include "fms_log_wrapper.h"
#include "form_bms_helper.h"
#include "form_data_mgr.h"
#include "form_mgr_adapter.h"
#include "form_mgr_errors.h"
#include "form_provider_mgr.h"
#include "form_util.h"
#include "ipc_skeleton.h"
#include "accesstoken_kit.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string KEY_DELIMITER = "?"; // the delimiter between key and uid
} // namespace

class PermissionCustomizeListener : public Security::AccessToken::PermStateChangeCallbackCustomize {
    public:
        FormDataProxyRecord *formDataProxyRecord_;

        PermissionCustomizeListener(const Security::AccessToken::PermStateChangeScope &scopeInfo,
            FormDataProxyRecord *formDataProxyRecord)
            : Security::AccessToken::PermStateChangeCallbackCustomize(scopeInfo)
        {
            formDataProxyRecord_ = formDataProxyRecord;
        }

        virtual void PermStateChangeCallback(Security::AccessToken::PermStateChangeInfo& result)
        {
            HILOG_INFO("PermStateChangeCallback type = %{public}d, permissionName = %{public}s",
                result.permStateChangeType, result.permissionName.c_str());
            formDataProxyRecord_->PermStateChangeCallback(result.permStateChangeType, result.permissionName);
        }
};

void FormDataProxyRecord::PermStateChangeCallback(const int32_t permStateChangeType, const std::string permissionName)
{
    HILOG_DEBUG("Permission has been changed, form id: %{public}" PRId64 ", permission name: %{public}s.", formId_,
        permissionName.c_str());
    auto search = formDataPermissionProxyMap_.find(permissionName);
    if (search == formDataPermissionProxyMap_.end()) {
        HILOG_ERROR("no permission data proxy, permissionName : %{public}s", permissionName.c_str());
        return;
    }
    std::vector<FormDataProxy> formDataProxies = search->second;
    std::vector<FormDataProxy> subscribeFormDataProxies;
    std::vector<FormDataProxy> unSubscribeFormDataProxies;
    for (const auto &formDataProxy : formDataProxies) {
        GetSubscribeFormDataProxies(formDataProxy, subscribeFormDataProxies, unSubscribeFormDataProxies);
    }

    bool isAuthorized = permStateChangeType == PERMISSION_GRANTED_OPER;
    SubscribeMap rdbSubscribeMap;
    SubscribeMap publishSubscribeMap;
    if (isAuthorized) {
        if (!subscribeFormDataProxies.empty()) {
            SubscribeFormData(subscribeFormDataProxies, rdbSubscribeMap, publishSubscribeMap);
        }
    } else {
        if (!unSubscribeFormDataProxies.empty()) {
            ParseFormDataProxies(unSubscribeFormDataProxies, rdbSubscribeMap, publishSubscribeMap);
            UnsubscribeFormData(rdbSubscribeMap, publishSubscribeMap);
        }
    }
    Want newWant(wantCache_);
    newWant.SetParam(Constants::FORM_PERMISSION_NAME_KEY, permissionName);
    newWant.SetParam(Constants::FORM_PERMISSION_GRANTED_KEY, isAuthorized);
    if (FormProviderMgr::GetInstance().ConnectAmsForRefreshPermission(formId_, newWant) != ERR_OK) {
        HILOG_ERROR(
            "ConnectAmsForRefreshPermission failed, permission name: %{public}s, isAuthorized: %{public}d",
            permissionName.c_str(), isAuthorized);
        return;
    }
}

void FormDataProxyRecord::SetWant(const AAFwk::Want &want)
{
    wantCache_ = want;
}

void FormDataProxyRecord::GetSubscribeFormDataProxies(const FormDataProxy formDataProxy,
    std::vector<FormDataProxy> &subscribeFormDataProxies, std::vector<FormDataProxy> &unSubscribeFormDataProxies)
{
    std::string userId = std::to_string(FormUtil::GetCurrentAccountId());
    std::string token = std::to_string(tokenId_);
    std::string uri = formDataProxy.key + "?" + "user=" + userId + "&srcToken=" + token +
        "&dstBundleName=" + bundleName_;
    auto rdbSubscribeResult = rdbSubscribeResultMap_.find(uri);
    if (rdbSubscribeResult != rdbSubscribeResultMap_.end()) {
        int64_t subscriberId = formId_;
        if (!FormUtil::ConvertStringToInt64(formDataProxy.subscribeId, subscriberId)) {
            HILOG_WARN("Convert string subscribe[%{public}s] to int64 failed, change to default value "
                "formId[%{public}s].", formDataProxy.subscribeId.c_str(), std::to_string(formId_).c_str());
        }
        auto subscribeResultRecord = rdbSubscribeResult->second.find(subscriberId);
        if (subscribeResultRecord != rdbSubscribeResult->second.end()) {
            if (subscribeResultRecord->second.ret != 0) {
                subscribeFormDataProxies.emplace_back(formDataProxy);
            } else {
                unSubscribeFormDataProxies.emplace_back(formDataProxy);
            }
        }
    } else {
        subscribeFormDataProxies.emplace_back(formDataProxy);
    }
}

void FormDataProxyRecord::UnRegisterPermissionListener()
{
    if (callbackPtr_ != nullptr) {
        int32_t accessTokenKit = Security::AccessToken::AccessTokenKit::UnRegisterPermStateChangeCallback(callbackPtr_);
        callbackPtr_ = nullptr;
    }
}

void FormDataProxyRecord::RegisterPermissionListener(const std::vector<FormDataProxy> &formDataProxies)
{
    std::vector<ProxyData> proxyData;
    std::vector<std::string> permList;
    FormBmsHelper::GetInstance().GetAllProxyDataInfos(FormUtil::GetCurrentAccountId(), proxyData);
    if (proxyData.empty() || !formDataPermissionProxyMap_.empty()) {
        return;
    }
    for (const auto &formDataProxy : formDataProxies) {
        for (const auto &data : proxyData) {
            if (formDataProxy.key != data.uri) {
                continue;
            }
            auto search = formDataPermissionProxyMap_.find(data.requiredReadPermission);
            std::vector<FormDataProxy> proxies;
            if (search != formDataPermissionProxyMap_.end()) {
                proxies = search->second;
            }
            permList.emplace_back(data.requiredReadPermission);
            proxies.emplace_back(formDataProxy);
            formDataPermissionProxyMap_[data.requiredReadPermission] = proxies;
            break;
        }
    }
    std::string callingIdentity = IPCSkeleton::ResetCallingIdentity();
    Security::AccessToken::PermStateChangeScope scopeInfo;
    scopeInfo.permList = {permList};
    scopeInfo.tokenIDs = {tokenId_};
    callbackPtr_ = std::make_shared<PermissionCustomizeListener>(scopeInfo, this);
    int32_t accessTokenKit = Security::AccessToken::AccessTokenKit::RegisterPermStateChangeCallback(callbackPtr_);
    IPCSkeleton::SetCallingIdentity(callingIdentity);
    HILOG_INFO("RegisterPermissionListener formId = %{public}s", std::to_string(formId_).c_str());
    if (accessTokenKit != 0) {
        formDataPermissionProxyMap_.clear();
    }
}


void FormDataProxyRecord::OnRdbDataChange(const DataShare::RdbChangeNode &changeNode)
{
    HILOG_INFO("on rdb data change. data size is %{public}zu", changeNode.data_.size());
    if (changeNode.data_.size() == 0) {
        return;
    }
    UpdateRdbDataForm(changeNode.data_);
}

void FormDataProxyRecord::OnPublishedDataChange(const DataShare::PublishedDataChangeNode &changeNode)
{
    HILOG_DEBUG("on published data change. data size is %{public}zu", changeNode.datas_.size());
    UpdatePublishedDataForm(changeNode.datas_);
}

FormDataProxyRecord::FormDataProxyRecord(int64_t formId, const std::string &bundleName, FormType uiSyntax,
    uint32_t tokenId, int32_t uid) : formId_(formId), bundleName_(bundleName), uiSyntax_(uiSyntax),
    tokenId_(tokenId), uid_(uid)
{
    HILOG_INFO("create FormDataProxyRecord formId: %{public}s, bundleName: %{public}s",
        std::to_string(formId).c_str(), bundleName.c_str());
    std::string uri = "datashareproxy://" + bundleName;
    DataShare::CreateOptions options;
    options.isProxy_ = true;
    dataShareHelper_ = DataShare::DataShareHelper::Creator(uri, options);
}

FormDataProxyRecord::~FormDataProxyRecord()
{
    HILOG_INFO("destroy FormDataProxyRecod formId: %{public}s, bundleName: %{public}s",
        std::to_string(formId_).c_str(), bundleName_.c_str());
    UnRegisterPermissionListener();
    if (dataShareHelper_ != nullptr) {
        dataShareHelper_->Release();
    }
}

ErrCode FormDataProxyRecord::SubscribeFormData(const std::vector<FormDataProxy> &formDataProxies)
{
    RegisterPermissionListener(formDataProxies);
    return SubscribeFormData(formDataProxies, rdbSubscribeMap_, publishSubscribeMap_);
}

ErrCode FormDataProxyRecord::SubscribeFormData(const std::vector<FormDataProxy> &formDataProxies,
    SubscribeMap &rdbSubscribeMap, SubscribeMap &publishSubscribeMap)
{
    HILOG_INFO("subscribe form data, formDataProxies size: %{public}zu.", formDataProxies.size());
    ParseFormDataProxies(formDataProxies, rdbSubscribeMap, publishSubscribeMap);
    ErrCode ret = ERR_OK;
    ret = SubscribeRdbFormData(rdbSubscribeMap);
    if (ret != ERR_OK) {
        HILOG_ERROR("subscribe rdb form data failed.");
        return ret;
    }
    ret = SubscribePublishFormData(publishSubscribeMap);
    if (ret != ERR_OK) {
        HILOG_ERROR("subscribe publish form data failed.");
        return ret;
    }
    return ret;
}

ErrCode FormDataProxyRecord::SubscribeRdbFormData(const SubscribeMap &rdbSubscribeMap)
{
    HILOG_INFO("SubscribeRdbFormData");
    if (dataShareHelper_ == nullptr) {
        HILOG_ERROR("dataShareHelper is nullptr.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (rdbSubscribeMap.empty()) {
        HILOG_ERROR("rdbSubscribeMap is empty.");
        return ERR_OK;
    }

    std::vector<FormDataProxyRequest> formDataProxyRequests;
    ConvertSubscribeMapToRequests(rdbSubscribeMap, formDataProxyRequests);

    std::weak_ptr<FormDataProxyRecord> weak(shared_from_this());
    auto rdbTask = [weak](const DataShare::RdbChangeNode &changeNode) {
        auto formDataRecord = weak.lock();
        if (formDataRecord == nullptr) {
            HILOG_ERROR("formDataRecord is nullptr.");
            return;
        }
        formDataRecord->OnRdbDataChange(changeNode);
    };
    for (const auto &search : formDataProxyRequests) {
        DataShare::TemplateId templateId;
        templateId.subscriberId_ = search.subscribeId;
        templateId.bundleName_ = bundleName_;
        auto ret = dataShareHelper_->SubscribeRdbData(search.uris, templateId, rdbTask);
        uint32_t failNum = 0;
        for (const auto &iter : ret) {
            SubscribeResultRecord record{iter.key_, search.subscribeId, iter.errCode_, false, 0};
            AddSubscribeResultRecord(record, true);
            if (iter.errCode_ != 0) {
                HILOG_ERROR("subscribe rdb data failed. uri: %{public}s, errCode: %{public}d",
                    iter.key_.c_str(), iter.errCode_);
                failNum++;
            }
        }
        HILOG_DEBUG("subscribe rdb data. subscribeId: %{public}s, failNum: %{public}d, totalNum: %{public}zu",
            std::to_string(search.subscribeId).c_str(), failNum, search.uris.size());
    }

    return ERR_OK;
}

ErrCode FormDataProxyRecord::SubscribePublishFormData(const SubscribeMap &publishSubscribeMap)
{
    HILOG_INFO("SubscribePublishFormData");
    if (dataShareHelper_ == nullptr) {
        HILOG_ERROR("dataShareHelper is nullptr.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (publishSubscribeMap.empty()) {
        HILOG_ERROR("publishSubscribeMap is nullptr.");
        return ERR_OK;
    }

    std::vector<FormDataProxyRequest> formDataProxyRequests;
    ConvertSubscribeMapToRequests(publishSubscribeMap, formDataProxyRequests);

    std::weak_ptr<FormDataProxyRecord> weak(shared_from_this());
    auto publishedTask = [weak](const DataShare::PublishedDataChangeNode &changeNode) {
        auto formDataRecord = weak.lock();
        if (formDataRecord == nullptr) {
            HILOG_ERROR("formDataRecord is nullptr.");
            return;
        }
        formDataRecord->OnPublishedDataChange(changeNode);
    };
    for (const auto &search : formDataProxyRequests) {
        auto ret = dataShareHelper_->SubscribePublishedData(search.uris, search.subscribeId, publishedTask);
        uint32_t failNum = 0;
        for (const auto &iter : ret) {
            SubscribeResultRecord record{iter.key_, search.subscribeId, iter.errCode_, false, 0};
            AddSubscribeResultRecord(record, false);
            if (iter.errCode_ != 0) {
                HILOG_ERROR("subscribe published data failed. uri: %{public}s, errCode: %{public}d",
                    iter.key_.c_str(), iter.errCode_);
                failNum++;
            }
        }
        HILOG_DEBUG("subscribe published data. subscribeId: %{public}s, failNum: %{public}d, totalNum: %{public}zu",
            std::to_string(search.subscribeId).c_str(), failNum, search.uris.size());
    }

    return ERR_OK;
}

ErrCode FormDataProxyRecord::UnsubscribeFormData()
{
    return UnsubscribeFormData(rdbSubscribeMap_, publishSubscribeMap_);
}

ErrCode FormDataProxyRecord::UnsubscribeFormData(SubscribeMap &rdbSubscribeMap, SubscribeMap &publishSubscribeMap)
{
    if (dataShareHelper_ == nullptr) {
        HILOG_ERROR("dataShareHelper is nullptr.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    std::vector<FormDataProxyRequest> rdbRequests;
    ConvertSubscribeMapToRequests(rdbSubscribeMap, rdbRequests);
    for (const auto &search : rdbRequests) {
        DataShare::TemplateId templateId;
        templateId.subscriberId_ = search.subscribeId;
        templateId.bundleName_ = bundleName_;
        dataShareHelper_->UnsubscribeRdbData(search.uris, templateId);
        for (const auto &uri : search.uris) {
            RemoveSubscribeResultRecord(uri, search.subscribeId, true);
        }
    }
    rdbSubscribeMap.clear();

    std::vector<FormDataProxyRequest> publishRequests;
    ConvertSubscribeMapToRequests(publishSubscribeMap, publishRequests);
    for (const auto &search : publishRequests) {
        dataShareHelper_->UnsubscribePublishedData(search.uris, search.subscribeId);
        for (const auto &uri : search.uris) {
            RemoveSubscribeResultRecord(uri, search.subscribeId, false);
        }
    }
    publishSubscribeMap.clear();
    return ERR_OK;
}

void FormDataProxyRecord::ParseFormDataProxies(const std::vector<FormDataProxy> &formDataProxies,
    SubscribeMap &rdbSubscribeMap, SubscribeMap &publishSubscribeMap)
{
    std::vector<ProxyData> proxyData;
    FormBmsHelper::GetInstance().GetAllProxyDataInfos(FormUtil::GetCurrentAccountId(), proxyData);
    HILOG_INFO("ParseFormDataProxies proxyData.size: %{public}zu", proxyData.size());
    for (size_t i = 0; i < proxyData.size(); ++i) {
        HILOG_INFO("ParseFormDataProxies proxyData[%{public}zu].uri: %{public}s", i, proxyData[i].uri.c_str());
    }

    std::unordered_set<std::string> expectedKeys;
    for (auto &data : proxyData) {
        expectedKeys.emplace(data.uri);
    }

    HILOG_INFO("subscribe rdb data");
    ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys(formDataProxies, expectedKeys, true, rdbSubscribeMap);
    HILOG_INFO("subscribe publish data");
    ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys(formDataProxies, expectedKeys, false, publishSubscribeMap);
}

void FormDataProxyRecord::ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys(
    const std::vector<FormDataProxy> &formDataProxies, const std::unordered_set<std::string> &expectedKeys,
    bool keyCheckingNeeded, SubscribeMap &subscribeMap)
{
    subscribeMap.clear();
    for (const auto &formDataProxy : formDataProxies) {
        if (keyCheckingNeeded && expectedKeys.find(formDataProxy.key) == expectedKeys.end()) {
            continue;
        }
        auto subscribe = formDataProxy.subscribeId.empty() ? std::to_string(formId_) : formDataProxy.subscribeId;
        auto it = subscribeMap.find(formDataProxy.key);
        if (it == subscribeMap.end()) {
            std::unordered_set<std::string> subscribeIds;
            subscribeIds.emplace(subscribe);
            subscribeMap.emplace(formDataProxy.key, subscribeIds);
        } else {
            it->second.emplace(subscribe);
        }
        HILOG_INFO("parse subscribe record: key: %{public}s, subscribeId: %{public}s",
            formDataProxy.key.c_str(), subscribe.c_str());
    }
}

void FormDataProxyRecord::ConvertSubscribeMapToRequests(
    const SubscribeMap &subscribeMap, std::vector<FormDataProxyRequest> &formDataProxyRequests)
{
    formDataProxyRequests.clear();
    std::string userId = std::to_string(FormUtil::GetCurrentAccountId());
    std::string token = std::to_string(tokenId_);
    std::unordered_map<int64_t, std::vector<std::string>> subscribeId2UrisMap;

    for (const auto &record : subscribeMap) {
        const auto &key = record.first;
        for (const auto &subscribe : record.second) {
            int64_t subscriberId = formId_;
            if (!FormUtil::ConvertStringToInt64(subscribe, subscriberId)) {
                HILOG_WARN("Convert string subscribe[%{public}s] to int64 failed, change to default value "
                    "formId[%{public}s].", subscribe.c_str(), std::to_string(formId_).c_str());
            }

            std::string uri = key + "?" + "user=" + userId + "&srcToken=" + token + "&dstBundleName=" + bundleName_;
            auto it = subscribeId2UrisMap.find(subscriberId);
            if (it == subscribeId2UrisMap.end()) {
                std::vector<std::string> uris;
                uris.push_back(uri);
                subscribeId2UrisMap.emplace(subscriberId, uris);
            } else {
                it->second.push_back(uri);
            }
        }
    }

    for (auto &record : subscribeId2UrisMap) {
        FormDataProxyRequest request{record.first, std::move(record.second)};
        formDataProxyRequests.push_back(request);
    }
}

void FormDataProxyRecord::UpdatePublishedDataForm(const std::vector<DataShare::PublishedDataItem> &data)
{
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    nlohmann::json object;
    std::string formDataKeysStr = "";
    for (const auto& iter : data) {
        if (iter.key_.empty()) {
            HILOG_ERROR("key is empty.");
            continue;
        }
        if (iter.IsAshmem()) {
            PrepareImageData(iter, object, imageDataMap);
        } else {
            auto value = std::get<std::string>(iter.value_);
            nlohmann::json dataObject = nlohmann::json::parse(value, nullptr, false);
            if (dataObject.is_discarded()) {
                HILOG_ERROR("failed to parse data: %{public}s.", value.c_str());
                continue;
            }
            object[iter.key_] = dataObject;
            std::string newKeyStr = formDataKeysStr.empty() ? iter.key_ : (", " + iter.key_);
            formDataKeysStr += newKeyStr;
        }
    }
    std::string formDataStr = object.empty() ? "" : object.dump();
    std::string subStr = formDataStr.substr(0, std::min((int)formDataStr.length(), 30));
    HILOG_INFO("form[formId: %{public}s] will update published data. formDataStr[len: %{public}zu]: %{private}s, "
        "formDataKeysStr: %{public}s, imageDataMap size: %{public}zu.", std::to_string(formId_).c_str(),
        formDataStr.length(), subStr.c_str(), formDataKeysStr.c_str(), imageDataMap.size());

    FormProviderData formProviderData;
    formProviderData.SetDataString(formDataStr);
    if (!imageDataMap.empty()) {
        formProviderData.SetImageDataState(FormProviderData::IMAGE_DATA_STATE_ADDED);
        formProviderData.SetImageDataMap(imageDataMap);
    }
    auto ret = FormMgrAdapter::GetInstance().UpdateForm(formId_, uid_, formProviderData);
    if (ret == ERR_OK && receivedDataCount_ < INT32_MAX) {
        receivedDataCount_ += 1;
    }
}

void FormDataProxyRecord::UpdateRdbDataForm(const std::vector<std::string> &data)
{
    nlohmann::json object;
    for (const auto& iter : data) {
        HILOG_DEBUG("iter: %{private}s.", iter.c_str());
        nlohmann::json dataObject = nlohmann::json::parse(iter, nullptr, false);
        if (dataObject.is_discarded()) {
            HILOG_ERROR("failed to parse data: %{public}s.", iter.c_str());
            continue;
        }
        object.merge_patch(dataObject);
    }

    std::string formDataStr = object.empty() ? "" : object.dump();
    std::string subStr = formDataStr.substr(0, std::min((int)formDataStr.size(), 30));
    HILOG_INFO("form[formId: %{public}s] will update rdb data. formDataStr[len: %{public}zu]: %{private}s.",
        std::to_string(formId_).c_str(), formDataStr.length(), subStr.c_str());

    FormProviderData formProviderData;
    formProviderData.SetDataString(formDataStr);
    auto ret = FormMgrAdapter::GetInstance().UpdateForm(formId_, uid_, formProviderData);
    if (ret == ERR_OK && receivedDataCount_ < INT32_MAX) {
        receivedDataCount_ += 1;
    }
}

void FormDataProxyRecord::UpdateSubscribeFormData(const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_INFO("UpdateSubscribeFormData");
    SubscribeMap originRdbMap;
    SubscribeMap newRdbMap;
    SubscribeMap originPublishMap;
    SubscribeMap newPublishMap;
    UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);
    UnsubscribeFormData(originRdbMap, originPublishMap);
    SubscribeRdbFormData(newRdbMap);
    SubscribePublishFormData(newPublishMap);
}

void FormDataProxyRecord::UpdateSubscribeMap(const std::vector<FormDataProxy> &formDataProxies,
    SubscribeMap &originRdbMap, SubscribeMap &newRdbMap, SubscribeMap &originPublishMap, SubscribeMap &newPublishMap)
{
    SubscribeMap updateMap;
    std::unordered_set<std::string> expectedKeys;
    ParseFormDataProxiesIntoSubscribeMapWithExpectedKeys(formDataProxies, expectedKeys, false, updateMap);
    for (const auto &record : updateMap) {
        const auto &key = record.first;
        const auto &newSubscribeIds = record.second;
        auto it = rdbSubscribeMap_.find(key);
        if (it != rdbSubscribeMap_.end()) {
            originRdbMap[key] = it->second;
            newRdbMap[key] = newSubscribeIds;
            rdbSubscribeMap_[key] = newSubscribeIds;
        }
        it = publishSubscribeMap_.find(key);
        if (it != publishSubscribeMap_.end()) {
            originPublishMap[key] = it->second;
            newPublishMap[key] = newSubscribeIds;
            publishSubscribeMap_[key] = newSubscribeIds;
        }
    }
}

void FormDataProxyRecord::EnableSubscribeFormData()
{
    HILOG_INFO("enable subscribe form, formId:%{public}s, rdbSize:%{public}zu, publishSize:%{public}zu",
        std::to_string(formId_).c_str(), rdbSubscribeMap_.size(), publishSubscribeMap_.size());
    SetRdbSubsState(rdbSubscribeMap_, true);
    SetPublishSubsState(publishSubscribeMap_, true);
}

void FormDataProxyRecord::DisableSubscribeFormData()
{
    HILOG_DEBUG("disable subscribe form, formId: %{public}s.", std::to_string(formId_).c_str());
    SetRdbSubsState(rdbSubscribeMap_, false);
    SetPublishSubsState(publishSubscribeMap_, false);
}

void FormDataProxyRecord::RetryFailureSubscribes()
{
    HILOG_INFO("retry subscribe form, formId: %{public}s", std::to_string(formId_).c_str());
    if (dataShareHelper_ == nullptr) {
        HILOG_ERROR("dataShareHelper is nullptr.");
        return;
    }

    for (auto& result : rdbSubscribeResultMap_) {
        for (auto& records : result.second) {
            auto& record = records.second;
            RetryFailureRdbSubscribes(record);
        }
    }

    for (auto& result : publishSubscribeResultMap_) {
        for (auto& records : result.second) {
            auto& record = records.second;
            RetryFailurePublishedSubscribes(record);
        }
    }
}

void FormDataProxyRecord::GetFormSubscribeInfo(std::vector<std::string> &subscribedKeys, int32_t &count)
{
    GetFormSubscribeKeys(subscribedKeys, true);
    GetFormSubscribeKeys(subscribedKeys, false);
    count = receivedDataCount_;
}

ErrCode FormDataProxyRecord::SetRdbSubsState(const SubscribeMap &rdbSubscribeMap, bool subsState)
{
    if (dataShareHelper_ == nullptr) {
        HILOG_ERROR("dataShareHelper is nullptr.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (rdbSubscribeMap.empty()) {
        HILOG_DEBUG("rdbSubscribeMap is empty.");
        return ERR_OK;
    }

    std::vector<FormDataProxyRequest> formDataProxyRequests;
    ConvertSubscribeMapToRequests(rdbSubscribeMap, formDataProxyRequests);

    for (const auto &search : formDataProxyRequests) {
        DataShare::TemplateId templateId;
        templateId.subscriberId_ = search.subscribeId;
        templateId.bundleName_ = bundleName_;
        std::vector<DataShare::OperationResult> ret;
        if (subsState) {
            ret = dataShareHelper_->EnableRdbSubs(search.uris, templateId);
        } else {
            ret = dataShareHelper_->DisableRdbSubs(search.uris, templateId);
        }
        uint32_t failNum = 0;
        for (const auto &iter : ret) {
            if (iter.errCode_ != 0) {
                PrintSubscribeState(iter.key_, search.subscribeId, true);
                failNum++;
            }
        }
        HILOG_DEBUG("set rdb state. subscribeId: %{public}s, failNum: %{public}d, totalNum: %{public}zu",
            std::to_string(search.subscribeId).c_str(), failNum, search.uris.size());
    }

    return ERR_OK;
}

ErrCode FormDataProxyRecord::SetPublishSubsState(const SubscribeMap &publishSubscribeMap,
    bool subsState)
{
    if (dataShareHelper_ == nullptr) {
        HILOG_ERROR("dataShareHelper is nullptr.");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    if (publishSubscribeMap.empty()) {
        HILOG_DEBUG("publishSubscribeMap is nullptr.");
        return ERR_OK;
    }

    std::vector<FormDataProxyRequest> formDataProxyRequests;
    ConvertSubscribeMapToRequests(publishSubscribeMap, formDataProxyRequests);

    for (const auto &search : formDataProxyRequests) {
        std::vector<DataShare::OperationResult> ret;
        if (subsState) {
            ret = dataShareHelper_->EnablePubSubs(search.uris, search.subscribeId);
        } else {
            ret = dataShareHelper_->DisablePubSubs(search.uris, search.subscribeId);
        }
        uint32_t failNum = 0;
        for (const auto &iter : ret) {
            if (iter.errCode_ != 0) {
                PrintSubscribeState(iter.key_, search.subscribeId, false);
                failNum++;
            }
        }
        HILOG_DEBUG("set published state. subscribeId: %{public}s, failNum: %{public}d, totalNum: %{public}zu",
            std::to_string(search.subscribeId).c_str(), failNum, search.uris.size());
    }

    return ERR_OK;
}

/*
 * we need to automatically produce image names due to differences in usage between image publishing and rendering
 */
bool FormDataProxyRecord::PrepareImageData(const DataShare::PublishedDataItem &data, nlohmann::json &jsonObj,
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> &imageDataMap)
{
    auto node = std::get<DataShare::AshmemNode>(data.value_);
    if (node.ashmem == nullptr) {
        HILOG_ERROR("ashmem form data share is nullptr.");
        return false;
    }
    sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
    if (formAshmem == nullptr) {
        HILOG_ERROR("alloc shmem failed");
        return false;
    }
    auto size = node.ashmem->GetAshmemSize();
    auto imageName = data.key_ + std::to_string(FormUtil::GetCurrentNanosecond());
    if (!formAshmem->WriteToAshmem(imageName, (char *)node.ashmem->ReadFromAshmem(size, 0), size)) {
        HILOG_ERROR("write to shmem failed");
        return false;
    }

    jsonObj[data.key_] = imageName;
    if (uiSyntax_ == FormType::JS) {
        jsonObj[data.key_] = "memory://" + imageName; // adapt memory image uri for js card
    }

    std::pair<sptr<FormAshmem>, int32_t> imageDataRecord = std::make_pair(formAshmem, sizeof(formAshmem));
    imageDataMap[imageName] = imageDataRecord;
    return true;
}

void FormDataProxyRecord::AddSubscribeResultRecord(SubscribeResultRecord record, bool isRdbType)
{
    std::map<std::string, std::map<int64_t, SubscribeResultRecord>>* resultMap =
        isRdbType ? &rdbSubscribeResultMap_ : &publishSubscribeResultMap_;
    auto mapIter = resultMap->find(record.uri);
    if (mapIter == resultMap->end()) {
        std::map<int64_t, SubscribeResultRecord> records;
        records.emplace(record.subscribeId, record);
        resultMap->emplace(record.uri, records);
    } else {
        mapIter->second[record.subscribeId] = record;
    }
}

void FormDataProxyRecord::RemoveSubscribeResultRecord(const std::string &uri, int64_t subscribeId, bool isRdbType)
{
    std::map<std::string, std::map<int64_t, SubscribeResultRecord>>* resultMap =
        isRdbType ? &rdbSubscribeResultMap_ : &publishSubscribeResultMap_;
    auto mapIter = resultMap->find(uri);
    if (mapIter == resultMap->end()) {
        return;
    }
    auto it = mapIter->second.find(subscribeId);
    if (it != mapIter->second.end()) {
        mapIter->second.erase(it);
    }
    if (mapIter->second.empty()) {
        resultMap->erase(mapIter);
    }
}

void FormDataProxyRecord::PrintSubscribeState(const std::string &uri, int64_t subscribeId, bool isRdbType)
{
    std::string type = isRdbType ? "rdb" : "published";
    std::map<std::string, std::map<int64_t, SubscribeResultRecord>>* resultMap =
        isRdbType ? &rdbSubscribeResultMap_ : &publishSubscribeResultMap_;
    bool alreadySubscribed = true;
    auto mapIter = resultMap->find(uri);
    if (mapIter == resultMap->end()) {
        alreadySubscribed = false;
    } else {
        auto it = mapIter->second.find(subscribeId);
        if (it == mapIter->second.end()) {
            alreadySubscribed = false;
        } else {
            HILOG_ERROR("subscribe state, type: %{public}s, uri: %{public}s, subscriberId: %{public}s, "
                "ret: %{public}d, retry: %{public}s, retryRet: %{public}d", type.c_str(), uri.c_str(),
                std::to_string(subscribeId).c_str(), it->second.ret, (it->second.retry ? "yes" : "no"),
                it->second.retryRet);
        }
    }
    if (!alreadySubscribed) {
        HILOG_ERROR("failed to find subscribe record, type: %{public}s uri: %{public}s, subscriberId: %{public}s",
            type.c_str(), uri.c_str(), std::to_string(subscribeId).c_str());
    }
}

void FormDataProxyRecord::RetryFailureRdbSubscribes(SubscribeResultRecord &record)
{
    // ok or already retry
    if (record.ret == 0 || record.retry) {
        return;
    }

    std::weak_ptr<FormDataProxyRecord> weak(shared_from_this());
    auto rdbTask = [weak](const DataShare::RdbChangeNode &changeNode) {
        auto formDataRecord = weak.lock();
        if (formDataRecord == nullptr) {
            HILOG_ERROR("formDataRecord is nullptr.");
            return;
        }
        formDataRecord->OnRdbDataChange(changeNode);
    };

    record.retry = true;
    std::vector<std::string> uris{record.uri};
    DataShare::TemplateId templateId;
    templateId.subscriberId_ = record.subscribeId;
    templateId.bundleName_ = bundleName_;
    auto ret = dataShareHelper_->SubscribeRdbData(uris, templateId, rdbTask);
    for (const auto &iter : ret) {
        if (iter.errCode_ != 0) {
            HILOG_ERROR("retry subscribe rdb data failed, uri: %{public}s, subscriberId: %{public}s, "
                "errCode: %{public}d", iter.key_.c_str(), std::to_string(record.subscribeId).c_str(), iter.errCode_);
        } else {
            HILOG_INFO("retry subscribe rdb data success, uri: %{public}s, subscriberId: %{public}s",
                iter.key_.c_str(), std::to_string(record.subscribeId).c_str());
        }
        record.retryRet = iter.errCode_;
    }
}

void FormDataProxyRecord::RetryFailurePublishedSubscribes(SubscribeResultRecord &record)
{
    // ok or already retry
    if (record.ret == 0 || record.retry) {
        return;
    }

    std::weak_ptr<FormDataProxyRecord> weak(shared_from_this());
    auto publishedTask = [weak](const DataShare::PublishedDataChangeNode &changeNode) {
        auto formDataRecord = weak.lock();
        if (formDataRecord == nullptr) {
            HILOG_ERROR("formDataRecord is nullptr.");
            return;
        }
        formDataRecord->OnPublishedDataChange(changeNode);
    };

    record.retry = true;
    std::vector<std::string> uris{record.uri};
    auto ret = dataShareHelper_->SubscribePublishedData(uris, record.subscribeId, publishedTask);
    for (const auto &iter : ret) {
        if (iter.errCode_ != 0) {
            HILOG_ERROR("retry subscribe published data failed, uri: %{public}s, subscriberId: %{public}s, "
                "errCode: %{public}d", iter.key_.c_str(), std::to_string(record.subscribeId).c_str(), iter.errCode_);
        } else {
            HILOG_INFO("retry subscribe published data success, uri: %{public}s, subscriberId: %{public}s",
                iter.key_.c_str(), std::to_string(record.subscribeId).c_str());
        }
        record.retryRet = iter.errCode_;
    }
}

void FormDataProxyRecord::GetFormSubscribeKeys(std::vector<std::string> &subscribedKeys, bool isRdbType)
{
    auto resultMap = isRdbType ? rdbSubscribeResultMap_ : publishSubscribeResultMap_;
    for (auto &result : resultMap) {
        for (auto &records : result.second) {
            auto &record = records.second;
            if (record.ret != 0) {
                continue;
            }
            auto uri = record.uri;
            auto index = uri.find(KEY_DELIMITER);
            if (index == std::string::npos) {
                return;
            }
            auto subscribeKey = uri.substr(0, index);
            auto search = std::find(subscribedKeys.begin(), subscribedKeys.end(), subscribeKey);
            if (search == subscribedKeys.end()) {
                subscribedKeys.emplace_back(subscribeKey);
            }
        }
    }
}
} // namespace AppExecFwk
} // namespace OHOS