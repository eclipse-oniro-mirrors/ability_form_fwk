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

#include <vector>

#include "form_ashmem.h"
#include "form_bms_helper.h"
#include "form_data_mgr.h"
#include "form_mgr_adapter.h"
#include "form_mgr_errors.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "nlohmann/json.hpp"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
void FormDataProxyRecord::OnRdbDataChange(const DataShare::RdbChangeNode &changeNode)
{
    HILOG_DEBUG("on rdb data change.");
    UpdateRdbDataForm(changeNode.data_);
}

void FormDataProxyRecord::OnPublishedDataChange(const DataShare::PublishedDataChangeNode &changeNode)
{
    HILOG_DEBUG("on published data change.");
    UpdatePublishedDataForm(changeNode.datas_);
}

FormDataProxyRecord::FormDataProxyRecord(int64_t formId, const std::string &bundleName, const std::string &moduleName,
    uint32_t tokenId) : formId_(formId), bundleName_(bundleName), moduleName_(moduleName), tokenId_(tokenId)
{
    std::string uri = "datashareproxy://" + bundleName;
    DataShare::CreateOptions options;
    options.isProxy_ = true;
    dataShareHelper_ = DataShare::DataShareHelper::Creator(uri, options);
}

FormDataProxyRecord::~FormDataProxyRecord()
{
    if (dataShareHelper_ != nullptr) {
        dataShareHelper_->Release();
    }
}

ErrCode FormDataProxyRecord::SubscribeFormData(const std::vector<FormDataProxy> &formDataProxies)
{
    HILOG_DEBUG("subscribe form data.");
    ParseFormDataProxies(formDataProxies);
    ErrCode ret = ERR_OK;
    ret = SubscribeRdbFormData(rdbSubscribeMap_);
    if (ret != ERR_OK) {
        HILOG_ERROR("subscribe rdb form data failed.");
        return ret;
    }
    ret = SubscribePublishFormData(publishSubscribeMap_);
    if (ret != ERR_OK) {
        HILOG_ERROR("subscribe publish form data failed.");
        return ret;
    }
    return ret;
}

ErrCode FormDataProxyRecord::SubscribeRdbFormData(std::map<std::string, std::string> &rdbSubscribeMap)
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
            if (iter.errCode_ != 0) {
                HILOG_ERROR("subscribe rdb data failed. %{public}s", iter.key_.c_str());
                failNum++;
            }
        }
        HILOG_DEBUG("subscribe rdb data. subscribeId: %{public}s, failNum: %{public}d, totalNum: %{public}zu",
            std::to_string(search.subscribeId).c_str(), failNum, search.uris.size());
    }

    return ERR_OK;
}

ErrCode FormDataProxyRecord::SubscribePublishFormData(std::map<std::string, std::string> &publishSubscribeMap)
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
            if (iter.errCode_ != 0) {
                HILOG_ERROR("subscribe published data failed. %{public}s", iter.key_.c_str());
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

ErrCode FormDataProxyRecord::UnsubscribeFormData(std::map<std::string, std::string> &rdbSubscribeMap,
    std::map<std::string, std::string> &publishSubscribeMap)
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
    }
    rdbSubscribeMap.clear();

    std::vector<FormDataProxyRequest> publishRequests;
    ConvertSubscribeMapToRequests(publishSubscribeMap, publishRequests);
    for (const auto &search : publishRequests) {
        dataShareHelper_->UnsubscribePublishedData(search.uris, search.subscribeId);
    }
    publishSubscribeMap.clear();
    return ERR_OK;
}

void FormDataProxyRecord::ParseFormDataProxies(const std::vector<FormDataProxy> &formDataProxies)
{
    std::vector<ProxyData> proxyData;
    FormBmsHelper::GetInstance().GetProxyDataInfos(bundleName_, moduleName_, FormUtil::GetCurrentAccountId(),
        proxyData);

    for (const auto& formDataProxy : formDataProxies) {
        auto subscribe = formDataProxy.subscribeId.empty() ? std::to_string(formId_) : formDataProxy.subscribeId;
        bool isRdbSubscribe = false;
        for (const auto& iter : proxyData) {
            if (formDataProxy.key == iter.uri) {
                rdbSubscribeMap_[formDataProxy.key] = subscribe;
                isRdbSubscribe = true;
                HILOG_DEBUG("subscribe rdb data. key: %{public}s, subscribeId: %{public}s",
                    formDataProxy.key.c_str(), subscribe.c_str());
                break;
            }
        }
        if (isRdbSubscribe == false) {
            publishSubscribeMap_[formDataProxy.key] = subscribe;
            HILOG_DEBUG("subscribe publish data. key: %{public}s, subscribeId: %{public}s",
                formDataProxy.key.c_str(), subscribe.c_str());
        }
    }
}

void FormDataProxyRecord::ConvertSubscribeMapToRequests(std::map<std::string, std::string> &subscribeMap,
    std::vector<FormDataProxyRequest> &formDataProxyRequests)
{
    std::string userId = std::to_string(FormUtil::GetCurrentAccountId());
    for (const auto &subscribe : subscribeMap) {
        int64_t subscriberId = formId_;
        if (!FormUtil::ConvertStringToInt64(subscribe.second, subscriberId)) {
            HILOG_WARN("Convert string to int64 failed, change to default value formId.");
        }
        bool isNewSubscriberId = true;
        std::string uri;
        for (auto &search : formDataProxyRequests) {
            if (search.subscribeId == subscriberId) {
                uri = subscribe.first + "?" + "user=" + userId + "&srcToken=" + std::to_string(tokenId_) +
                    "&dstBundleName=" + bundleName_;
                search.uris.push_back(uri);
                isNewSubscriberId = false;
                break;
            }
        }
        if (isNewSubscriberId == true) {
            FormDataProxyRequest formDataProxyRequest;
            formDataProxyRequest.subscribeId = subscriberId;
            uri = subscribe.first + "?" + "user=" + userId + "&srcToken=" + std::to_string(tokenId_) +
                "&dstBundleName=" + bundleName_;
            formDataProxyRequest.uris.emplace_back(uri);
            formDataProxyRequests.push_back(formDataProxyRequest);
        }
    }
}

void FormDataProxyRecord::UpdatePublishedDataForm(const std::vector<DataShare::PublishedDataItem> &data)
{
    std::map<std::string, std::pair<sptr<FormAshmem>, int32_t>> imageDataMap;
    nlohmann::json object;
    for (const auto& iter : data) {
        if (iter.key_.empty()) {
            HILOG_ERROR("key is empty.");
            continue;
        }
        if (iter.IsAshmem()) {
            auto node = std::get<DataShare::AshmemNode>(iter.value_);
            if (node.ashmem == nullptr) {
                HILOG_ERROR("ashmem form data share is nullptr.");
                continue;
            }

            sptr<FormAshmem> formAshmem = new (std::nothrow) FormAshmem();
            if (formAshmem == nullptr) {
                HILOG_ERROR("alloc shmem failed");
                continue;
            }
            auto size = node.ashmem->GetAshmemSize();
            if (!formAshmem->WriteToAshmem(iter.key_, (char *)node.ashmem->ReadFromAshmem(size, 0), size)) {
                HILOG_ERROR("write to shmem failed");
                continue;
            }
            std::pair<sptr<FormAshmem>, int32_t> imageDataRecord = std::make_pair(formAshmem, sizeof(formAshmem));
            imageDataMap[iter.key_] = imageDataRecord;
        } else {
            auto value = std::get<std::string>(iter.value_);
            nlohmann::json dataObject = nlohmann::json::parse(value, nullptr, false);
            if (dataObject.is_discarded()) {
                HILOG_ERROR("failed to parse data: %{public}s.", value.c_str());
                continue;
            }
            object[iter.key_] = dataObject;
        }
    }
    std::string formDataStr = object.empty() ? "" : object.dump();
    HILOG_DEBUG("formDataStr: %{private}s.", formDataStr.c_str());
    FormProviderData formProviderData;
    formProviderData.SetDataString(formDataStr);
    if (!imageDataMap.empty()) {
        formProviderData.SetImageDataState(FormProviderData::IMAGE_DATA_STATE_ADDED);
        formProviderData.SetImageDataMap(imageDataMap);
    }
    FormMgrAdapter::GetInstance().UpdateForm(formId_, bundleName_, formProviderData);
}

void FormDataProxyRecord::UpdateRdbDataForm(const std::vector<std::string> &data)
{
    nlohmann::json object;
    for (const auto& iter : data) {
        nlohmann::json dataObject = nlohmann::json::parse(iter, nullptr, false);
        if (dataObject.is_discarded()) {
            HILOG_ERROR("failed to parse data: %{public}s.", iter.c_str());
            continue;
        }
        object.merge_patch(dataObject);
    }

    std::string formDataStr = object.empty() ? "" : object.dump();
    HILOG_DEBUG("formDataStr: %{private}s.", formDataStr.c_str());
    FormProviderData formProviderData;
    formProviderData.SetDataString(formDataStr);
    FormMgrAdapter::GetInstance().UpdateForm(formId_, bundleName_, formProviderData);
}

void FormDataProxyRecord::UpdateSubscribeFormData(const std::vector<FormDataProxy> &formDataProxies)
{
    std::map<std::string, std::string> originRdbMap;
    std::map<std::string, std::string> newRdbMap;
    std::map<std::string, std::string> originPublishMap;
    std::map<std::string, std::string> newPublishMap;
    UpdateSubscribeMap(formDataProxies, originRdbMap, newRdbMap, originPublishMap, newPublishMap);
    UnsubscribeFormData(originRdbMap, originPublishMap);
    SubscribeRdbFormData(newRdbMap);
    SubscribePublishFormData(newPublishMap);
}

void FormDataProxyRecord::UpdateSubscribeMap(const std::vector<FormDataProxy> &formDataProxies,
    std::map<std::string, std::string> &originRdbMap,
    std::map<std::string, std::string> &newRdbMap,
    std::map<std::string, std::string> &originPublishMap,
    std::map<std::string, std::string> &newPublishMap)
{
    for (const auto &formDataProxy : formDataProxies) {
        std::string key = formDataProxy.key;
        std::string subscribe = formDataProxy.subscribeId.empty() ? std::to_string(formId_) : formDataProxy.subscribeId;
        auto iter = rdbSubscribeMap_.find(key);
        if (iter != rdbSubscribeMap_.end() && iter->second != subscribe) {
            originRdbMap[key] = iter->second;
            newRdbMap[key] = subscribe;
            rdbSubscribeMap_[key] = subscribe;
            continue;
        }
        iter = publishSubscribeMap_.find(key);
        if (iter != publishSubscribeMap_.end() && iter->second != subscribe) {
            originPublishMap[key] = iter->second;
            newPublishMap[key] = subscribe;
            publishSubscribeMap_[key] = subscribe;
        }
    }
}

void FormDataProxyRecord::EnableSubscribeFormData()
{
    SetRdbSubsState(rdbSubscribeMap_, true);
    SetPublishSubsState(publishSubscribeMap_, true);
}

void FormDataProxyRecord::DisableSubscribeFormData()
{
    SetRdbSubsState(rdbSubscribeMap_, false);
    SetPublishSubsState(publishSubscribeMap_, false);
}

ErrCode FormDataProxyRecord::SetRdbSubsState(std::map<std::string, std::string> &rdbSubscribeMap, bool subsState)
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
                HILOG_ERROR("set rdb state failed. %{public}s", iter.key_.c_str());
                failNum++;
            }
        }
        HILOG_DEBUG("set rdb state. subscribeId: %{public}s, failNum: %{public}d, totalNum: %{public}zu",
            std::to_string(search.subscribeId).c_str(), failNum, search.uris.size());
    }

    return ERR_OK;
}

ErrCode FormDataProxyRecord::SetPublishSubsState(std::map<std::string, std::string> &publishSubscribeMap,
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
                HILOG_ERROR("set published state failed. %{public}s", iter.key_.c_str());
                failNum++;
            }
        }
        HILOG_DEBUG("set published state. subscribeId: %{public}s, failNum: %{public}d, totalNum: %{public}zu",
            std::to_string(search.subscribeId).c_str(), failNum, search.uris.size());
    }

    return ERR_OK;
}
} // namespace AppExecFwk
} // namespace OHOS