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

#include "form_xml_parser.h"

#include <charconv>
#include <string>

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "form_constants.h"

namespace OHOS::AppExecFwk {
FormXMLParser::~FormXMLParser()
{
    HILOG_DEBUG("XMLParser Destroying the parser");
    std::lock_guard<std::mutex> lock(xmlDocumentMutex_);
    if (xmlDocument_ != nullptr) {
        xmlFreeDoc(xmlDocument_);
        xmlDocument_ = nullptr;
    }
}

int32_t FormXMLParser::Parse()
{
    HILOG_DEBUG("FormXMLParser Parse");
    std::lock_guard<std::mutex> lock(xmlDocumentMutex_);
    xmlDocument_ = xmlReadFile(CONFIG_FILE, nullptr, XML_PARSE_NOBLANKS);
    if (xmlDocument_ == nullptr) {
        HILOG_ERROR("null xmlDocument_");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    xmlNodePtr root = xmlDocGetRootElement(xmlDocument_);
    if (root == nullptr) {
        HILOG_ERROR("xmlDocGetRootElement failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }

    if (!CheckRootNode(root)) {
        HILOG_ERROR("CheckRootNode failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    if (!ParseInternal(root)) {
        HILOG_ERROR("ParseInternal failed");
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

bool FormXMLParser::CheckRootNode(xmlNodePtr &node)
{
    HILOG_DEBUG("CheckRootNode start");
    if (node == nullptr || node->name == nullptr ||
        xmlStrcmp(node->name, reinterpret_cast<const xmlChar*>("FORM"))) {
        HILOG_ERROR("get root element failed");
        return false;
    }
    HILOG_DEBUG("success");
    return true;
}

bool FormXMLParser::ParseInternal(xmlNodePtr &node)
{
    HILOG_DEBUG("ParseInternal start");
    xmlNodePtr curNodePtr = node->xmlChildrenNode;
    std::string quantityConfig = "quantityConfig";
    std::string nodeName = reinterpret_cast<const char*>(curNodePtr->name);
    if (nodeName != quantityConfig) {
        HILOG_ERROR("invalid node");
        return false;
    }
    for (xmlNodePtr curChildNodePtr = curNodePtr->xmlChildrenNode; curChildNodePtr != nullptr;
        curChildNodePtr = curChildNodePtr->next) {
        if (curChildNodePtr->name == nullptr || curChildNodePtr->type == XML_COMMENT_NODE) {
            HILOG_ERROR("invalid child node");
            continue;
        }
        std::string childNodeName = reinterpret_cast<const char*>(curChildNodePtr->name);
        if (childNodeName != std::string(Constants::MAX_NORMAL_FORM_SIZE)
            && childNodeName != std::string(Constants::MAX_TEMP_FORM_SIZE)
            && childNodeName != std::string(Constants::HOST_MAX_FORM_SIZE)
            && childNodeName != std::string(Constants::VISIBLE_NOTIFY_DELAY)) {
            continue;
        }
        xmlChar* content = xmlNodeGetContent(curChildNodePtr);
        if (content == nullptr) {
            HILOG_ERROR("read xml node error: nodeName:(%{public}s)", curChildNodePtr->name);
            continue;
        }
        std::string contentStr = reinterpret_cast<const char*>(content);
        int32_t contentInt = 0;
        auto result = std::from_chars(contentStr.data(), contentStr.data() + contentStr.size(), contentInt);
        if (!(result.ec == std::errc() && (result.ptr == contentStr.data() + contentStr.size()))) {
            HILOG_ERROR("convert formId failed");
            return false;
        }
        configMap_.emplace(std::make_pair(childNodeName, contentInt));
        xmlFree(content);
    }
    return true;
}

const std::map<std::string, int32_t>& FormXMLParser::GetConfigMap() const
{
    HILOG_DEBUG("GetConfigMap start");
    return configMap_;
}
} // namespace OHOS::AppExecFwk