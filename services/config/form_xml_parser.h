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

#ifndef OHOS_FORM_FWK_FORM_XML_PARSER_H
#define OHOS_FORM_FWK_FORM_XML_PARSER_H

#include <string>
#include <map>
#include <mutex>

#include <libxml/parser.h>
#include <libxml/tree.h>

namespace OHOS::AppExecFwk {
class FormXMLParser {
public:
    FormXMLParser() = default;

    ~FormXMLParser();

    int32_t Parse();

    const std::map<std::string, int32_t>& GetConfigMap() const;

private:
    bool CheckRootNode(xmlNodePtr &node);

    bool ParseInternal(xmlNodePtr &node);

    std::mutex xmlDocumentMutex_;
    xmlDocPtr xmlDocument_ = nullptr;
    static constexpr char CONFIG_FILE[] = "/system/etc/form/form_config.xml";
    std::map<std::string, int32_t> configMap_;
};
} // namespace OHOS::AppExecFwk
#endif // OHOS_FORM_FWK_FORM_XML_PARSER_H