/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_FORM_FWK_MOCK_FORM_INFO_MGR_H
#define OHOS_FORM_FWK_MOCK_FORM_INFO_MGR_H

#include <cstdint>
#include <memory>
#include "gmock/gmock.h"
#include "form_info.h"
#include "form_info_filter.h"
#include "form_custom_config.h"
#include "data_center/form_record/form_record.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormInfoMgr {
public:
    virtual ~AbstractMockFormInfoMgr() = default;
    virtual ErrCode GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos, int32_t userId) = 0;
    virtual bool IsMultiAppForm(const FormInfo &formInfo) = 0;
    virtual ErrCode GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId) = 0;
    virtual ErrCode GetFormsInfoByBundle(const std::string &bundleName,
        std::vector<FormInfo> &formInfos, int32_t userId) = 0;
    virtual ErrCode GetFormsInfoByFilter(const FormInfoFilter &filter,
        std::vector<FormInfo> &formInfos, int32_t userId) = 0;
    virtual ErrCode GetAllTemplateFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId) = 0;
    virtual ErrCode GetTemplateFormsInfoByBundle(const std::string &bundleName,
        std::vector<FormInfo> &formInfos, int32_t userId) = 0;
    virtual ErrCode GetTemplateFormsInfoByModule(const std::string &bundleName,
        const std::string &moduleName, std::vector<FormInfo> &formInfos, int32_t userId) = 0;
    virtual ErrCode GetFormsInfoByModuleWithoutCheck(const std::string &bundleName,
        const std::string &moduleName, std::vector<FormInfo> &formInfos, int32_t userId) = 0;
    virtual ErrCode GetAppFormVisibleNotifyByBundleName(const std::string &bundleName,
        int32_t providerUserId, bool &appFormVisibleNotify) = 0;
    virtual void UpdateFormShowConfigs(const std::vector<FormCustomConfig> &configs) = 0;
    virtual ErrCode GetFormsInfoByRecord(const FormRecord &formRecord, FormInfo &formInfo) = 0;
};

class MockFormInfoMgr : public AbstractMockFormInfoMgr {
public:
    static std::shared_ptr<MockFormInfoMgr> obj;
    MockFormInfoMgr() = default;
    ~MockFormInfoMgr() override = default;
    MOCK_METHOD4(GetFormsInfoByModule, ErrCode(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos, int32_t userId));
    MOCK_METHOD1(IsMultiAppForm, bool(const FormInfo &formInfo));
    MOCK_METHOD2(GetAllFormsInfo, ErrCode(std::vector<FormInfo> &formInfos, int32_t userId));
    MOCK_METHOD3(GetFormsInfoByBundle, ErrCode(const std::string &bundleName,
        std::vector<FormInfo> &formInfos, int32_t userId));
    MOCK_METHOD3(GetFormsInfoByFilter, ErrCode(const FormInfoFilter &filter,
        std::vector<FormInfo> &formInfos, int32_t userId));
    MOCK_METHOD2(GetAllTemplateFormsInfo, ErrCode(std::vector<FormInfo> &formInfos, int32_t userId));
    MOCK_METHOD3(GetTemplateFormsInfoByBundle, ErrCode(const std::string &bundleName,
        std::vector<FormInfo> &formInfos, int32_t userId));
    MOCK_METHOD4(GetTemplateFormsInfoByModule, ErrCode(const std::string &bundleName,
        const std::string &moduleName, std::vector<FormInfo> &formInfos, int32_t userId));
    MOCK_METHOD4(GetFormsInfoByModuleWithoutCheck, ErrCode(const std::string &bundleName,
        const std::string &moduleName, std::vector<FormInfo> &formInfos, int32_t userId));
    MOCK_METHOD3(GetAppFormVisibleNotifyByBundleName, ErrCode(const std::string &bundleName,
        int32_t providerUserId, bool &appFormVisibleNotify));
    MOCK_METHOD1(UpdateFormShowConfigs, void(const std::vector<FormCustomConfig> &configs));
    MOCK_METHOD2(GetFormsInfoByRecord, ErrCode(const FormRecord &formRecord, FormInfo &formInfo));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_INFO_MGR_H
