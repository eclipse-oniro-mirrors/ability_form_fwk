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

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormInfoMgr {
public:
    virtual ~AbstractMockFormInfoMgr() = default;
    virtual ErrCode GetFormsInfoByModule(const std::string &bundleName, const std::string &moduleName,
        std::vector<FormInfo> &formInfos, int32_t userId) = 0;
    virtual bool IsMultiAppForm(const FormInfo &formInfo) = 0;
    virtual ErrCode GetAllFormsInfo(std::vector<FormInfo> &formInfos, int32_t userId) = 0;
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
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_INFO_MGR_H
