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

#ifndef OHOS_FORM_FWK_MOCK_FORM_DB_CACHE_H
#define OHOS_FORM_FWK_MOCK_FORM_DB_CACHE_H

#include <cstdint>
#include <memory>
#include <vector>
#include "gmock/gmock.h"
#include "data_center/form_record/form_record.h"
#include "data_center/database/form_db_info.h"

namespace OHOS {
namespace AppExecFwk {
class AbstractMockFormDbCache {
public:
    virtual ~AbstractMockFormDbCache() = default;
    virtual ErrCode GetDBRecord(const int64_t formId, FormRecord &record) const = 0;
    virtual ErrCode UpdateDBRecord(const int64_t formId, const FormRecord &record) const = 0;
    virtual void GetAllFormInfo(std::vector<FormDBInfo> &formDBInfos) = 0;
};

class MockFormDbCache : public AbstractMockFormDbCache {
public:
    static std::shared_ptr<MockFormDbCache> obj;
    MockFormDbCache() = default;
    ~MockFormDbCache() override = default;
    MOCK_CONST_METHOD2(GetDBRecord, ErrCode(const int64_t formId, FormRecord &record));
    MOCK_CONST_METHOD2(UpdateDBRecord, ErrCode(const int64_t formId, const FormRecord &record));
    MOCK_METHOD1(GetAllFormInfo, void(std::vector<FormDBInfo> &formDBInfos));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_FORM_FWK_MOCK_FORM_DB_CACHE_H
