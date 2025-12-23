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

#ifndef OHOS_FORM_FWK_FORM_PARALLELIZE_FUZZ_BASE_H
#define OHOS_FORM_FWK_FORM_PARALLELIZE_FUZZ_BASE_H

#include <fuzzer/FuzzedDataProvider.h>

#include "form_mgr/form_mgr_service.h"
#include "form_constants_fuzzer.h"
#include "form_parallelize_fuzz_util.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormParallelizeFuzzBase
 * Defines form parallellize fuzz base.
 */
class FormParallelizeFuzzBase {
public:
    FormParallelizeFuzzBase(std::shared_ptr<OHOS::AppExecFwk::FormMgrService> formMgrService,
        std::shared_ptr<OHOS::AppExecFwk::FormParallelizeFuzzUtil> formParallelizeUtil)
        : formMgrService_(formMgrService), formParallelizeUtil_(formParallelizeUtil) {}

    virtual ~FormParallelizeFuzzBase() = default;

    virtual void Execute(FuzzedDataProvider &provider) = 0;

    sptr<IRemoteObject> GetMockRemoteObject()
    {
        return nullptr;
    }

protected:
     std::shared_ptr<OHOS::AppExecFwk::FormMgrService> formMgrService_;
     std::shared_ptr<OHOS::AppExecFwk::FormParallelizeFuzzUtil> formParallelizeUtil_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_PARALLELIZE_FUZZ_BASE_H