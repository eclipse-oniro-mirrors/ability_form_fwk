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

#ifndef OHOS_FORM_FWK_BASE_FORM_REFRESH_H
#define OHOS_FORM_FWK_BASE_FORM_REFRESH_H

#include "form_refresh/refresh_impl/base_form_refresh.h"
#include "form_refresh/refresh_impl/form_refresh_interface.h"
#include "form_refresh/strategy/refresh_config.h"
#include "form_refresh/check_mgr/base_checker_interface.h"

namespace OHOS {
namespace AppExecFwk {

// Control check result: continue to execute refresh
constexpr int ERR_CONTINUE_REFRESH = 0x1000;

/**
 * @class BaseFormRefresh
 * Base class for form refresh implementations using Template Method pattern.
 * Provides common refresh flow and allows subclasses to customize specific steps.
 * Check types and control checks are configured in each implementation class.
 */
class BaseFormRefresh : public IFormRefresh {
public:
    /**
     * @brief Constructor
     * @param config Refresh configuration
     */
    explicit BaseFormRefresh(RefreshConfig config);
    virtual ~BaseFormRefresh() = default;

    /**
     * @brief Template method - defines the algorithm skeleton for refresh
     * @param data Refresh data
     * @return Error code
     */
    int RefreshFormRequest(RefreshData &data) override final;

protected:
    /**
     * @brief Build check factor for validation
     * @param data Refresh data
     * @return CheckValidFactor
     */
    virtual CheckValidFactor BuildCheckFactor(RefreshData &data);

    /**
     * @brief Execute control checks
     * @param data Refresh data
     * @return ERR_OK if should skip refresh, ERR_CONTINUE_REFRESH if should continue, other error codes
     */
    virtual int DoControlCheck(RefreshData &data);

    /**
     * @brief Execute the actual refresh operation
     * @param data Refresh data
     * @return Error code
     */
    virtual int DoRefresh(RefreshData &data);

    RefreshConfig config_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_BASE_FORM_REFRESH_H