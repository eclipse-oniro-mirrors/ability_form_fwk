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

#include "form_refresh/refresh_impl/form_force_refresh_impl.h"


namespace OHOS {
namespace AppExecFwk {

FormForceRefreshImpl::FormForceRefreshImpl() : BaseFormRefresh(RefreshConfig{}) {}
FormForceRefreshImpl::~FormForceRefreshImpl() {}

int FormForceRefreshImpl::RefreshFormRequest(RefreshData &data)
{
    return DoRefresh(data);
}
} // namespace AppExecFwk
} // namespace OHOS