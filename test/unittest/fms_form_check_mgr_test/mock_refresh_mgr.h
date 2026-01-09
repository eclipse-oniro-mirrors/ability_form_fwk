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

#ifndef OHOS_MOCK_REFRESH_MGR_H
#define OHOS_MOCK_REFRESH_MGR_H

#include <gtest/gtest.h>

#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"

namespace OHOS {
void MockIsBaseValidPass(ErrCode mockRet);
void MockAskForProviderData(ErrCode mockRet);
void MockUpdateByProviderData(ErrCode mockRet);
void MockIsSystemOverload(bool mockBool);
void MockIsFormInvisible(bool mockBool);
void MockIsScreenOff(bool mockBool);
void MockIsHealthyControl(bool mockBool);
void MockIsNeedToFresh(bool mockBool);
void MockIsAddFormFinish(bool mockBool);
void MockFormProviderUpdateForm(ErrCode mockRet);
}
#endif // OHOS_MOCK_REFRESH_MGR_H