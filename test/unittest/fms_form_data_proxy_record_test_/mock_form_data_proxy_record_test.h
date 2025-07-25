/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MOCK_FORM_DATA_PROXY_RECORD_TEST_H
#define OHOS_MOCK_FORM_DATA_PROXY_RECORD_TEST_H

#include <gtest/gtest.h>

#include "accesstoken_kit.h"
#include "ams_mgr/form_ams_helper.h"
#include "bms_mgr/form_bms_helper.h"
#include "data_center/form_data_mgr.h"
#include "fms_log_wrapper.h"
#include "form_mgr_errors.h"
#include "common/util/form_util.h"
#include "perm_state_change_callback_customize.h"

namespace OHOS {
void MockGetFormRecord(bool mockRet);
void MockConnectServiceAbility(bool mockRet);
void MockGetCurrentAccountIdRet(int32_t userId);
void MockGetAllProxyDataInfos(bool mockRet, const AppExecFwk::ProxyData &proxyData);
void MockGetCurrentAccountIdRet(int32_t userId);
void MockRegisterPermStateChangeCallback(int32_t mockRet);
void MockUnRegisterPermStateChangeCallback(int32_t mockRet);
}
#endif // OHOS_MOCK_FORM_DATA_PROXY_RECORD_TEST_H