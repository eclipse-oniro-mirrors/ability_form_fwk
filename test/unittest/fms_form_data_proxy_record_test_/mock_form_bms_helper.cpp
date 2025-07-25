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

#include "mock_form_data_proxy_record_test.h"

using namespace OHOS::AppExecFwk;

namespace {
    bool g_mockGetAllProxyDataInfos = false;
    ProxyData g_mockProxyData;
}

namespace OHOS {
void MockGetAllProxyDataInfos(bool mockRet, const ProxyData &proxyData)
{
    g_mockGetAllProxyDataInfos = mockRet;
    g_mockProxyData = proxyData;
}
} // namespace OHOS


namespace OHOS {
namespace AppExecFwk {
FormBmsHelper::FormBmsHelper()
{}

FormBmsHelper::~FormBmsHelper()
{}

ErrCode FormBmsHelper::GetAllProxyDataInfos(int32_t userId, std::vector<ProxyData> &proxyData)
{
    if (g_mockGetAllProxyDataInfos) {
        proxyData.push_back(g_mockProxyData);
        return ERR_OK;
    }
    return ERR_APPEXECFWK_FORM_COMMON_CODE;
}
} // namespace AppExecFwk
} // namespace OHOS
