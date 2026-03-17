/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "form_observer/net_conn_callback_impl.h"

#include "fms_log_wrapper.h"
#include "form_mgr/form_mgr_adapter.h"
#include "common/util/form_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr long FORM_DISCON_NETWORK_CHECK_TIME = 600000; // ms
constexpr int32_t CONDITION_NETWORK = 1;
}

NetConnCallbackImpl::NetConnCallbackImpl()
{
    lastNetLostTime_.store(FormUtil::GetCurrentMillisecond());
}

int32_t NetConnCallbackImpl::NetAvailable(sptr<NetManagerStandard::NetHandle> &netHandle)
{
    HILOG_INFO("OnNetworkAvailable");
    
    if (lastNetLostTime_.load() == 0) {
        HILOG_DEBUG("no need update");
        return ERR_OK;
    }

    int64_t currentTime = FormUtil::GetCurrentMillisecond();
    if ((currentTime - lastNetLostTime_.load()) >= FORM_DISCON_NETWORK_CHECK_TIME) {
        HILOG_INFO("network is available for form update");
        FormMgrAdapter::GetInstance().UpdateFormByCondition(CONDITION_NETWORK);
        lastNetLostTime_.store(0);
    }
    
    return ERR_OK;
}

int32_t NetConnCallbackImpl::NetUnavailable()
{
    HILOG_DEBUG("OnNetworkUnavailable");
    return ERR_OK;
}

int32_t NetConnCallbackImpl::NetCapabilitiesChange(sptr<NetManagerStandard::NetHandle> &netHandle,
    const sptr<NetManagerStandard::NetAllCapabilities> &netAllCap)
{
    HILOG_DEBUG("OnNetCapabilitiesChange");
    return ERR_OK;
}

int32_t NetConnCallbackImpl::NetConnectionPropertiesChange(sptr<NetManagerStandard::NetHandle> &netHandle,
    const sptr<NetManagerStandard::NetLinkInfo> &info)
{
    HILOG_DEBUG("OnNetConnectionPropertiesChange");
    return ERR_OK;
}

int32_t NetConnCallbackImpl::NetLost(sptr<NetManagerStandard::NetHandle> &netHandle)
{
    HILOG_INFO("OnNetLost");
    lastNetLostTime_.store(FormUtil::GetCurrentMillisecond());
    return ERR_OK;
}

int32_t NetConnCallbackImpl::NetBlockStatusChange(sptr<NetManagerStandard::NetHandle> &netHandle, bool blocked)
{
    HILOG_DEBUG("OnNetBlockStatusChange");
    return ERR_OK;
}
} // AppExecFwk
} // OHOS
