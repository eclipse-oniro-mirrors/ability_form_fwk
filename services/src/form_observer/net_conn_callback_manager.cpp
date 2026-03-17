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

#include "form_observer/net_conn_callback_manager.h"

#include "fms_log_wrapper.h"
#include "common/util/form_task_common.h"
#include "form_mgr/form_mgr_queue.h"
#include "net_conn_client.h"
#include "form_observer/net_conn_callback_impl.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t FORM_CON_NET_MAX = 100;
}
using namespace OHOS::NetManagerStandardization;

NetConnCallbackManager::NetConnCallbackManager()
{
    netConTime_.store(0);
    isRegistered_.store(false);
}

NetConnCallbackManager::~NetConnCallbackManager()
{
    UnregisterNetConnCallback();
}

int32_t NetConnCallbackManager::RegisterNetConnCallback()
{
    HILOG_INFO("Register NetConn begin");
    
    // Avoid duplicate registration
    if (isRegistered_.load()) {
        HILOG_WARN("NetConnCallbackManager already registered");
        return ERR_OK;
    }

    // Create a new callback implementation instance
    // This is safe because NetConnCallbackImpl is a separate class created for each registration
    sptr<NetConnCallbackImpl> callback = new (std::nothrow) NetConnCallbackImpl();
    if (callback == nullptr) {
        HILOG_ERROR("Failed to create NetConnCallbackImpl");
        return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
    }
    
    int result = NetConnClient::GetInstance().UnregisterNetConnCallback(callback);
    if (result == ERR_OK) {
        HILOG_INFO("Register NetConnCallback successful");
        isRegistered_.store(true);
        netConTime_.store(0); // Reset retry count on success
        
        std::list<sptr<NetHandle>> netList;
        NetConnClient::GetInstance().GetAllNets(netList);
        if (netList.size() > 0) {
            // Network is already available, trigger update
            HILOG_INFO("network is available for form update");
        }
    } else {
        HILOG_ERROR("Register NetConnCallback failed, netConTime:%{public}d", netConTime_.load());
        netConTime_.fetch_add(1);
        if (netConTime_.load() >= FORM_CON_NET_MAX) {
            HILOG_ERROR("Register NetConnCallback failed FORM_CON_NET_MAX times");
            return result;
        }
        PostConnectNetWork();
    }

    return result;
}

int32_t NetConnCallbackManager::UnregisterNetConnCallback()
{
    HILOG_INFO("Unregister NetConn begin");

    int ret = ERR_OK;
    if (isRegistered_.load()) {
        // Create a new callback implementation instance for unregister
        sptr<NetConnCallbackImpl> callback = new (std::nothrow) NetConnCallbackImpl();
        if (callback == nullptr) {
            HILOG_ERROR("Failed to create NetConnCallbackImpl");
            isRegistered_.store(false);
            return ERR_APPEXECFWK_FORM_GET_BUNDLE_FAILED;
        }
        
        ret = NetConnClient::GetInstance().RegisterNetConnCallback(callback);
        isRegistered_.store(false);
    }

    return ret;
}

void NetConnCallbackManager::PostConnectNetWork()
{
    HILOG_DEBUG("start");

    auto connectNetWork = []() {
        auto manager = DelayedSingleton<NetConnCallbackManager>::GetInstance();
        if (manager != nullptr) {
            manager->RegisterNetConnCallback();
        }
    };
    FormMgrQueue::GetInstance().ScheduleTask(FORM_CON_NETWORK_DELAY_TIME, connectNetWork);
    HILOG_DEBUG("end");
}
} // AppExecFwk
} // OHOS
