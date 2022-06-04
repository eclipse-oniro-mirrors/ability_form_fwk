/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "form_supply_callback.h"

#include <cinttypes>

#include "appexecfwk_errors.h"
#include "form_ams_helper.h"
#include "form_constants.h"
#include "form_mgr_errors.h"
#include "form_provider_mgr.h"
#include "form_util.h"
#include "hilog_wrapper.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
sptr<FormSupplyCallback> FormSupplyCallback::instance_ = nullptr;
std::mutex FormSupplyCallback::mutex_;

sptr<FormSupplyCallback> FormSupplyCallback::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        if (instance_ == nullptr) {
            instance_ = new FormSupplyCallback();
        }
    }
    return instance_;
}

/**
 * @brief Accept form binding data from form provider.
 * @param providerFormInfo Form binding data.
 * @param want input data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormSupplyCallback::OnAcquire(const FormProviderInfo &formProviderInfo, const Want &want)
{
    HILOG_INFO("%{public}s called.", __func__);
    long connectId = want.GetLongParam(Constants::FORM_CONNECT_ID, 0);
    int errCode = want.GetIntParam(Constants::PROVIDER_FLAG, ERR_OK);
    if (errCode != ERR_OK) {
        RemoveConnection(connectId);
        HILOG_ERROR("%{public}s error, errCode: %{public}d", __func__, errCode);
        return errCode;
    }

    std::string strFormId  = want.GetStringParam(Constants::PARAM_FORM_IDENTITY_KEY);
    if (strFormId.empty()) {
        HILOG_ERROR("%{public}s error, formId is empty.", __func__);
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }
    int64_t formId = std::stoll(strFormId);
    int type = want.GetIntParam(Constants::ACQUIRE_TYPE, 0);
    HILOG_DEBUG("%{public}s come: %{public}" PRId64 ", %{public}ld, %{public}d", __func__,
    formId, connectId, type);
    RemoveConnection(connectId);

    switch (type) {
        case Constants::ACQUIRE_TYPE_CREATE_FORM:
            return FormProviderMgr::GetInstance().AcquireForm(formId, formProviderInfo);
        case Constants::ACQUIRE_TYPE_RECREATE_FORM:
            return FormProviderMgr::GetInstance().UpdateForm(formId, formProviderInfo);
        default:
            HILOG_WARN("%{public}s warning, onAcquired type: %{public}d", __func__, type);
    }
    HILOG_INFO("%{public}s end.", __func__);
    return ERR_APPEXECFWK_FORM_INVALID_PARAM;
}

/**
 * @brief Accept other event.
 * @param want input data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormSupplyCallback::OnEventHandle(const Want &want)
{
    HILOG_INFO("%{public}s called.", __func__);
    long connectId = want.GetLongParam(Constants::FORM_CONNECT_ID, 0);
    std::string supplyInfo = want.GetStringParam(Constants::FORM_SUPPLY_INFO);
    HILOG_DEBUG("%{public}s come: %{public}ld, %{public}s", __func__, connectId, supplyInfo.c_str());
    RemoveConnection(connectId);
    HILOG_INFO("%{public}s end.", __func__);
    return ERR_OK;
}

/**
 * @brief Accept form state from form provider.
 * @param state Form state.
 * @param provider provider info.
 * @param wantArg The want of onAcquireFormState.
 * @param want input data.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormSupplyCallback::OnAcquireStateResult(FormState state, const std::string &provider, const Want &wantArg,
                                             const Want &want)
{
    HILOG_INFO("%{public}s called.", __func__);
    long connectId = want.GetLongParam(Constants::FORM_CONNECT_ID, 0);
    RemoveConnection(connectId);

    ErrCode errCode = FormProviderMgr::GetInstance().AcquireFormStateBack(state, provider, wantArg);
    HILOG_INFO("%{public}s end.", __func__);
    return errCode;
}

/**
 * @brief Save ability Connection for the callback.
 * @param connection ability connection.
 */
void FormSupplyCallback::AddConnection(sptr<FormAbilityConnection> connection)
{
    HILOG_INFO("%{public}s called.", __func__);
    std::lock_guard<std::mutex> lock_l(conMutex_);
    long connectKey = FormUtil::GetCurrentMillisecond();
    while (connections_.find(connectKey) != connections_.end()) {
        connectKey++;
    }
    connection->SetConnectId(connectKey);
    connections_.emplace(connectKey, connection);
    HILOG_INFO("%{public}s end.", __func__);
}

/**
 * @brief Delete ability connection after the callback come.
 * @param connectId The ability connection id generated when save.
 */
void FormSupplyCallback::RemoveConnection(long connectId)
{
    HILOG_INFO("%{public}s called.", __func__);
    sptr<FormAbilityConnection> connection = nullptr;
    {
        std::lock_guard<std::mutex> lock_l(conMutex_);
        auto conIterator = connections_.find(connectId);
        if (conIterator != connections_.end()) {
            connection = conIterator->second;
            connections_.erase(connectId);
        }
    }

    if (connection != nullptr) {
        if (CanDisConnect(connection)) {
            FormAmsHelper::GetInstance().DisConnectServiceAbility(connection);
            HILOG_INFO("%{public}s end, disconnect service ability", __func__);
        } else {
            FormAmsHelper::GetInstance().DisConnectServiceAbilityDelay(connection);
            HILOG_INFO("%{public}s end, disconnect service ability delay", __func__);
        }
    }
    HILOG_INFO("%{public}s end.", __func__);
}
/**
 * @brief check if disconnect ability or not.
 * @param connection The ability connection.
 */
bool FormSupplyCallback::CanDisConnect(sptr<FormAbilityConnection> &connection)
{
    HILOG_INFO("%{public}s called.", __func__);
    int count = 0;
    for (auto &conn : connections_) {
        if (connection->GetProviderKey() == conn.second->GetProviderKey()) {
            HILOG_INFO("%{public}s, key: %{public}s", __func__, conn.second->GetProviderKey().c_str());
            count++;
            if (count > 1) {
                HILOG_INFO("%{public}s end, true.", __func__);
                return true;
            }
        }
    }
    HILOG_INFO("%{public}s end, false.", __func__);
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
