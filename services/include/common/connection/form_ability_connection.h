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

#ifndef OHOS_FORM_FWK_FORM_ABILITY_CONNECTION_H
#define OHOS_FORM_FWK_FORM_ABILITY_CONNECTION_H

#include "app_mgr_interface.h"
#include "provider_connect_stub.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;
enum class ConnectState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
};

constexpr int32_t DISCONNECT_ERROR = -1;

/**
 * @class FormAbilityConnection
 * Form Ability Connection Stub. Uses template method pattern for connection handling.
 * Note: FormRenderConnection does not participate in this refactoring and keeps original impl.
 */
class FormAbilityConnection : public ProviderConnectStub {
public:
    FormAbilityConnection() = default;
    virtual ~FormAbilityConnection() = default;

    /**
     * @brief OnAbilityConnectDone, AbilityMs notify caller ability the result of connect.
     *        Template method that defines the connection workflow.
     * @param element service ability's ElementName.
     * @param remoteObject the session proxy of service ability.
     * @param resultCode ERR_OK on success, others on failure.
     */
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode) override;

    /**
     * @brief OnAbilityDisconnectDone, AbilityMs notify caller ability the result of disconnect.
     * @param element service ability's ElementName.
     * @param resultCode ERR_OK on success, others on failure.
     */
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode) override;

    /**
     * @brief onFormAppConnect, when ability connectDone.
     * @return result of onFormAppConnect.
     */
    bool onFormAppConnect();

    /**
     * @brief Report Hisys FormApp UnbindEvent.
     */
    void ReportFormAppUnbindEvent();

    /**
     * @brief Get connectId.
     * @return The ability connection id.
     */
    int32_t GetConnectId() const;

    /**
     * @brief Set connectId.
     * @param connectId The ability connection id.
     */
    void SetConnectId(int32_t connectId);

    /**
     * @brief Get the provider Key.
     * @return The provider Key.
     */
    std::string GetProviderKey() const;

    /**
     * @brief Set the Provider Key.
     * @param bundleName bundleName.
     * @param abilityName abilityName.
     * @param userId userId.
     */
    void SetProviderKey(const std::string &bundleName, const std::string &abilityName, const int32_t userId);

    /**
     * @brief Set module name.
     * @param moduleName moduleName.
     */
    void SetModuleName(const std::string &moduleName);

    /**
     * @brief Set free install true or false.
     * @param isFreeInstall Indicates the free install flag is true or false.
     */
    void SetFreeInstall(bool isFreeInstall);

    /**
     * @brief Set form ID.
     * @param formId Indicates the form ID.
     */
    void SetFormId(int64_t formId);

    /**
     * @brief Get form ID.
     */
    int64_t GetFormId() const;

    /**
     * @brief Get connection state.
     * @return Current connection state.
     */
    ConnectState GetConnectState() const;

    /**
     * @brief Get user ID.
     * @return Current user ID.
     */
    int32_t GetUserId() const;

    /**
     * @brief Create connection Want.
     * @return Want object with bundleName, abilityName and moduleName set.
     */
    Want CreateConnectWant() const;

    /**
     * @brief Clone connection object.
     * @return Cloned connection object, nullptr for base class.
     */
    virtual sptr<FormAbilityConnection> Clone() const { return nullptr; }

    /**
     * @brief Set host token.
     * @param hostToken Indicates the host token.
     */
    void SetHostToken(const sptr<IRemoteObject> hostToken);

    /**
     * @brief Get host token.
     */
    sptr<IRemoteObject> GetHostToken() const;

    /**
     * @brief Set provider token.
     * @param providerToken Indicates the provider token.
     */
    void SetProviderToken(const sptr<IRemoteObject> providerToken);

    /**
     * @brief Get provider token.
     */
    sptr<IRemoteObject> GetProviderToken() const;

    /**
     * @brief Add death recipient.
     */
    void AddHostDeathRecipient();

    /**
     * @brief Get bundle name.
     */
    std::string GetBundleName();

    /**
     * @brief Get process pid.
     */
    int32_t GetAppFormPid();

protected:
    /**
     * @brief Execute task after connection success - subclass must implement.
     *        Different subclasses call different TaskMgr:
     *        - Provider classes call FormProviderTaskMgr
     *        - FormShareConnection calls FormShareTaskMgr
     * @param want Task Want parameter.
     * @param remoteObject Remote object.
     */
    virtual void OnExecuteConnectTask(const Want &want, const sptr<IRemoteObject> &remoteObject) = 0;

    /**
     * @brief Build task Want parameter - subclass can override.
     *        Default implementation sets FORM_CONNECT_ID.
     * @return Built Want object.
     */
    virtual Want OnBuildTaskWant();

    /**
     * @brief Pre-processing after connection success - subclass optional impl.
     *        Used for pre-processing before task execution.
     */
    virtual void OnPreConnectTask() {}

    /**
     * @brief Error handling when connection fails - subclass optional impl.
     *        FormShareConnection needs to send error response.
     * @param resultCode Error code.
     * @param element Connection element.
     */
    virtual void OnConnectError(int resultCode, const AppExecFwk::ElementName &element) {}

    /**
     * @brief Whether freeInstall processing is needed.
     *        FormRefreshConnection/FormUpdateSizeConnection etc need it.
     * @return true means need freeInstall processing.
     */
    virtual bool NeedFreeInstallProcessing() const { return false; }

    /**
     * @brief Whether register to FormSupplyCallback.
     *        FormBackgroundConnection does not need register.
     * @return true means need register.
     */
    virtual bool NeedRegisterToSupplyCallback() const { return true; }

    /**
     * @brief Connection state (atomic for thread safety).
     */
    std::atomic<ConnectState> connectState_{ConnectState::DISCONNECTED};

private:
    /**
     * @brief Get app manager proxy.
     * @return App manager proxy.
     */
    sptr<OHOS::AppExecFwk::IAppMgr> GetAppMgr();

    /**
     * @brief Validate connection result.
     * @param resultCode Result code.
     * @param element Connection element.
     * @return true if valid.
     */
    bool ValidateResult(int resultCode, const AppExecFwk::ElementName &element);

    /**
     * @brief Register to FormSupplyCallback.
     */
    void RegisterToSupplyCallback();

    /**
     * @brief Process freeInstall logic.
     * @param element Connection element.
     * @param remoteObject Remote object.
     * @param resultCode Result code.
     */
    void ProcessFreeInstall(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int resultCode);

    int64_t formId_ = -1;
    std::string deviceId_ = "";
    std::string bundleName_ = "";
    std::string abilityName_ = "";
    std::string moduleName_ = "";
    bool isFreeInstall_ = false;
    int32_t userId_ = 0;
    int32_t connectId_ = 0;
    int32_t appFormPid_ = -1;
    sptr<IRemoteObject> hostToken_ = nullptr;
    sptr<IRemoteObject> providerToken_ = nullptr;

    DISALLOW_COPY_AND_MOVE(FormAbilityConnection);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_ABILITY_CONNECTION_H