/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_FREE_INSTALL_OPERATOR_H
#define FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_FREE_INSTALL_OPERATOR_H

#include "common/event/form_event_handler.h"
#include "common/util/form_serial_queue.h"
#include "feature/free_install/free_install_status_callback_stub.h"

namespace OHOS {
namespace AppExecFwk {
class FreeInstallStatusCallBack;
/**
 * @class FormFreeInstallOperator
 * Free install operator class.
 */
class FormFreeInstallOperator final : public std::enable_shared_from_this<FormFreeInstallOperator> {
public:
    FormFreeInstallOperator(const std::string &formShareInfoKey,
        const std::shared_ptr<FormSerialQueue> &serialQueue);
    ~FormFreeInstallOperator();

    int32_t StartFreeInstall(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId);
    void OnInstallFinished(int32_t resultCode, const int32_t userId);

private:
    std::string formShareInfoKey_;
    sptr<FreeInstallStatusCallBack> freeInstallStatusCallBack_ = nullptr;
    std::shared_ptr<FormSerialQueue> serialQueue_ = nullptr;
};

class FreeInstallStatusCallBack final : public FreeInstallStatusCallBackStub {
public:
    FreeInstallStatusCallBack(const std::weak_ptr<FormFreeInstallOperator> &freeInstallOperator);
    virtual ~FreeInstallStatusCallBack() = default;

    /**
     * Callback triggered by free installation completion.
     *
     * @param resultCode, ERR_OK on success, others on failure.
     * @param want Indicates the ability to free install.
     * @param userId, user`s id.
     */
    void OnInstallFinished(int32_t resultCode, const Want &want, int32_t userId) override;

private:
    std::weak_ptr<FormFreeInstallOperator> formFreeInstallOperator_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_ABILITY_FORM_FWK_SERVICES_INCLUDE_FORM_FREE_INSTALL_OPERATOR_H
