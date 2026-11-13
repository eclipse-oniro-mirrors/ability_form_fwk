/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_FORM_FWK_FORM_CUST_CONFIG_MGR_H
#define OHOS_FORM_FWK_FORM_CUST_CONFIG_MGR_H

#include <singleton.h>
#include <string>

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormCustConfigMgr
 * form cust config mananger.
 */
class FormCustConfigMgr final : public DelayedRefSingleton<FormCustConfigMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormCustConfigMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormCustConfigMgr);

    void InitCustConfigParameters();

    /**
     * @brief Get the FormExtension process pool max threshold.
     *        Read once at construction via system parameter
     *        persist.sys.fms.form_extension.process_pool.threshold (C++ API
     *        OHOS::system::GetIntParameter), sanitized by SanitizePoolThreshold:
     *        negative -> default 20; greater than 50 -> clamp 50; 0 keeps 0
     *        (pool gating disabled). Takes effect after FMS restart.
     * @return Sanitized threshold.
     */
    size_t GetFormExtensionProcessPoolMax() const;

    /**
     * @brief Sanitize the raw pool threshold.
     * @param rawThreshold Raw value from system parameter.
     * @return negative -> 20; (50, +inf) -> 50; otherwise raw value.
     */
    static size_t SanitizePoolThreshold(int32_t rawThreshold);

    bool IsSupportSceneAnimation();

    bool IsSupportFunInteraction();

    bool IsSupportGameCard();
private:
    std::string liveFormSupportType = "";
    std::string gameCardSupportEnable = "";
    size_t processPoolThreshold_ = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_CUST_CONFIG_MGR_H