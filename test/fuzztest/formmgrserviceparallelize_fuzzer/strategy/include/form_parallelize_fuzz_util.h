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

#ifndef OHOS_FORM_FWK_FORM_PARALLELIZE_FUZZ_UTIL_H
#define OHOS_FORM_FWK_FORM_PARALLELIZE_FUZZ_UTIL_H

#include <fuzzer/FuzzedDataProvider.h>

#include "token_setproc.h"
#include "form_js_info.h"
#include "running_form_info.h"
#include "form_provider_data.h"
#include "form_info_filter.h"
#include "form_state_info.h"
#include "form_share_info.h"
#include "form_lock_info.h"
#include "form_major_info.h"
#include "form_instances_filter.h"
#include "template_form_detail_info.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormParallelizeFuzzUtil
 * Defines form parallellize fuzz util.
 */
class FormParallelizeFuzzUtil {
public:
    FormParallelizeFuzzUtil() = default;

    ~FormParallelizeFuzzUtil() = default;

    /**
     * @brief Mock remote object.
     */
    sptr<IRemoteObject> GetMockRemoteObject();

    /**
     * @brief Fill formJsInfo.
     * @param provider data provider.
     * @param formInfo form info.
     */
    void FillFormJsInfo(FuzzedDataProvider &provider, FormJsInfo &formInfo);

    /**
     * @brief Fill RunningFormInfo.
     * @param provider data provider.
     * @param formInfo running form info.
     */
    void FillRunningFormInfo(FuzzedDataProvider &provider, RunningFormInfo &formInfo);

    /**
     * @brief Fill FormProviderData.
     * @param provider data provider.
     * @param data form provider data.
     */
    void FillFormProviderData(FuzzedDataProvider &provider, FormProviderData &data);

    /**
     * @brief Fill FormInfoFilter.
     * @param provider data provider.
     * @param filter form info filter.
     */
    void FillFormInfoFilter(FuzzedDataProvider &provider, FormInfoFilter &filter);

    /**
     * @brief Fill FormStateInfo.
     * @param provider data provider.
     * @param stateInfo form state info.
     */
    void FillFormStateInfo(FuzzedDataProvider &provider, FormStateInfo &stateInfo);

    /**
     * @brief Fill FormShareInfo.
     * @param provider data provider.
     * @param info form share info.
     */
    void FillFormShareInfo(FuzzedDataProvider &provider, FormShareInfo &info);

    /**
     * @brief Fill FormLockInfo.
     * @param provider data provider.
     * @param info form lock info.
     */
    void FillFormLockInfo(FuzzedDataProvider &provider, FormLockInfo &info);

    /**
     * @brief Fill FormMajorInfo.
     * @param provider data provider.
     * @param info form major info.
     */
    void FillFormMajorInfo(FuzzedDataProvider &provider, FormMajorInfo &info);

    /**
     * @brief Fill FormInstancesFilter.
     * @param provider data provider.
     * @param info form instance filter.
     */
    void FillFormInstancesFilter(FuzzedDataProvider &provider, FormInstancesFilter &filter);

    /**
     * @brief Fill Rect.
     * @param provider data provider.
     * @param info form rect filter.
     */
    void FillRectInfo(FuzzedDataProvider &provider, Rect& rect);

    /**
     * @brief Fill OverflowInfo.
     * @param provider data provider.
     * @param info form overflow info.
     */
    void FillOverflowInfo(FuzzedDataProvider &provider, OverflowInfo& overflowInfo);

    /**
     * @brief Fill TemplateFormDetailInfo.
     * @param provider data provider.
     * @param templateFormDetailInfo form templateFormDetailInfo info.
     */
    void FillTemplateFormDetailInfo(FuzzedDataProvider &provider, TemplateFormDetailInfo &templateFormDetailInfo);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_PARALLELIZE_FUZZ_UTIL_H