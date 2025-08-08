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

#ifndef OHOS_FORM_FWK_FORM_DUMP_MGR_H
#define OHOS_FORM_FWK_FORM_DUMP_MGR_H

#include <unordered_map>
#include <singleton.h>

#include "form_constants.h"
#include "data_center/database/form_db_info.h"
#include "form_host/form_host_record.h"
#include "data_center/form_info/form_info_mgr.h"
#include "running_form_info.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class FormDumpMgr
 * Form dump mgr.
 */
class FormDumpMgr final : public DelayedRefSingleton<FormDumpMgr> {
    DECLARE_DELAYED_REF_SINGLETON(FormDumpMgr)
public:
    DISALLOW_COPY_AND_MOVE(FormDumpMgr);

    /**
     * @brief Dump all of form storage infos.
     * @param storageInfos Form storage infos
     * @param formInfos Form storage dump info.
     */
    void DumpStorageFormInfos(const std::vector<FormDBInfo> &storageInfos, std::string &formInfos) const;
    /**
     * @brief Dump all of temporary form infos.
     * @param formRecordInfos Form record infos.
     * @param formInfos Form dump infos.
     */
    void DumpTemporaryFormInfos(const std::vector<FormRecord> &formRecordInfos, std::string &formInfos) const;
    /**
     * @brief Dump form infos of all bundles, this is static info.
     * @param bundleFormInfos Form infos from bundle.
     * @param formInfos Form dump infos.
     */
    void DumpStaticBundleFormInfos(const std::vector<FormInfo> &bundleFormInfos, std::string &formInfos) const;

    /**
     * @brief Dump has form visible with bundleInfo.
     * @param tokenId *Unique identifaication of application.
     * @param bundleName Bundle name.
     * @param userId User ID.
     * @param instIndex Index of application instance.
     * @param formInfos Form dump infos.
     */
    void DumpHasFormVisible(
        const uint32_t tokenId,
        const std::string &bundleName,
        const int32_t userId,
        const int32_t instIndex,
        std::string &formInfos) const;

    /**
     * @brief Dump form infos.
     * @param formRecordInfos Form record infos.
     * @param formInfos Form dump infos.
     */
    void DumpFormInfos(const std::vector<FormRecord> &formRecordInfos, std::string &formInfos) const;
    /**
     * @brief Dump form infos.
     * @param formRecordInfo Form Host record info.
     * @param formInfo Form dump info.
     */
    void DumpFormHostInfo(const FormHostRecord &formHostRecord, std::string &formInfo) const;
    /**
     * @brief Dump form infos.
     * @param formRecordInfo Form record info.
     * @param formInfo Form dump info.
     */
    void DumpFormInfo(const FormRecord &formRecordInfo, std::string &formInfo) const;

    /**
     * @brief Dump form subscribe info.
     * @param subscribedKeys Form subscribe key info.
     * @param count Form received data count
     * @param formInfo Form dump info.
     */
    void DumpFormSubscribeInfo(
        const std::vector<std::string> &subscribedKeys, const int64_t &count, std::string &formInfo) const;

    /**
     * @brief Dump running form information.
     * @param runningFormInfos All the running form information
     * @param infosResult The dump info of all the running form info.
     */
    void DumpRunningFormInfos(const std::vector<RunningFormInfo> &runningFormInfos,
        std::string &infosResult) const;

    void AppendLiveFormStatus(const std::string &formId,
        const std::unordered_map<std::string, std::string> &liveFormStatusMap, std::string &formInfo) const;
private:
    void AppendBundleFormInfo(const FormRecord &formRecordInfo, std::string &formInfo) const;
    void AppendFormStatus(const int64_t formId, std::string &formInfo) const;
    void AppendRunningFormInfos(const std::string &formHostBundleName,
        const std::vector<RunningFormInfo> &runningFormInfos,
        std::string &infosResult) const;
    void AppendFormLocation(Constants::FormLocation formLocation, std::string &infosResult) const;
    void AppendBundleType(const BundleType formBundleType, std::string &formInfo) const;
    void AppendFormRefreshControlPoints(
        std::string &formInfo, const bool enableForm, const std::string &bundleName, const int64_t formId) const;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_DUMP_MGR_H
