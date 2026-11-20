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

#ifndef OHOS_FORM_FWK_FORM_MGR_DUMP_HANDLER_H
#define OHOS_FORM_FWK_FORM_MGR_DUMP_HANDLER_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {

/**
 * @class FormMgrDumpHandler
 * Handles hidumper protocol parsing and dispatch for form manager service.
 * Service keeps 2 thin-shell Dump() overloads that delegate here.
 */
class FormMgrDumpHandler {
public:
    enum class DumpKey {
        KEY_DUMP_HELP,
        KEY_DUMP_STATIC,
        KEY_DUMP_STORAGE,
        KEY_DUMP_VISIBLE,
        KEY_DUMP_TEMPORARY,
        KEY_DUMP_BY_BUNDLE_NAME,
        KEY_DUMP_BY_FORM_ID,
        KEY_DUMP_RUNNING,
        KEY_DUMP_BLOCKED_APPS,
        KEY_DUMP_CROSS_DEVICE,
        KEY_DUMP_PROCESS_POOL,
    };

    /**
     * @brief Process dump request (fd-based, used by SystemAbility::Dump).
     */
    static int Dump(int fd, const std::vector<std::u16string> &args);

    /**
     * @brief Process dump request (args/result, used by FormMgrStub IFormMgr overrides).
     */
    static void Dump(const std::vector<std::u16string> &args, std::string &result);

    /**
     * @brief Dump storage form infos (IFormMgr override shell).
     */
    static int DumpStorageFormInfos(std::string &formInfos);

    /**
     * @brief Dump form info by bundle name (IFormMgr override shell).
     */
    static int DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos);

    /**
     * @brief Dump form info by form id (IFormMgr override shell).
     */
    static int DumpFormInfoByFormId(const int64_t formId, std::string &formInfo);

    /**
     * @brief Dump form timer by form id (IFormMgr override shell).
     */
    static int DumpFormTimerByFormId(const int64_t formId, std::string &isTimingService);

    static bool ParseOption(const std::vector<std::u16string> &args, DumpKey &key,
        std::string &value, std::string &result);

private:
    static void HiDumpHelp(const std::string &args, std::string &result);
    static void HiDumpStorageFormInfos(const std::string &args, std::string &result);
    static void HiDumpTemporaryFormInfos(const std::string &args, std::string &result);
    static void HiDumpStaticBundleFormInfos(const std::string &args, std::string &result);
    static void HiDumpHasFormVisible(const std::string &args, std::string &result);
    static void HiDumpFormInfoByBundleName(const std::string &args, std::string &result);
    static void HiDumpFormInfoByFormId(const std::string &args, std::string &result);
    static void HiDumpFormRunningFormInfos(const std::string &args, std::string &result);
    static void HiDumpFormBlockedApps(const std::string &args, std::string &result);
    static void HiDumpCrossDevice(const std::string &args, std::string &result);

    /**
     * @brief Dump the FormExtension process pool state (hidumper -p).
     */
    static void HiDumpProcessPool(const std::string &args, std::string &result);

    static bool CheckCallerIsSystemApp();
    static const std::map<std::string, DumpKey> dumpKeyMap_;
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_FORM_FWK_FORM_MGR_DUMP_HANDLER_H
