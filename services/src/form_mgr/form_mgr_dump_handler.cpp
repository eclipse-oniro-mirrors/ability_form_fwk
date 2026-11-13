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

#include "form_mgr/form_mgr_dump_handler.h"

#include <cstdlib>
#include <unistd.h>

#include "fms_log_wrapper.h"
#include "form_mgr/form_mgr_adapter_facade.h"
#include "ipc_skeleton.h"
#include "common/util/form_util.h"
#include "common/util/form_trust_mgr.h"
#include "form_mgr_errors.h"
#include "string_ex.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AppExecFwk {

constexpr int32_t FORM_DUMP_ARGC_MAX = 2;

const std::string FORM_DUMP_HELP = "options list:\n"
    "  -h, --help                           list available commands\n"
    "  -b, --bundle-form-info               query all form infos from bundle, Un-added form info will also be dumped\n"
    "  -v, --visible                        query form visible infos from args like bundleName_userId_instIndex\n"
    "  -s, --storage                        query form storage info\n"
    "  -t, --temp                           query temporary form info\n"
    "  -n  <bundle-name>                    query form info by a bundle name\n"
    "  -i  <form-id>                        query form info by a form ID\n"
    "  -r  --running                        query running form info\n"
    "  -a  --apps-blocked                   query blocked app name list\n"
    "  -c  --cross-device                   query cross-device publish router state\n";

const std::map<std::string, FormMgrDumpHandler::DumpKey> FormMgrDumpHandler::dumpKeyMap_ = {
    {"-h", DumpKey::KEY_DUMP_HELP},
    {"--help", DumpKey::KEY_DUMP_HELP},
    {"-b", DumpKey::KEY_DUMP_STATIC},
    {"--bundle-form-info", DumpKey::KEY_DUMP_STATIC},
    {"-v", DumpKey::KEY_DUMP_VISIBLE},
    {"--visible", DumpKey::KEY_DUMP_VISIBLE},
    {"-s", DumpKey::KEY_DUMP_STORAGE},
    {"--storage", DumpKey::KEY_DUMP_STORAGE},
    {"-t", DumpKey::KEY_DUMP_TEMPORARY},
    {"--temp", DumpKey::KEY_DUMP_TEMPORARY},
    {"-n", DumpKey::KEY_DUMP_BY_BUNDLE_NAME},
    {"-i", DumpKey::KEY_DUMP_BY_FORM_ID},
    {"-r", DumpKey::KEY_DUMP_RUNNING},
    {"--running", DumpKey::KEY_DUMP_RUNNING},
    {"-a", DumpKey::KEY_DUMP_BLOCKED_APPS},
    {"--apps-blocked", DumpKey::KEY_DUMP_BLOCKED_APPS},
    {"-c", DumpKey::KEY_DUMP_CROSS_DEVICE},
    {"--cross-device", DumpKey::KEY_DUMP_CROSS_DEVICE},
};

bool FormMgrDumpHandler::CheckCallerIsSystemApp()
{
    auto callerTokenID = IPCSkeleton::GetCallingFullTokenID();
    if (!FormUtil::IsSACall() && !Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(callerTokenID)) {
        HILOG_ERROR("The caller not system-app,can't use system-api");
        return false;
    }
    return true;
}

int FormMgrDumpHandler::Dump(int fd, const std::vector<std::u16string> &args)
{
    std::string result;
    Dump(args, result);
    int ret = dprintf(fd, "%s\n", result.c_str());
    if (ret < 0 || static_cast<size_t>(ret) < result.size() + 1) {
        HILOG_ERROR("dprintf failed or short write, ret: %{public}d, expect: %{public}zu", ret, result.size() + 1);
        return ERR_APPEXECFWK_FORM_COMMON_CODE;
    }
    return ERR_OK;
}

void FormMgrDumpHandler::Dump(const std::vector<std::u16string> &args, std::string &result)
{
    if (!CheckCallerIsSystemApp()) {
        result = "error: permission denied.";
        return;
    }
    DumpKey key;
    std::string value;
    if (!ParseOption(args, key, value, result)) {
        result.append('\n' + FORM_DUMP_HELP);
        return;
    }

    switch (key) {
        case DumpKey::KEY_DUMP_HELP:
            return HiDumpHelp(value, result);
        case DumpKey::KEY_DUMP_STATIC:
            return HiDumpStaticBundleFormInfos(value, result);
        case DumpKey::KEY_DUMP_STORAGE:
            return HiDumpStorageFormInfos(value, result);
        case DumpKey::KEY_DUMP_VISIBLE:
            return HiDumpHasFormVisible(value, result);
        case DumpKey::KEY_DUMP_TEMPORARY:
            return HiDumpTemporaryFormInfos(value, result);
        case DumpKey::KEY_DUMP_BY_BUNDLE_NAME:
            return HiDumpFormInfoByBundleName(value, result);
        case DumpKey::KEY_DUMP_BY_FORM_ID:
            return HiDumpFormInfoByFormId(value, result);
        case DumpKey::KEY_DUMP_RUNNING:
            return HiDumpFormRunningFormInfos(value, result);
        case DumpKey::KEY_DUMP_BLOCKED_APPS:
            return HiDumpFormBlockedApps(value, result);
        case DumpKey::KEY_DUMP_CROSS_DEVICE:
#ifdef DISTRIBUTED_FORM_SUPPORTED
            return HiDumpCrossDevice(value, result);
#else
            result = "DISTRIBUTED_FORM_SUPPORTED not enabled";
            return;
#endif
        default:
            result = "error: unknow function.";
            return;
    }
}

int FormMgrDumpHandler::DumpStorageFormInfos(std::string &formInfos)
{
    return FormMgrAdapterFacade::GetInstance().DumpStorageFormInfos(formInfos);
}

int FormMgrDumpHandler::DumpFormInfoByBundleName(const std::string &bundleName, std::string &formInfos)
{
    return FormMgrAdapterFacade::GetInstance().DumpFormInfoByBundleName(bundleName, formInfos);
}

int FormMgrDumpHandler::DumpFormInfoByFormId(const int64_t formId, std::string &formInfo)
{
    return FormMgrAdapterFacade::GetInstance().DumpFormInfoByFormId(formId, formInfo);
}

int FormMgrDumpHandler::DumpFormTimerByFormId(const int64_t formId, std::string &isTimingService)
{
    return FormMgrAdapterFacade::GetInstance().DumpFormTimerByFormId(formId, isTimingService);
}

bool FormMgrDumpHandler::ParseOption(const std::vector<std::u16string> &args, DumpKey &key,
    std::string &value, std::string &result)
{
    if (args.empty() || static_cast<int32_t>(args.size()) > FORM_DUMP_ARGC_MAX) {
        result = "error: invalid arguments.";
        return false;
    }
    std::string argStr = Str16ToStr8(args[0]);
    auto it = dumpKeyMap_.find(argStr);
    if (it == dumpKeyMap_.end()) {
        result = "error: unknown option.";
        return false;
    }
    key = it->second;
    if (args.size() > 1) {
        value = Str16ToStr8(args[1]);
    }
    return true;
}

void FormMgrDumpHandler::HiDumpHelp([[maybe_unused]] const std::string &args, std::string &result)
{
    result = FORM_DUMP_HELP;
}

void FormMgrDumpHandler::HiDumpStorageFormInfos([[maybe_unused]] const std::string &args, std::string &result)
{
    FormMgrAdapterFacade::GetInstance().DumpStorageFormInfos(result);
}

void FormMgrDumpHandler::HiDumpTemporaryFormInfos([[maybe_unused]] const std::string &args, std::string &result)
{
    FormMgrAdapterFacade::GetInstance().DumpTemporaryFormInfos(result);
}

void FormMgrDumpHandler::HiDumpStaticBundleFormInfos([[maybe_unused]] const std::string &args, std::string &result)
{
    FormMgrAdapterFacade::GetInstance().DumpStaticBundleFormInfos(result);
}

void FormMgrDumpHandler::HiDumpHasFormVisible(const std::string &args, std::string &result)
{
    if (args.empty()) {
        result = "error: request a bundleName_userId_instIndex.";
        return;
    }
    FormMgrAdapterFacade::GetInstance().DumpHasFormVisible(args, result);
}

void FormMgrDumpHandler::HiDumpFormInfoByBundleName(const std::string &args, std::string &result)
{
    if (args.empty()) {
        result = "error: request a bundle name.";
        return;
    }
    FormMgrAdapterFacade::GetInstance().DumpFormInfoByBundleName(args, result);
}

void FormMgrDumpHandler::HiDumpFormRunningFormInfos([[maybe_unused]] const std::string &args, std::string &result)
{
    FormMgrAdapterFacade::GetInstance().DumpFormRunningFormInfos(result);
}

void FormMgrDumpHandler::HiDumpFormBlockedApps([[maybe_unused]] const std::string &args, std::string &result)
{
    FormTrustMgr::GetInstance().GetUntrustAppNameList(result);
}

void FormMgrDumpHandler::HiDumpCrossDevice([[maybe_unused]] const std::string &args, std::string &result)
{
    FormMgrAdapterFacade::GetInstance().DumpCrossDevice(result);
}

void FormMgrDumpHandler::HiDumpFormInfoByFormId(const std::string &args, std::string &result)
{
    if (args.empty()) {
        result = "error: request a form ID.";
        return;
    }
    int64_t formId = atoll(args.c_str());
    if (formId == 0) {
        result = "error: form ID is invalid.";
        return;
    }
    FormMgrAdapterFacade::GetInstance().DumpFormInfoByFormId(formId, result);
}

} // namespace AppExecFwk
} // namespace OHOS
