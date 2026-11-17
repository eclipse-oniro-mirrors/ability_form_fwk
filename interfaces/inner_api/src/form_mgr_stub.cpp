/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "form_mgr_stub.h"

#include "appexecfwk_errors.h"
#include "fms_log_wrapper.h"
#include "form_ipc_dispatch_table.h"
#include "form_mgr_errors.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {

FormMgrStub::FormMgrStub()
{}

FormMgrStub::~FormMgrStub()
{}

/**
 * @brief Serialize a deny result following the command's legacy deny carrier.
 *
 * Deny shape is part of the client-visible IPC contract frozen in the dispatch
 * table. CARRIER_STATUS is the default (and mandatory) shape for new commands;
 * the two legacy carriers only replicate how pre-refactor stub handlers reported
 * permission denials inside the reply parcel with an ERR_OK status.
 *
 * @param shape Deny carrier declared in the dispatch-table policy.
 * @param denyCode Deny code produced by the access checker.
 * @param reply Output parcel of the current request.
 * @return Returns the status channel code: ERR_OK for legacy carriers, denyCode otherwise.
 */
static ErrCode WriteDenyByShape(DenyShape shape, ErrCode denyCode, MessageParcel &reply)
{
    switch (shape) {
        case DenyShape::CARRIER_REPLY_INT32:
            if (!reply.WriteInt32(denyCode)) {
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
            return ERR_OK;
        case DenyShape::CARRIER_REPLY_BOOL:
            if (!reply.WriteBool(false)) {
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
            return ERR_OK;
        case DenyShape::CARRIER_STATUS:
        default:
            return denyCode;
    }
}
/**
 * @brief handle remote request.
 * @param code ipc code.
 * @param data input param.
 * @param reply output param.
 * @param option message option.
 * @return Returns ERR_OK on success, others on failure.
 */
int FormMgrStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HILOG_DEBUG("code= %{public}u,flags= %{public}d", code, option.GetFlags());
    std::u16string descriptor = FormMgrStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("remote not equal to localDescriptor");
        return ERR_APPEXECFWK_FORM_INVALID_PARAM;
    }

    auto &table = FormIpcDispatchTable::GetInstance();
    const HandlerEntry *entry = table.Find(code);
    if (entry == nullptr) {
        HILOG_WARN("code=%{public}u not found in dispatch table, fallback to base stub", code);
        // Unregistered code (including reserved values) keeps the base-stub behavior.
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    // Capture caller context once before any business deserialization.
    FormIpcContext context{};
    context.callingUid = IPCSkeleton::GetCallingUid();
    context.callingTokenId = IPCSkeleton::GetCallingFullTokenID();
    context.callingPid = IPCSkeleton::GetCallingPid();

    // Deny before deserialize: denied requests never read business params.
    auto checker = table.GetAccessChecker();
    ErrCode denyCode = checker->Check(entry->policy, context);
    if (denyCode != ERR_OK) {
        HILOG_ERROR("IPC deny: code=%{public}u, uid=%{public}d, deny=%{public}d",
                    code, context.callingUid, denyCode);
        return WriteDenyByShape(entry->policy.denyShape, denyCode, reply);
    }

    return entry->handler(*this, data, reply);
}

}  // namespace AppExecFwk
}  // namespace OHOS
