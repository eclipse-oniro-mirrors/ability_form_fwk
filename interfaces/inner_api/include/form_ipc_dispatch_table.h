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

#ifndef OHOS_FORM_FWK_FORM_IPC_DISPATCH_TABLE_H
#define OHOS_FORM_FWK_FORM_IPC_DISPATCH_TABLE_H

#include <cstdint>
#include <memory>

#include "form_mgr_interface.h"
#include "form_permission_policy.h"
#include "message_parcel.h"

namespace OHOS {
namespace AppExecFwk {

class IStubAccessChecker;

// Handlers are free functions over IFormMgr;
// form_mgr_interface.h also defines the Message code domain.

/**
 * @brief Free function pointer type for IPC handlers.
 */
using IpcHandlerFunc = int32_t (*)(IFormMgr &, MessageParcel &, MessageParcel &);

/**
 * @brief One entry in the IPC dispatch table.
 * The code field keeps the Message domain type; Find converts to uint32_t at the search boundary.
 */
struct HandlerEntry {
    IFormMgr::Message code;
    IpcHandlerFunc handler;
    FormPermissionPolicy policy;
};

/**
 * @class FormIpcDispatchTable
 * @brief Meyers singleton mapping IPC codes to handler and policy.
 */
class FormIpcDispatchTable {
public:
    /**
     * @brief Get the singleton instance.
     * @return Reference to the singleton.
     */
    static FormIpcDispatchTable &GetInstance();

    /**
     * @brief Find the entry for an IPC message code.
     * @param code IPC message code.
     * @return Returns the matching entry, or nullptr if the code is not registered.
     */
    const HandlerEntry *Find(uint32_t code) const;

    /**
     * @brief Get the source entry table for unit-test iteration.
     * @return Pointer to the first source entry.
     */
    const HandlerEntry *GetEntries() const;

    /**
     * @brief Get the number of source entries.
     * @return Number of entries in the source table.
     */
    size_t GetEntryCount() const;

    /**
     * @brief Install an access checker.
     * @param checker The checker to install.
     * @note Threading contract: Set/Get are not synchronized. The owner must install the real
     *       checker once during service startup, before the SA is published, so that IPC
     *       worker threads only read the checker after publication.
     */
    void SetAccessChecker(std::shared_ptr<IStubAccessChecker> checker);

    /**
     * @brief Get the current access checker.
     * @return The installed checker.
     */
    std::shared_ptr<IStubAccessChecker> GetAccessChecker() const;

private:
    FormIpcDispatchTable();
    ~FormIpcDispatchTable() = default;
    FormIpcDispatchTable(const FormIpcDispatchTable &) = delete;
    FormIpcDispatchTable &operator=(const FormIpcDispatchTable &) = delete;
    FormIpcDispatchTable(FormIpcDispatchTable &&) = delete;
    FormIpcDispatchTable &operator=(FormIpcDispatchTable &&) = delete;

    std::shared_ptr<IStubAccessChecker> checker_;
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_FORM_FWK_FORM_IPC_DISPATCH_TABLE_H
