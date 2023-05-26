/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define private public
#define protected public
#include "distributed_kv_data_manager.h"
#include "mock_store_manager.h"
#include "kvstore.h"
#include "mock_single_kv_store.h"
#undef private
#undef protected

namespace {
    bool g_mockGetSingleKvStoreRet = true;
    bool g_mockSingleKvStore = true;
}

void MockGetSingleKvStore(bool mockRet)
{
    g_mockGetSingleKvStoreRet = mockRet;
}

void MockGetKvStore(bool mockRet)
{
    g_mockSingleKvStore = mockRet;
}

namespace OHOS {
namespace DistributedKv {
Status DistributedKvDataManager::GetSingleKvStore(const Options &options, const AppId &appId, const StoreId &storeId,
    std::shared_ptr<SingleKvStore> &singleKvStore)
{
    if (g_mockSingleKvStore) {
        singleKvStore= nullptr;
    } else {
        std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr = std::make_shared<MockSingleKvStore>();
        singleKvStore = kvStorePtr;
    }
    if (!g_mockGetSingleKvStoreRet) {
        Status status = Status::INVALID_ARGUMENT;
        return status;
    }
    return SUCCESS;
}
}
} // namespace OHOS
