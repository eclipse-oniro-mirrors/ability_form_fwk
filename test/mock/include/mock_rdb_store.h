/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#ifndef MOCK_RDB_STORE_H
#define MOCK_RDB_STORE_H

#include <string>

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::NativeRdb;

class MockRdbStore : public RdbStore {
public:
    MockRdbStore(const RdbStoreConfig& config) {}
    MockRdbStore(const RdbStoreConfig& config, int& errCode) {}
    virtual ~MockRdbStore() {}

    MOCK_METHOD3(Insert, int(int64_t&, const std::string&, const ValuesBucket&));
    MOCK_METHOD3(BatchInsert, int(int64_t&, const std::string&, const std::vector<ValuesBucket>&));
    MOCK_METHOD3(Replace, int(int64_t&, const std::string&, const ValuesBucket&));
    MOCK_METHOD4(InsertWithConflictResolution, int(int64_t&, const std::string&, const ValuesBucket&,
                 ConflictResolution));
    MOCK_METHOD5(Update, int(int&, const std::string&, const ValuesBucket&,
                 const std::string&, const std::vector<std::string>&));
    MOCK_METHOD5(Update, int(int&, const std::string&, const ValuesBucket&,
                 const std::string&, const std::vector<ValueObject>&));
    MOCK_METHOD6(UpdateWithConflictResolution, int(int&, const std::string&, const ValuesBucket&,
                 const std::string&, const std::vector<std::string>&, ConflictResolution));
    MOCK_METHOD6(UpdateWithConflictResolution, int(int&, const std::string&, const ValuesBucket&,
                 const std::string&, const std::vector<ValueObject>&, ConflictResolution));
    MOCK_METHOD4(Delete, int(int&, const std::string&, const std::string&, const std::vector<std::string>&));
    MOCK_METHOD4(Delete, int(int&, const std::string&, const std::string&, const std::vector<ValueObject>&));
    MOCK_METHOD11(Query, std::shared_ptr<AbsSharedResultSet>(int&, bool, const std::string&,
                  const std::vector<std::string>&, const std::string&, const std::vector<ValueObject>&,
                  const std::string&, const std::string&, const std::string&, const int&, const int&));
    MOCK_METHOD2(QuerySql, std::shared_ptr<AbsSharedResultSet>(const std::string&, const std::vector<std::string>&));
    MOCK_METHOD2(QuerySql, std::shared_ptr<AbsSharedResultSet>(const std::string&, const std::vector<ValueObject>&));
    MOCK_METHOD2(QueryByStep, std::shared_ptr<ResultSet>(const std::string&, const std::vector<std::string>&));
    MOCK_METHOD3(QueryByStep, std::shared_ptr<ResultSet>(const std::string&, const std::vector<ValueObject>&, bool));
    MOCK_METHOD2(ExecuteSql, int(const std::string&, const std::vector<ValueObject>&));
    MOCK_METHOD3(ExecuteAndGetLong, int(int64_t&, const std::string&, const std::vector<ValueObject>&));
    MOCK_METHOD3(ExecuteAndGetString, int(std::string&, const std::string&, const std::vector<ValueObject>&));
    MOCK_METHOD3(ExecuteForLastInsertedRowId, int(int64_t&, const std::string&, const std::vector<ValueObject>&));
    MOCK_METHOD3(ExecuteForChangedRowCount, int(int64_t&, const std::string&, const std::vector<ValueObject>&));
    MOCK_METHOD2(Backup, int(const std::string&, const std::vector<uint8_t>&));
    MOCK_METHOD2(Count, int(int64_t&, const AbsRdbPredicates&));
    MOCK_METHOD2(Query, std::shared_ptr<AbsSharedResultSet>(const AbsRdbPredicates&, const std::vector<std::string>&));
    MOCK_METHOD3(QueryByStep, std::shared_ptr<ResultSet>(const AbsRdbPredicates&, const std::vector<std::string>&,
                 bool));
    MOCK_METHOD4(RemoteQuery, std::shared_ptr<ResultSet>(const std::string&, const AbsRdbPredicates&,
                 const std::vector<std::string>&, int&));
    MOCK_METHOD3(Update, int(int&, const ValuesBucket&, const AbsRdbPredicates&));
    MOCK_METHOD2(Delete, int(int&, const AbsRdbPredicates&));
    MOCK_METHOD1(GetVersion, int(int&));
    MOCK_METHOD1(SetVersion, int(int));
    MOCK_METHOD0(BeginTransaction, int());
    MOCK_METHOD0(RollBack, int());
    MOCK_METHOD0(Commit, int());
    MOCK_METHOD0(IsInTransaction, bool());
    MOCK_METHOD0(GetPath, std::string());
    MOCK_METHOD0(IsHoldingConnection, bool());
    MOCK_CONST_METHOD0(IsOpen, bool());
    MOCK_CONST_METHOD0(IsReadOnly, bool());
    MOCK_CONST_METHOD0(IsMemoryRdb, bool());
    MOCK_METHOD2(Restore, int(const std::string&, const std::vector<uint8_t>&));
    MOCK_METHOD3(SetDistributedTables, int(const std::vector<std::string>&, int32_t,
                 const DistributedRdb::DistributedConfig&));
    MOCK_METHOD3(ObtainDistributedTableName, std::string(const std::string&, const std::string&, int&));
    MOCK_METHOD3(Sync, int(const SyncOption&, const AbsRdbPredicates&, const AsyncBrief&));
    MOCK_METHOD3(Sync, int(const SyncOption&, const std::vector<std::string>&, const AsyncDetail&));
    MOCK_METHOD3(Sync, int(const SyncOption&, const AbsRdbPredicates&, const AsyncDetail&));
    MOCK_METHOD2(Subscribe, int(const SubscribeOption&, RdbStoreObserver*));
    MOCK_METHOD2(UnSubscribe, int(const SubscribeOption&, RdbStoreObserver*));
    MOCK_METHOD1(RegisterAutoSyncCallback, int(std::shared_ptr<DetailProgressObserver>));
    MOCK_METHOD1(UnregisterAutoSyncCallback, int(std::shared_ptr<DetailProgressObserver>));
    MOCK_METHOD1(Notify, int(const std::string&));
    MOCK_CONST_METHOD0(IsSlaveDiffFromMaster, bool());
    MOCK_METHOD3(GetModifyTime, ModifyTime(const std::string&, const std::string&, std::vector<PRIKey>&));
    MOCK_METHOD2(CleanDirtyData, int(const std::string&, uint64_t));
    MOCK_METHOD1(GetRebuilt, int(RebuiltType&));
};
}
}
#endif  // MOCK_RDB_STORE_H
