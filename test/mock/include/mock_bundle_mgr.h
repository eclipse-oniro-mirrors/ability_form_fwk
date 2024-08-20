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

#ifndef MOCK_BUNDLE_MGR_H
#define MOCK_BUNDLE_MGR_H
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "iremote_stub.h"
#include "bundle_mgr_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class MockBundleMgrStub : public IRemoteStub<IBundleMgr> {
public:
    MockBundleMgrStub() {};
    virtual ~MockBundleMgrStub() = default;
    MOCK_METHOD4(GetApplicationInfoV9, ErrCode(const std::string &, int32_t, int32_t, ApplicationInfo &));
    MOCK_METHOD4(GetBundleInfo, bool(const std::string &, int32_t, BundleInfo &, int32_t));
    MOCK_METHOD4(GetBundleInfoV9,
        ErrCode(const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId));
    int OnRemoteRequest(
        uint32_t code, MessageParcel& data, MessageParcel& reply, MessageOption& option) override
    {
        return 0;
    };
};

class MockBundleMgrProxy : public BundleMgrProxy {
public:
    explicit MockBundleMgrProxy(const sptr<IRemoteObject> &impl) : BundleMgrProxy(impl) {};
    virtual ~MockBundleMgrProxy() = default;

    MOCK_METHOD1(CheckIsSystemAppByUid, bool(const int));
    MOCK_METHOD4(GetApplicationInfoV9, ErrCode(const std::string &, int32_t, int32_t, ApplicationInfo &));
    MOCK_METHOD4(GetBundleInfo, bool(const std::string &, const BundleFlag, BundleInfo &, int32_t));
    MOCK_METHOD4(GetBundleInfoV9,
        ErrCode(const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId));
    MOCK_METHOD2(GetBundleNameForUid, bool(const int, std::string &));
    MOCK_METHOD2(GetNameForUid, int32_t(const int, std::string &));
    MOCK_METHOD2(GetAdditionalInfo, ErrCode(const std::string &, std::string &));
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // MOCK_BUNDLE_MGR_H
