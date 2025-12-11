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

#include "gmock/gmock.h"
#include <gtest/gtest.h>
#define private public
#define protected public
#include "form_ashmem.h"
#include "fms_log_wrapper.h"
#include "message_parcel.h"
#undef public
#undef protected

using namespace testing::ext;
extern void MockWriteAshmem(bool mockRet);
extern void MockReadFileDescriptor(bool mockRet);
extern void MockMapReadAndWriteAshmem(bool mockRet);
extern void MockWriteToAshmem(bool mockRet);

namespace OHOS {
namespace AppExecFwk {
const std::int32_t ERROR_OK = 0;
const std::int32_t ERROR_NUM = -1;
class FmsFormAshmemTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();

    sptr<FormAshmem> form_ashmem_;
};

void FmsFormAshmemTest::SetUpTestCase() {}

void FmsFormAshmemTest::TearDownTestCase() {}

void FmsFormAshmemTest::SetUp()
{
    form_ashmem_ = new (std::nothrow) FormAshmem();
}

void FmsFormAshmemTest::TearDown()
{
    form_ashmem_ = nullptr;
}

/*
* @tc.number: FmsFormAshmemTest_001
* @tc.name: Marshalling
* @tc.desc: Verify function Marshalling return value is false
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_001 start";
    Parcel parcel;
    int32_t fd = -1;
    int32_t size = -1;
    form_ashmem_->ashmem_ = new (std::nothrow) Ashmem(fd, size);
    EXPECT_TRUE(form_ashmem_->ashmem_ != nullptr);
    MockWriteAshmem(false);
    EXPECT_FALSE(form_ashmem_->Marshalling(parcel));
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_001 end";
}

/*
* @tc.number: FmsFormAshmemTest_002
* @tc.name: ReadFromParcel
* @tc.desc: Verify function ReadFromParcel return value is false
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_002 start";
    Parcel parcel;
    MockReadFileDescriptor(false);
    EXPECT_FALSE(form_ashmem_->ReadFromParcel(parcel));
    EXPECT_TRUE(form_ashmem_->ashmem_ == nullptr);
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_002 end";
}

/*
* @tc.number: FmsFormAshmemTest_003
* @tc.name: Unmarshalling
* @tc.desc: Verify function Unmarshalling return value is nullptr
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_003 start";
    Parcel parcel;
    MockWriteAshmem(false);
    form_ashmem_->ashmem_ = nullptr;
    EXPECT_TRUE(form_ashmem_->Unmarshalling(parcel) == nullptr);
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_003 end";
}

/*
* @tc.number: FmsFormAshmemTest_004
* @tc.name: WriteToAshmem
* @tc.desc: Verify function WriteToAshmem return value is false
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_004 start";
    std::string name = "abc";
    char data[] = "ab";
    int32_t size = -1;
    form_ashmem_->ashmem_ = nullptr;
    form_ashmem_->WriteToAshmem(name, data, size);
    EXPECT_FALSE(form_ashmem_->WriteToAshmem(name, data, size));
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_004 end";
}

/*
* @tc.number: FmsFormAshmemTest_005
* @tc.name: GetAshmemSize
* @tc.desc: Verify function GetAshmemSize return value is ERROR_NUM
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_005 start";
    int32_t fd = -1;
    int32_t size = -1;
    form_ashmem_->ashmem_ = new (std::nothrow) Ashmem(fd, size);
    form_ashmem_->GetAshmemSize();
    EXPECT_TRUE(form_ashmem_->ashmem_ != nullptr);
    EXPECT_EQ(form_ashmem_->GetAshmemSize(), ERROR_NUM);
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_005 end";
}

/*
* @tc.number: FmsFormAshmemTest_006
* @tc.name: GetAshmemFd
* @tc.desc: Verify function GetAshmemFd return value is ERROR_NUM
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_006 start";
    int32_t fd = -1;
    int32_t size = -1;
    form_ashmem_->ashmem_ = new (std::nothrow) Ashmem(fd, size);
    form_ashmem_->GetAshmemFd();
    EXPECT_TRUE(form_ashmem_->ashmem_ != nullptr);
    EXPECT_EQ(form_ashmem_->GetAshmemFd(), ERROR_NUM);
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_006 end";
}

/*
* @tc.number: FmsFormAshmemTest_007
* @tc.name: Marshalling
* @tc.desc: Verify function Marshalling return value is true
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_007 start";
    Parcel parcel;
    MockWriteAshmem(true);
    EXPECT_TRUE(form_ashmem_->Marshalling(parcel));
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_007 end";
}

/*
* @tc.number: FmsFormAshmemTest_008
* @tc.name: ReadFromParcel
* @tc.desc: Verify function ReadFromParcel return value is true
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_008 start";
    Parcel parcel;
    MockReadFileDescriptor(true);
    EXPECT_TRUE(form_ashmem_->ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_008 end";
}

/*
* @tc.number: FmsFormAshmemTest_009
* @tc.name: GetAshmemSize
* @tc.desc: Verify function GetAshmemSize return value is ERROR_OK
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_009 start";
    form_ashmem_->ashmem_ = nullptr;
    EXPECT_EQ(form_ashmem_->GetAshmemSize(), ERROR_OK);
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_009 end";
}

/*
* @tc.number: FmsFormAshmemTest_010
* @tc.name: GetAshmemFd
* @tc.desc: Verify function GetAshmemFd return value is ERROR_NUM
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_010 start";
    form_ashmem_->ashmem_ = nullptr;
    EXPECT_EQ(form_ashmem_->GetAshmemFd(), ERROR_NUM);
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_010 end";
}

/*
* @tc.number: FmsFormAshmemTest_011
* @tc.name: WriteToAshmem
* @tc.desc: Verify function WriteToAshmem return value is false
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_011 start";
    std::string name = "abc";
    char data[] = "ab";
    int32_t size = 1;
    int32_t fd = -1;
    form_ashmem_->ashmem_ = new (std::nothrow) Ashmem(fd, size);
    MockMapReadAndWriteAshmem(false);
    form_ashmem_->WriteToAshmem(name, data, size);
    EXPECT_TRUE(form_ashmem_->ashmem_ != nullptr);
    EXPECT_FALSE(form_ashmem_->WriteToAshmem(name, data, size));
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_011 end";
}

/*
* @tc.number: FmsFormAshmemTest_012
* @tc.name: WriteToAshmem
* @tc.desc: Verify function WriteToAshmem return value is false
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_012 start";
    std::string name = "abc";
    char data[] = "ab";
    int32_t size = 1;
    int32_t fd = -1;
    form_ashmem_->ashmem_ = new (std::nothrow) Ashmem(fd, size);
    MockMapReadAndWriteAshmem(true);
    MockWriteToAshmem(false);
    form_ashmem_->WriteToAshmem(name, data, size);
    EXPECT_FALSE(form_ashmem_->WriteToAshmem(name, data, size));
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_012 end";
}

/*
* @tc.number: FmsFormAshmemTest_013
* @tc.name: WriteToAshmem
* @tc.desc: Verify function WriteToAshmem return value is true
*/
HWTEST_F(FmsFormAshmemTest, FmsFormAshmemTest_013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_013 start";
    std::string name = "abc";
    char data[] = "ab";
    int32_t size = 1;
    int32_t fd = -1;
    form_ashmem_->ashmem_ = new (std::nothrow) Ashmem(fd, size);
    MockMapReadAndWriteAshmem(true);
    MockWriteToAshmem(true);
    form_ashmem_->WriteToAshmem(name, data, size);
    EXPECT_TRUE(form_ashmem_->WriteToAshmem(name, data, size));
    GTEST_LOG_(INFO) << "FmsFormAshmemTest_013 end";
}
}  // namespace AppExecFwk
}  // namespace OHOS