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

#include <gtest/gtest.h>
#include <chrono>
#include <thread>

#include "util/form_time_util.h"
#include "fms_log_wrapper.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk::Common;

namespace {
constexpr int32_t SLEEP_INTERVAL_MS = 50;
constexpr int32_t CALL_COUNT = 5;
constexpr int64_t TIME_TOLERANCE_MS = 20;
constexpr int64_t EXPECTED_TOTAL_SLEEP_MS = (CALL_COUNT - 1) * SLEEP_INTERVAL_MS;
constexpr int64_t TOTAL_TIME_TOLERANCE_MS = 50;

class FmsFormTimeUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FmsFormTimeUtilTest::SetUpTestCase()
{}

void FmsFormTimeUtilTest::TearDownTestCase()
{}

void FmsFormTimeUtilTest::SetUp()
{}

void FmsFormTimeUtilTest::TearDown()
{}

/**
 * @tc.name: FmsFormTimeUtilTest_GetBootTimeMs_001
 * @tc.desc: Verify GetBootTimeMs returns positive value
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormTimeUtilTest, FmsFormTimeUtilTest_GetBootTimeMs_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetBootTimeMs_001 start";
    int64_t bootTime = FormTimeUtil::GetBootTimeMs();
    EXPECT_GT(bootTime, 0);
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetBootTimeMs_001 end";
}

/**
 * @tc.name: FmsFormTimeUtilTest_GetBootTimeMs_002
 * @tc.desc: Verify GetBootTimeMs increases over time with reasonable time difference
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormTimeUtilTest, FmsFormTimeUtilTest_GetBootTimeMs_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetBootTimeMs_002 start";
    auto startSteady = std::chrono::steady_clock::now();
    int64_t time1 = FormTimeUtil::GetBootTimeMs();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL_MS));
    int64_t time2 = FormTimeUtil::GetBootTimeMs();
    auto endSteady = std::chrono::steady_clock::now();

    EXPECT_GE(time2, time1) << "Time should be non-decreasing";

    int64_t timeDiff = time2 - time1;
    auto actualSleepMs = std::chrono::duration_cast<std::chrono::milliseconds>(endSteady - startSteady).count();

    int64_t minExpected = actualSleepMs - TIME_TOLERANCE_MS;
    int64_t maxExpected = actualSleepMs + TIME_TOLERANCE_MS;
    if (minExpected < 0) {
        minExpected = 0;
    }

    EXPECT_GE(timeDiff, minExpected) << "Time diff " << timeDiff << "ms should be >= actual sleep " <<
        actualSleepMs << "ms minus tolerance " << TIME_TOLERANCE_MS << "ms";
    EXPECT_LE(timeDiff, maxExpected) << "Time diff " << timeDiff << "ms should be <= actual sleep " <<
        actualSleepMs << "ms plus tolerance " << TIME_TOLERANCE_MS << "ms";
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetBootTimeMs_002 end";
}

/**
 * @tc.name: FmsFormTimeUtilTest_GetNowMillisecond_001
 * @tc.desc: Verify GetNowMillisecond returns positive value
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormTimeUtilTest, FmsFormTimeUtilTest_GetNowMillisecond_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetNowMillisecond_001 start";
    int64_t currentTime = FormTimeUtil::GetNowMillisecond();
    EXPECT_GT(currentTime, 0);
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetNowMillisecond_001 end";
}

/**
 * @tc.name: FmsFormTimeUtilTest_GetNowMillisecond_002
 * @tc.desc: Verify GetNowMillisecond increases over time with reasonable time difference
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormTimeUtilTest, FmsFormTimeUtilTest_GetNowMillisecond_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetNowMillisecond_002 start";
    auto startSteady = std::chrono::steady_clock::now();
    int64_t time1 = FormTimeUtil::GetNowMillisecond();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL_MS));
    int64_t time2 = FormTimeUtil::GetNowMillisecond();
    auto endSteady = std::chrono::steady_clock::now();

    EXPECT_GE(time2, time1) << "Time should be non-decreasing";

    int64_t timeDiff = time2 - time1;
    auto actualSleepMs = std::chrono::duration_cast<std::chrono::milliseconds>(endSteady - startSteady).count();

    int64_t minExpected = actualSleepMs - TIME_TOLERANCE_MS;
    int64_t maxExpected = actualSleepMs + TIME_TOLERANCE_MS;
    if (minExpected < 0) {
        minExpected = 0;
    }

    EXPECT_GE(timeDiff, minExpected) << "Time diff " << timeDiff << "ms should be >= actual sleep " <<
        actualSleepMs << "ms minus tolerance " << TIME_TOLERANCE_MS << "ms";
    EXPECT_LE(timeDiff, maxExpected) << "Time diff " << timeDiff << "ms should be <= actual sleep " <<
        actualSleepMs << "ms plus tolerance " << TIME_TOLERANCE_MS << "ms";
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetNowMillisecond_002 end";
}

/**
 * @tc.name: FmsFormTimeUtilTest_GetBootTimeMs_MultipleCalls_001
 * @tc.desc: Verify multiple calls to GetBootTimeMs return non-decreasing values with total time threshold
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormTimeUtilTest, FmsFormTimeUtilTest_GetBootTimeMs_MultipleCalls_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetBootTimeMs_MultipleCalls_001 start";
    int64_t times[CALL_COUNT];
    for (int i = 0; i < CALL_COUNT; i++) {
        times[i] = FormTimeUtil::GetBootTimeMs();
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL_MS));
    }

    for (int i = 1; i < CALL_COUNT; i++) {
        EXPECT_GE(times[i], times[i - 1]) << "Time should be non-decreasing at index " << i;
    }

    int64_t totalTimeDiff = times[CALL_COUNT - 1] - times[0];

    int64_t minExpected = EXPECTED_TOTAL_SLEEP_MS - TOTAL_TIME_TOLERANCE_MS;
    int64_t maxExpected = EXPECTED_TOTAL_SLEEP_MS + TOTAL_TIME_TOLERANCE_MS;

    EXPECT_GE(totalTimeDiff, minExpected) << "Total time diff " << totalTimeDiff <<
        "ms should be >= expected total sleep " << EXPECTED_TOTAL_SLEEP_MS <<
        "ms minus tolerance " << TOTAL_TIME_TOLERANCE_MS << "ms";
    EXPECT_LE(totalTimeDiff, maxExpected) << "Total time diff " << totalTimeDiff <<
        "ms should be <= expected total sleep " << EXPECTED_TOTAL_SLEEP_MS <<
        "ms plus tolerance " << TOTAL_TIME_TOLERANCE_MS << "ms";
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetBootTimeMs_MultipleCalls_001 end";
}

/**
 * @tc.name: FmsFormTimeUtilTest_GetNowMillisecond_MultipleCalls_001
 * @tc.desc: Verify multiple calls to GetNowMillisecond return non-decreasing values with total time threshold
 * @tc.type: FUNC
 */
HWTEST_F(FmsFormTimeUtilTest, FmsFormTimeUtilTest_GetNowMillisecond_MultipleCalls_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetNowMillisecond_MultipleCalls_001 start";
    int64_t times[CALL_COUNT];
    for (int i = 0; i < CALL_COUNT; i++) {
        times[i] = FormTimeUtil::GetNowMillisecond();
        std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_INTERVAL_MS));
    }

    for (int i = 1; i < CALL_COUNT; i++) {
        EXPECT_GE(times[i], times[i - 1]) << "Time should be non-decreasing at index " << i;
    }

    int64_t totalTimeDiff = times[CALL_COUNT - 1] - times[0];

    int64_t minExpected = EXPECTED_TOTAL_SLEEP_MS - TOTAL_TIME_TOLERANCE_MS;
    int64_t maxExpected = EXPECTED_TOTAL_SLEEP_MS + TOTAL_TIME_TOLERANCE_MS;

    EXPECT_GE(totalTimeDiff, minExpected) << "Total time diff " << totalTimeDiff <<
        "ms should be >= expected total sleep " << EXPECTED_TOTAL_SLEEP_MS <<
        "ms minus tolerance " << TOTAL_TIME_TOLERANCE_MS << "ms";
    EXPECT_LE(totalTimeDiff, maxExpected) << "Total time diff " << totalTimeDiff <<
        "ms should be <= expected total sleep " << EXPECTED_TOTAL_SLEEP_MS <<
        "ms plus tolerance " << TOTAL_TIME_TOLERANCE_MS << "ms";
    GTEST_LOG_(INFO) << "FmsFormTimeUtilTest_GetNowMillisecond_MultipleCalls_001 end";
}
}