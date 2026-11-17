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
#include "form_hisysevent_wrapper.h"
#include "fms_log_wrapper.h"

namespace {
int32_t g_writeEventRet = 0;
int32_t g_writeEventCount = 0;
std::string g_lastDomain;
std::string g_lastEventName;
}

void MockFormHiSysEventWrapperWriteEvent(int32_t mockRet)
{
    g_writeEventRet = mockRet;
}

void ResetFormHiSysEventWrapperMock()
{
    g_writeEventRet = 0;
    g_writeEventCount = 0;
    g_lastDomain.clear();
    g_lastEventName.clear();
}

int32_t GetFormHiSysEventWrapperWriteCount()
{
    return g_writeEventCount;
}

std::string GetLastWriteDomain()
{
    return g_lastDomain;
}

std::string GetLastWriteEventName()
{
    return g_lastEventName;
}

namespace OHOS {
namespace AppExecFwk {
void FormHiSysEventBuilder::InsertParam(const std::string &key, int64_t value)
{
    HILOG_DEBUG("InsertParam int64_t called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, uint64_t value)
{
    HILOG_DEBUG("InsertParam uint64_t called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, int32_t value)
{
    HILOG_DEBUG("InsertParam int32_t called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, uint32_t value)
{
    HILOG_DEBUG("InsertParam uint32_t called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, int8_t value)
{
    HILOG_DEBUG("InsertParam int8_t called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, uint8_t value)
{
    HILOG_DEBUG("InsertParam uint8_t called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, bool value)
{
    HILOG_DEBUG("InsertParam bool called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, float value)
{
    HILOG_DEBUG("InsertParam float called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, double value)
{
    HILOG_DEBUG("InsertParam double called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const char *value)
{
    HILOG_DEBUG("InsertParam const char* called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::string &value)
{
    HILOG_DEBUG("InsertParam string called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<int64_t> &values)
{
    HILOG_DEBUG("InsertParam vector<int64_t> called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<uint64_t> &values)
{
    HILOG_DEBUG("InsertParam vector<uint64_t> called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<int32_t> &values)
{
    HILOG_DEBUG("InsertParam vector<int32_t> called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<uint32_t> &values)
{
    HILOG_DEBUG("InsertParam vector<uint32_t> called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<uint8_t> &values)
{
    HILOG_DEBUG("InsertParam vector<uint8_t> called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<bool> &values)
{
    HILOG_DEBUG("InsertParam vector<bool> called, key=%{public}s", key.c_str());
}

void FormHiSysEventBuilder::InsertParam(const std::string &key, const std::vector<std::string> &values)
{
    HILOG_DEBUG("InsertParam vector<string> called, key=%{public}s", key.c_str());
}

int FormHiSysEventBuilder::Write(const std::string &domain, const std::string &eventName, HiSysEventEventType eventType)
{
    HILOG_DEBUG("Write called, domain=%{public}s, eventName=%{public}s", domain.c_str(), eventName.c_str());
    g_writeEventCount++;
    g_lastDomain = domain;
    g_lastEventName = eventName;
    return g_writeEventRet;
}

void FormHiSysEventBuilder::Clear()
{
    HILOG_DEBUG("Clear called");
}

bool FormHiSysEventBuilder::CheckParamCount()
{
    return true;
}

HiSysEventParam FormHiSysEventBuilder::PrepareParam(const std::string &key, HiSysEventParamType type)
{
    HiSysEventParam param;
    return param;
}

void FormHiSysEventBuilder::SetParamName(HiSysEventParam &param, const std::string &key)
{
    HILOG_DEBUG("SetParamName called, key=%{public}s", key.c_str());
}

int FormHiSysEventWrapper::WriteEvent(const std::string &domain, const std::string &eventName,
    HiSysEventEventType eventType)
{
    HILOG_DEBUG("WriteEvent called, domain=%{public}s, eventName=%{public}s", domain.c_str(), eventName.c_str());
    g_writeEventCount++;
    g_lastDomain = domain;
    g_lastEventName = eventName;
    return g_writeEventRet;
}
} // namespace AppExecFwk
} // namespace OHOS
