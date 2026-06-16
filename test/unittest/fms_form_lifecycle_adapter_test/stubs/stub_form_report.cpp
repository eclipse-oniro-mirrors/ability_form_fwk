/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * Stub implementation for FormReport used in unit testing.
 */

#include "common/util/form_report.h"

namespace OHOS {
namespace AppExecFwk {

FormReport::FormReport() {}
FormReport::~FormReport() {}

void FormReport::SetFormRecordInfo(int64_t formId, const Want &want) {}
void FormReport::SetStartAquireTime(int64_t formId, int64_t startTime) {}
void FormReport::SetEndAquireTime(int64_t formId, int64_t endTime) {}
void FormReport::GetEndAquireTime(int64_t formId, int64_t &endTime) {}
void FormReport::SetStartBindTime(int64_t formId, int64_t startTime) {}
void FormReport::SetEndBindTime(int64_t formId, int64_t endBindTime_) {}
void FormReport::SetStartGetTime(int64_t formId, int64_t startTime) {}
void FormReport::SetEndGetTime(int64_t formId, int64_t endTime) {}
void FormReport::SetDurationStartTime(int64_t formId, int64_t startTime) {}
void FormReport::SetDurationEndTime(int64_t formId, int64_t endTime) {}
void FormReport::HandleAddFormStatistic(int64_t formId) {}
void FormReport::HandleFirstUpdateStatistic(int64_t formId) {}
void FormReport::InsertFormId(int64_t formId) {}
void FormReport::RemoveFormId(int64_t formId) {}
bool FormReport::HasFormId(int64_t formId) { return false; }
std::unordered_map<int64_t, FormStatistic>& FormReport::GetStatistic()
{
    static std::unordered_map<int64_t, FormStatistic> empty;
    return empty;
}
}  // namespace AppExecFwk
}  // namespace OHOS
