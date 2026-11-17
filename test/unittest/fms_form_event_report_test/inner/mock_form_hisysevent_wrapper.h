#ifndef INNER_MOCK_FORM_HISYSEVENT_WRAPPER_H
#define INNER_MOCK_FORM_HISYSEVENT_WRAPPER_H

#include <cstdint>
#include <string>

void MockFormHiSysEventWrapperWriteEvent(int32_t mockRet);
void ResetFormHiSysEventWrapperMock();

int32_t GetFormHiSysEventWrapperWriteCount();
std::string GetLastWriteDomain();
std::string GetLastWriteEventName();

#endif // INNER_MOCK_FORM_HISYSEVENT_WRAPPER_H
