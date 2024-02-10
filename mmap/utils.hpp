#pragma once
#include <Windows.h>
#include <locale>
#include <codecvt>
#include <string>
#include "apiset.hpp"


#define VIRTUAL_DLL_PREFIX "api-ms"

static NTSTATUS(__stdcall* NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) = (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER)) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtDelayExecution");
static NTSTATUS(__stdcall* ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG)) GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwSetTimerResolution");

class Utils {
private:
	Utils() {};
public:
	//https://stackoverflow.com/questions/85122/how-to-make-thread-sleep-less-than-a-millisecond-on-windows/31411628#31411628
	//todo: syscall NtDelayExecution
	static void sleep(float milliseconds) {
		static bool once = true;
		if (once) {
			ULONG actualResolution;
			ZwSetTimerResolution(1, true, &actualResolution);
			once = false;
		}

		LARGE_INTEGER interval;
		interval.QuadPart = -1 * (int)(milliseconds * 10000.0f);
		NtDelayExecution(false, &interval);
	}
	//https://github.com/zodiacon/WindowsInternals/blob/master/APISetMap/APISetMap.cpp
	static std::string get_dll_name_from_api_set_map(const std::string& api_set) {
		std::wstring wapi_set(api_set.begin(), api_set.end());
		undocumented::ntdll::PEB* peb = reinterpret_cast<undocumented::ntdll::PEB*>(NtCurrentTeb()->ProcessEnvironmentBlock);
		API_SET_NAMESPACE* apiSetMap = static_cast<API_SET_NAMESPACE*>(peb->ApiSetMap);
		ULONG_PTR apiSetMapAsNumber = reinterpret_cast<ULONG_PTR>(apiSetMap);
		API_SET_NAMESPACE_ENTRY* nsEntry = reinterpret_cast<API_SET_NAMESPACE_ENTRY*>((apiSetMap->EntryOffset + apiSetMapAsNumber));
		for (ULONG i = 0; i < apiSetMap->Count; i++) {
			UNICODE_STRING nameString, valueString;
			nameString.MaximumLength = static_cast<USHORT>(nsEntry->NameLength);
			nameString.Length = static_cast<USHORT>(nsEntry->NameLength);
			nameString.Buffer = reinterpret_cast<PWCHAR>(apiSetMapAsNumber + nsEntry->NameOffset);
			std::wstring name = std::wstring(nameString.Buffer, nameString.Length / sizeof(WCHAR)) + L".dll";
			if (_wcsicmp(wapi_set.c_str(), name.c_str()) == 0) {
				API_SET_VALUE_ENTRY* valueEntry = reinterpret_cast<API_SET_VALUE_ENTRY*>(apiSetMapAsNumber + nsEntry->ValueOffset);
				if (nsEntry->ValueCount == 0)
					return "";
				valueString.Buffer = reinterpret_cast<PWCHAR>(apiSetMapAsNumber + valueEntry->ValueOffset);
				valueString.MaximumLength = static_cast<USHORT>(valueEntry->ValueLength);
				valueString.Length = static_cast<USHORT>(valueEntry->ValueLength);
				std::wstring value = std::wstring(valueString.Buffer, valueString.Length / sizeof(WCHAR));
				//note: there might be more than one value, but we will just return the first one..
				return std::string(value.begin(), value.end());
			}
			nsEntry++;
		}
		return "";
	}
	static std::wstring get_wstring_from_char(const char* str) {
		static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> wstr_converter;
		return wstr_converter.from_bytes(str);
	}
	static void print_and_exit(const char* format, ...) {
		printf("Error: ");
		va_list arglist;
		va_start(arglist, format);
		vprintf(format, arglist);
		va_end(arglist);
		std::exit(1);
	}
};