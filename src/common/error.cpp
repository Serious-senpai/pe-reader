#include "error.hpp"

void print_last_error()
{
    DWORD code = GetLastError();
    if (code == 0)
    {
        return;
    }

    LPWSTR message_buffer = nullptr;
    DWORD size = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&message_buffer,
        0,
        NULL);

    std::wstring message;
    if (size == 0)
    {
        message = L"Unknown error.";
    }
    else
    {
        message.assign(message_buffer, size);
    }

    std::wcerr << message << std::endl;
    if (message_buffer != nullptr)
    {
        LocalFree(message_buffer);
    }
}
