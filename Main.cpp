#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS

#include <ncrypt.h>
#include <bcrypt.h>
#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>
#include <string>
#include <vector>
#include <functional>
#include <optional>

#pragma comment(lib, "ncrypt.lib")

#define KEY_NAME L"tpm_test_key"

// printf format for wstring. Helper function.
std::string Format(const char* pszFormat, ...)
{
    va_list argptr;
    va_start(argptr, pszFormat);

    size_t nCount = _vscprintf(pszFormat, argptr);
    if (nCount == -1)
    {
        return std::string();
    }

    std::vector<char> buf;

    buf.resize(nCount + 1);

    vsprintf_s(buf.data(), nCount + 1, pszFormat, argptr);

    va_end(argptr);

    std::string strOut = buf.data();

    return strOut;
}

std::optional<std::vector<uint8_t>> create_sign_buffer(std::string &error)
{
    std::vector<uint8_t> buffer(32);

    // Fill buffer with random starting data. Why? So the decrypt won't have a pattern!
    NTSTATUS ntStatus = ::BCryptGenRandom(
        NULL,                       // Alg Handle pointer; If NULL, the default provider is chosen
        (PBYTE)buffer.data(),            // Address of the buffer that recieves the random number(s)
        (ULONG)buffer.size(),             // Size of the buffer in bytes
        BCRYPT_USE_SYSTEM_PREFERRED_RNG); // Flags 
    if (!NT_SUCCESS(ntStatus))
    {
        SECURITY_STATUS secStatus = HRESULT_FROM_NT(ntStatus);
        error = ::Format("Failed to generate random data for signing (error: 0x%08X)", secStatus);
        return std::nullopt;
    }

    return buffer;
}

std::optional<NCRYPT_PROV_HANDLE> open_provider(std::string &error)
{
    NCRYPT_PROV_HANDLE prov;

    SECURITY_STATUS result = ::NCryptOpenStorageProvider(&prov, MS_PLATFORM_CRYPTO_PROVIDER, 0);
    if (FAILED(result))
    {
        DWORD error_code = ::GetLastError();
        error = ::Format("Failed to open crypto provider (0x%08X)", error_code);
        return std::nullopt;
    }

    return prov;
}

bool close_provider(NCRYPT_PROV_HANDLE prov, std::string& error)
{
    SECURITY_STATUS result = ::NCryptFreeObject(prov);
    if (FAILED(result))
    {
        error = ::Format("Failed to close crypto provider (0x%08X)", result);
        return false;
    }

    return true;
}

bool close_key(NCRYPT_KEY_HANDLE key, std::string& error)
{
    SECURITY_STATUS result = ::NCryptFreeObject(key);
    if (FAILED(result))
    {
        error = ::Format("Failed to close key (0x%08X)", result);
        return false;
    }

    return true;
}


bool create_key(const std::wstring& name, std::string& error)
{
    auto prov = open_provider(error);
    if (!prov.has_value())
    {
        return false;
    }

    NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS status = ::NCryptCreatePersistedKey(prov.value(), &key, BCRYPT_ECDSA_ALGORITHM, name.c_str(), 0, NCRYPT_OVERWRITE_KEY_FLAG);
    if (FAILED(status))
    {
        error = ::Format("Failed to create persisted ecdsa key (error: 0x%08X)", status);
        return false;
    }
    
    // NTE_NOT_SUPPORTED is returned by some providers (TPM) meaning you can't set what curve to use. Software -REQUIRES- setting the curve to use.
    status = NCryptSetProperty(key, BCRYPT_ECC_CURVE_NAME, (PUCHAR)BCRYPT_ECC_CURVE_NISTP256, (DWORD)sizeof(BCRYPT_ECC_CURVE_NISTP256), 0);
    if (FAILED(status)
    && status != NTE_NOT_SUPPORTED)
    {
        error = ::Format("Failed to set curve on ecdsa key (error: 0x%08X)", status);
        ::NCryptFreeObject(key);
        return false;
    }

    status = ::NCryptFinalizeKey(key, 0);
    if (FAILED(status))
    {
        error = Format("Failed to finalize ecdsa key (error: 0x%08X)", status);
        ::NCryptFreeObject(key);
        return false;
    }

    if (!close_key(key, error))
    {
        return false;
    }

    if (!close_provider(prov.value(), error))
    {
        return false;
    }

    return true;
}

bool delete_key(const std::wstring& name, std::string& error)
{
    auto prov = open_provider(error);
    if (!prov.has_value())
    {
        return false;
    }

    NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS status = ::NCryptOpenKey(prov.value(), &key, name.c_str(), 0, 0);
    if (FAILED(status))
    {
        error = ::Format("Failed to open ecdsa key (error: 0x%08X)", status);
        return false;
    }

    status = ::NCryptDeleteKey(key, 0);
    if (FAILED(status))
    {
        error = Format("Failed to delete ecdsa key (error: 0x%08X)", status);
        return false;
    }

    if (!close_provider(prov.value(), error))
    {
        return false;
    }

    return true;
}

bool sign_buffer(const std::wstring& name, std::string& error)
{
    auto prov = open_provider(error);
    if (!prov.has_value())
    {
        return false;
    }

    NCRYPT_KEY_HANDLE key;
    SECURITY_STATUS status = ::NCryptOpenKey(prov.value(), &key, name.c_str(), 0, 0);
    if (FAILED(status))
    {
        error = ::Format("Failed to open ecdsa key (error: 0x%08X)", status);
        return false;
    }

    auto buffer = create_sign_buffer(error);
    if (!buffer.has_value())
    {
        ::NCryptFreeObject(key);
        return false;
    }

    DWORD dwSize;
    status = ::NCryptSignHash(key, NULL, (PBYTE)buffer.value().data(), (DWORD)buffer.value().size(), NULL, 0, &dwSize, 0);
    if (FAILED(status))
    {
        error = Format("Failed to calculate buffer length for signing (error: 0x%08X)", status);
        ::NCryptFreeObject(key);
        return false;
    }

    std::vector<uint8_t> out((size_t)dwSize);

    status = NCryptSignHash(key, NULL, (PBYTE)buffer.value().data(), (DWORD)buffer.value().size(), out.data(), (DWORD)out.size(), &dwSize, 0);
    if (FAILED(status))
    {
        error = Format("Failed to sign buffer (error: 0x%08X)", status);
        ::NCryptFreeObject(key);
        return false;
    }


    if (!close_key(key, error))
    {
        return false;
    }

    if (!close_provider(prov.value(), error))
    {
        return false;
    }

    return true;
}

void usage()
{
    printf("USAGE: TPMtool.exe <action>\r\n\r\n");
    printf("ACTIONS:\r\n");
    printf("\tcreate_key  - Creates and ECDSA key with the name \"%S\".\r\n", KEY_NAME);
    printf("\tsign        - Uses the ECDSA key to sign a random buffer.\r\n");
    printf("\tdelete_key  - Deletes the ECDSA key with the name \"%S\".\r\n", KEY_NAME);
}

int do_create_key()
{
    printf("Creating ECDSA key with the name \"%S\"...", KEY_NAME);

    std::string error;
    if (create_key(KEY_NAME, error))
    {
        printf("success.\r\n");
        return 0;
    }
    else
    {
        printf("failed.\r\nError: %s\r\n", error.c_str());
        return 1;
    }
}

int do_delete_key()
{
    printf("Deleting ECDSA key with the name \"%S\"...", KEY_NAME);

    std::string error;
    if (delete_key(KEY_NAME, error))
    {
        printf("success.\r\n");
        return 0;
    }
    else
    {
        printf("failed.\r\nError: %s\r\n", error.c_str());
        return 1;
    }
}

int do_sign()
{
    printf("Signing random buffer with the key named \"%S\"...", KEY_NAME);

    std::string error;
    if (sign_buffer(KEY_NAME, error))
    {
        printf("success.\r\n");
        return 0;
    }
    else
    {
        printf("failed.\r\nError: %s\r\n", error.c_str());
        return 1;
    }
}

int wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
    if (argc < 2)
    {
        usage();
        return 1;
    }

    std::wstring action = argv[1];
    if (action == L"create_key")
    {
        return do_create_key();
    }
    else  if (action == L"delete_key")
    {
        return do_delete_key();
    }
    else if (action == L"sign")
    {
        return do_sign();
    }
    else
    {
        printf("Error: Unknown action \"%S\".\r\n\r\n", action.c_str());
        usage();
    }

    return 0;
}