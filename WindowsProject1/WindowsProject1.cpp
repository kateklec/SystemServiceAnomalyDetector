#include "json.hpp"
#include <fstream>

#include "framework.h"
#include "WindowsProject1.h"
#include "sqlite3.h"
#include <iostream>
#include <CommCtrl.h>
#include <Initguid.h>
#include <windows.h>
#include <string>
#include <algorithm>
#include <vector>
#include <map>
#include <stdio.h>
#include <locale>
#include <set>
#include <chrono>
#include <ctime>
#include <shellapi.h>

#include <wincrypt.h>
#include <sstream>
#include <iomanip>

#include <future>
#include <thread>

using json = nlohmann::json;

#define MAX_LOADSTRING 100

#pragma comment(lib, "comctl32.lib")
//#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

// Глобальные переменные:
HINSTANCE hInst;                                // текущий экземпляр
WCHAR szTitle[MAX_LOADSTRING];                  // Текст строки заголовка
WCHAR szWindowClass[MAX_LOADSTRING];            // имя класса главного окна
HWND hWndListView;
sqlite3* db = nullptr;
HWND hEditResult;

// Отправить объявления функций, включенных в этот модуль кода:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    DatabaseDialogProc(HWND, UINT, WPARAM, LPARAM);
void UpdateServiceData(ENUM_SERVICE_STATUS_PROCESS&, QUERY_SERVICE_CONFIG*, SERVICE_STATUS_PROCESS&, LPSERVICE_DESCRIPTION);
void StartMonitoring(int intervalSeconds);
void StopMonitoring();
INT_PTR CALLBACK MonitoringDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
std::wstring UpdateResults();
void OpenNotepadAndWait(const wchar_t* filename);

std::string wcharToString(const wchar_t* wstr) {
    if (wstr == nullptr) {
        return std::string();
    }

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &strTo[0], size_needed, NULL, NULL);
    strTo.pop_back();
    return strTo;
}

std::wstring stringToWstring(const std::string& str) {
    if (str.empty()) {
        return std::wstring();
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string wstringToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &str[0], size_needed, NULL, NULL);
    return str;
}

// Функция для загрузки JSON из файла
json loadJson(const std::string& filename) {
    std::ifstream file(filename);
    json j;
    file >> j;
    return j;
}

// Загрузка JSON данных
json criticalServicesNotDisabled = loadJson("services_not_disabled.json");
json criticalServicesNotStopped = loadJson("services_not_stopped.json");
json viruses = loadJson("viruses.json");
json customServices = loadJson("custom_services.json");

// Функция для хэширования пароля с использованием SHA-256
std::string hashPassword(const std::string& password) {
    HCRYPTPROV hProv = 0; // Дескриптор криптографического провайдера
    HCRYPTHASH hHash = 0; // Дескриптор хэша
    BYTE hash[32]; // Массив для хранения хэша (32 байта для SHA-256)
    DWORD hashLen = 32; // Длина хэша (32 байта для SHA-256)

    // Получение контекста криптографического провайдера
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        // Создание объекта хэша
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            // Добавление данных для хэширования
            if (CryptHashData(hHash, (BYTE*)password.c_str(), password.length(), 0)) {
                // Получение хэш-значения
                if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                    std::stringstream ss;
                    // Преобразование хэша в шестнадцатеричную строку
                    for (DWORD i = 0; i < hashLen; i++) {
                        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                    }
                    // Освобождение дескриптора хэша
                    CryptDestroyHash(hHash);
                    // Освобождение контекста криптографического провайдера
                    CryptReleaseContext(hProv, 0);
                    return ss.str();
                }
            }
            // Освобождение дескриптора хэша в случае ошибки
            CryptDestroyHash(hHash);
        }
        // Освобождение контекста криптографического провайдера в случае ошибки
        CryptReleaseContext(hProv, 0);
    }
    return "";
}

// Функция для проверки пароля администратора
bool checkAdminPassword(const std::string& inputPassword) {
    std::ifstream file("password.json");
    if (!file.is_open()) {
        MessageBox(NULL, L"Не удалось открыть файл с паролем администратора.", L"Ошибка", MB_ICONERROR);
        return false;
    }

    json passwordJson;
    file >> passwordJson;
    std::string storedHash = passwordJson["admin_password_hash"];
    std::string inputHash = hashPassword(inputPassword);

    return storedHash == inputHash;
}

wchar_t inputPassword[100];

// Диалоговый обработчик пароля
INT_PTR CALLBACK PasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);
    //static wchar_t inputPassword[100]; // Статический буфер для хранения пароля
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            GetDlgItemText(hDlg, IDC_PASSWORD, inputPassword, 100);
            EndDialog(hDlg, IDOK);
            return (INT_PTR)TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}


bool promptForAdminPassword() {
    int result = DialogBoxParam(hInst, MAKEINTRESOURCE(IDD_PASSWORD_DIALOG), NULL, PasswordDialogProc, (LPARAM)inputPassword);
    if (result == IDOK) {
        if (checkAdminPassword(wcharToString(inputPassword))) {
            return true;
        }
        else {
            MessageBox(NULL, L"Неверный пароль администратора.", L"Ошибка", MB_ICONERROR);
            return false;
        }
    }
    return false;
}

std::string getStoredPasswordHash() {
    std::ifstream file("password.json");
    json passwordJson;
    file >> passwordJson;
    return passwordJson["admin_password_hash"];
}

void updateAdminPasswordHash(const std::string& newHash) {
    std::ofstream file("password.json");
    json passwordJson;
    passwordJson["admin_password_hash"] = newHash;
    file << passwordJson;
}

INT_PTR CALLBACK ChangePasswordDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            wchar_t oldPassword[100], newPassword[100], confirmPassword[100];
            GetDlgItemText(hDlg, IDC_OLD_PASSWORD, oldPassword, 100);
            GetDlgItemText(hDlg, IDC_NEW_PASSWORD, newPassword, 100);
            GetDlgItemText(hDlg, IDC_CONFIRM_PASSWORD, confirmPassword, 100);

            if (hashPassword(wstringToString(oldPassword)) != getStoredPasswordHash()) {
                MessageBox(hDlg, L"Неверный старый пароль.", L"Ошибка", MB_ICONERROR);
            }
            else if (wcscmp(newPassword, confirmPassword) != 0) {
                MessageBox(hDlg, L"Пароли не совпадают.", L"Ошибка", MB_ICONERROR);
            }
            else {
                updateAdminPasswordHash(hashPassword(wstringToString(newPassword)));
                MessageBox(hDlg, L"Пароль успешно изменен.", L"Успех", MB_ICONINFORMATION);
                EndDialog(hDlg, IDOK);
            }
            return (INT_PTR)TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, IDCANCEL);
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

std::map<std::wstring, std::wstring> DynamicNamesNotDisabled = {};

// Функция для получения списка служб, имена которых содержат заданный шаблон
std::vector<std::wstring> FindServicesWithDynamicNames(const std::wstring& baseName) {
    std::vector<std::wstring> foundServices;
    ENUM_SERVICE_STATUS_PROCESS* serviceArray = nullptr;
    DWORD bytesNeeded = 0;
    DWORD serviceCount = 0;
    DWORD resumeHandle = 0;
    SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);

    if (scmHandle) {
        // Определение размера буфера
        EnumServicesStatusEx(scmHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            nullptr, 0, &bytesNeeded, &serviceCount, &resumeHandle, nullptr);

        serviceArray = (ENUM_SERVICE_STATUS_PROCESS*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytesNeeded);

        if (serviceArray) {
            // Получение списка служб
            if (EnumServicesStatusEx(scmHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                (LPBYTE)serviceArray, bytesNeeded, &bytesNeeded, &serviceCount,
                &resumeHandle, nullptr)) {
                // Перебор всех служб и поиск по шаблону
                for (DWORD i = 0; i < serviceCount; i++) {
                    std::wstring serviceName = serviceArray[i].lpServiceName;
                    if (serviceName.find(baseName) != std::wstring::npos) {
                        foundServices.push_back(serviceName);
                    }
                }
            }
            HeapFree(GetProcessHeap(), 0, serviceArray);
        }
        CloseServiceHandle(scmHandle);
    }

    return foundServices;
}

std::string GetScanStartTime() {

    auto now = std::chrono::system_clock::now();
    //для корректировки
    auto adjustedTime = now - std::chrono::seconds(5) - std::chrono::hours(3);
    // Преобразуем время в тип std::time_t для последующего форматирования
    auto adjustedTimeT = std::chrono::system_clock::to_time_t(adjustedTime);
    std::tm localTm = {};
    localtime_s(&localTm, &adjustedTimeT); // безопасная альтернатива std::localtime
    std::stringstream ss;
    ss << std::put_time(&localTm, "%Y-%m-%d %H:%M:%S"); // Преобразование обратно в строку
    return ss.str();
}

void InitializeDatabase() {

    //sqlite3* db;
    char* errMsg = nullptr;
    int rc;

    // Открытие базы данных (или ее создание, если она не существует)
    rc = sqlite3_open("services.db", &db);
    if (rc != SQLITE_OK) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        return;
    }

    // Создание таблицы, если она не существует
    const char* sqlCreateTable =
        "CREATE TABLE IF NOT EXISTS Services ("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ServiceName TEXT, "
        "DisplayName TEXT, "
        "ServiceType INTEGER, "
        "StartType INTEGER, "
        "ErrorControl INTEGER, "
        "BinaryPath TEXT, "
        "Account TEXT, "
        "CurrentState INTEGER, "
        "Win32ExitCode INTEGER, "
        "ServiceSpecificExitCode INTEGER, "
        "CheckPoint INTEGER, "
        "WaitHint INTEGER, "
        "ProcessID INTEGER, "
        "ServiceFlags INTEGER, "
        "Description TEXT, "
        "LastUpdated TIMESTAMP DEFAULT CURRENT_TIMESTAMP)";

    rc = sqlite3_exec(db, sqlCreateTable, nullptr, nullptr, &errMsg);

    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
    else {
        std::cout << "Table created successfully" << std::endl;
    }

    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scManager) {
        std::cerr << "Error opening service manager." << std::endl;
        sqlite3_close(db);
        return;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusEx(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    std::vector<BYTE> buffer(bytesNeeded);
    ENUM_SERVICE_STATUS_PROCESS* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESS*>(buffer.data());

    if (!EnumServicesStatusEx(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, buffer.data(), buffer.size(), &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        std::cerr << "Error enumerating services." << std::endl;
        CloseServiceHandle(scManager);
        sqlite3_close(db);
        return;
    }

    for (unsigned int i = 0; i < servicesReturned; ++i) {
        SC_HANDLE service = OpenService(scManager, services[i].lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
        if (service) {
            DWORD bytesNeeded = 0;
            QueryServiceConfig(service, NULL, 0, &bytesNeeded);
            std::vector<BYTE> configBuffer(bytesNeeded);
            QUERY_SERVICE_CONFIG* serviceConfig = reinterpret_cast<QUERY_SERVICE_CONFIG*>(configBuffer.data());

            if (QueryServiceConfig(service, serviceConfig, configBuffer.size(), &bytesNeeded)) {
                SERVICE_STATUS_PROCESS status;
                if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
                    DWORD bytesNeededDesc = 0;
                    QueryServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &bytesNeededDesc);
                    std::vector<BYTE> descriptionBuffer(bytesNeededDesc);
                    LPSERVICE_DESCRIPTION svcDescription = nullptr;
                    if (QueryServiceConfig2(service, SERVICE_CONFIG_DESCRIPTION, descriptionBuffer.data(), bytesNeededDesc, &bytesNeededDesc)) {
                        svcDescription = (LPSERVICE_DESCRIPTION)descriptionBuffer.data();
                    }

                    UpdateServiceData(services[i], serviceConfig, status, svcDescription);
                }
            }

            CloseServiceHandle(service);
        }
    }
    //CloseServiceHandle(scManager);
    //sqlite3_close(db);
}

void UpdateDynamicNamesNotDisabled() {
    // Очистка словаря
    DynamicNamesNotDisabled.clear();

    // Заполнение словаря динамическими именами
    for (const auto& el : customServices.items()) {
        std::wstring baseName = stringToWstring(el.key());
        std::wstring description = stringToWstring(el.value());
        std::vector<std::wstring> foundServices = FindServicesWithDynamicNames(baseName);
        for (const auto& serviceName : foundServices) {
            DynamicNamesNotDisabled[serviceName] = description;
        }
    }
}

void UpdateServiceData(ENUM_SERVICE_STATUS_PROCESS& serviceData, QUERY_SERVICE_CONFIG* serviceConfig, SERVICE_STATUS_PROCESS& status, LPSERVICE_DESCRIPTION svcDescription) {

    std::string scanStartTime = GetScanStartTime();
    
    char* errMsg = 0;
    int rcPrepare, rcExec;

    // Проверка на существование записи
    char* sqlCheck = sqlite3_mprintf("SELECT COUNT(*) FROM Services WHERE ServiceName = %Q", wcharToString(serviceData.lpServiceName).c_str());
    sqlite3_stmt* stmt;
    rcPrepare = sqlite3_prepare_v2(db, sqlCheck, -1, &stmt, NULL);
    if (rcPrepare == SQLITE_OK) {
        sqlite3_step(stmt);
        int count = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        sqlite3_free(sqlCheck);

        // SQL запрос для обновления или вставки
        char* sql;
        if (count > 0) {
            // Обновление существующей записи

            sql = sqlite3_mprintf("UPDATE Services SET DisplayName = %Q, ServiceType = %d, StartType = %d, ErrorControl = %d, BinaryPath = %Q, Account = %Q, CurrentState = %d, Win32ExitCode = %d, ServiceSpecificExitCode = %d, CheckPoint = %d, WaitHint = %d, ProcessID = %d, ServiceFlags = %d, Description = %Q, LastUpdated = CURRENT_TIMESTAMP WHERE ServiceName = %Q",
                wcharToString(serviceData.lpDisplayName).c_str(),
                serviceConfig->dwServiceType,
                serviceConfig->dwStartType,
                serviceConfig->dwErrorControl,
                wcharToString(serviceConfig->lpBinaryPathName).c_str(),
                wcharToString(serviceConfig->lpServiceStartName).c_str(),
                status.dwCurrentState,
                status.dwWin32ExitCode,
                status.dwServiceSpecificExitCode,
                status.dwCheckPoint,
                status.dwWaitHint,
                status.dwProcessId,
                status.dwServiceFlags,
                svcDescription ? wcharToString(svcDescription->lpDescription).c_str() : "",
                wcharToString(serviceData.lpServiceName).c_str());
        }
        else {
            // Вставка новой записи
            sql = sqlite3_mprintf("INSERT INTO Services (ServiceName, DisplayName, ServiceType, StartType, ErrorControl, BinaryPath, Account, CurrentState, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessID, ServiceFlags, Description) VALUES (%Q, %Q, %d, %d, %d, %Q, %Q, %d, %d, %d, %d, %d, %d, %d, %Q)",
                wcharToString(serviceData.lpServiceName).c_str(),
                wcharToString(serviceData.lpDisplayName).c_str(),
                serviceConfig->dwServiceType,
                serviceConfig->dwStartType,
                serviceConfig->dwErrorControl,
                wcharToString(serviceConfig->lpBinaryPathName).c_str(),
                wcharToString(serviceConfig->lpServiceStartName).c_str(),
                status.dwCurrentState,
                status.dwWin32ExitCode,
                status.dwServiceSpecificExitCode,
                status.dwCheckPoint,
                status.dwWaitHint,
                status.dwProcessId,
                status.dwServiceFlags,
                svcDescription ? wcharToString(svcDescription->lpDescription).c_str() : "");
        }

        // Выполнение SQL запроса
        rcExec = sqlite3_exec(db, sql, 0, 0, &errMsg);

        if (rcExec != SQLITE_OK) {
            std::cerr << "SQL error: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }

        sqlite3_free(sql);

        // Удаление записей, которые не были обновлены в текущем сеансе
        char* sqlDeleteOld = sqlite3_mprintf("DELETE FROM Services WHERE LastUpdated < %Q", scanStartTime.c_str());
        rcExec = sqlite3_exec(db, sqlDeleteOld, 0, 0, &errMsg);
        if (rcExec != SQLITE_OK) {
            std::cerr << "SQL error during deleting old records: " << errMsg << std::endl;
            sqlite3_free(errMsg);
        }
        sqlite3_free(sqlDeleteOld);
    }
    else {
        std::cerr << "SQL prepare error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_free(sqlCheck);
    }
}

std::wstring CheckServiceNotStopped(const json& criticalServices) {
    std::wstring result;
    
    // Проверка критических служб из JSON
    for (auto& el : criticalServices.items()) {
        std::string serviceNameStr = el.key();  // Имя службы как std::string
        std::wstring serviceName = stringToWstring(serviceNameStr);  // Преобразуем в std::wstring
        std::string serviceDescriptionStr = el.value();
        std::wstring description = stringToWstring(serviceDescriptionStr);  // Получаем и преобразуем описание

        std::string sql = "SELECT CurrentState FROM Services WHERE ServiceName = ?";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, serviceNameStr.c_str(), -1, SQLITE_TRANSIENT);

            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int currentState = sqlite3_column_int(stmt, 0);
                if (currentState == SERVICE_STOPPED && currentState != SERVICE_DISABLED) {
                    result += L"Служба \"" + serviceName + L"\" остановлена. " + description + L"\r\n\r\n";
                }
            }
            else {
                result += L"Службы \"" + serviceName + L"\" нет в базе данных.\r\n";
            }
            sqlite3_finalize(stmt);
        }
    }

    return result.empty() ? L"Никакие важные службы не остановлены.\r\n\r\n" : result;
}


std::wstring CheckServiceNotDisabled(const json& criticalServices) {
    std::wstring result;
    // Проверка критических служб из JSON
    for (const auto& el : criticalServices.items()) {
        std::string serviceNameStr = el.key();
        std::wstring serviceName = stringToWstring(serviceNameStr);

        std::wstring description;
        // Проверяем, является ли значение строкой
        if (el.value().is_string()) 
            description = stringToWstring(el.value().get<std::string>());  // Безопасно извлекаем и преобразуем строку


        std::string sqlQuery = "SELECT StartType FROM Services WHERE ServiceName = ?";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, sqlQuery.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, serviceNameStr.c_str(), -1, SQLITE_STATIC);  // Привязываем строку UTF-8
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int startType = sqlite3_column_int(stmt, 0);
                if (startType == SERVICE_DISABLED) {
                    result += L"Служба \"" + serviceName + L"\" отключена. " + description + L"\r\n\r\n";
                }
            }
            else {
                result += L"Службы \"" + serviceName + L"\" нет в базе данных.\r\n";
            }
            sqlite3_finalize(stmt);
        }
    }

    // Проверка критических служб из DynamicNamesNotDisabled
    for (const auto& [serviceName, description] : DynamicNamesNotDisabled) {
        std::string serviceNameStr = wstringToString(serviceName); // Преобразуем в std::string

        std::string sqlQuery = "SELECT StartType FROM Services WHERE ServiceName = ?";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, sqlQuery.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, serviceNameStr.c_str(), -1, SQLITE_STATIC); // Привязываем строку UTF-8
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int startType = sqlite3_column_int(stmt, 0);
                if (startType == SERVICE_DISABLED) {
                    result += L"Служба \"" + serviceName + L"\" отключена. " + description + L"\r\n\r\n";
                }
            }
            else {
                result += L"Службы \"" + serviceName + L"\" нет в базе данных.\r\n";
            }
            sqlite3_finalize(stmt);
        }
    }

    return result.empty() ? L"Никакие важные службы не отключены.\n" : result;
}

std::wstring CheckServiceGroup(const json& virus) {
    std::wstring result;
    int disabledCount = 0;
    std::wstring virusDescription = stringToWstring(virus["description"].get<std::string>());

    for (const auto& serviceNameJson : virus["serviceNames"]) {
        std::string serviceNameStr = serviceNameJson.get<std::string>();
        std::string sqlQuery = "SELECT StartType FROM Services WHERE ServiceName = ?";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db, sqlQuery.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, serviceNameStr.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) == SQLITE_ROW) {
                int startType = sqlite3_column_int(stmt, 0);
                if (startType == SERVICE_DISABLED) {
                    disabledCount++;
                }
            }
            sqlite3_finalize(stmt);
        }
    }

    if (disabledCount == virus["serviceNames"].size()) {
        result = L"Возможное присутствие вируса: " + virusDescription + L"\r\n";
    }
    return result;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{

    InitializeDatabase();
    UpdateDynamicNamesNotDisabled();


    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // Инициализация глобальных строк
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_WINDOWSPROJECT1, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Выполнить инициализацию приложения
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_WINDOWSPROJECT1));

    MSG msg;

    // Цикл основного сообщения
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

//
//  ФУНКЦИЯ: MyRegisterClass()
//
//  ЦЕЛЬ: Регистрирует класс окна.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_WINDOWSPROJECT1));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_WINDOWSPROJECT1);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

void FillListViewFromDatabase(HWND hWndListView) {
    ListView_DeleteAllItems(hWndListView); // Очистка ListView
    sqlite3_stmt* stmt;
    if (sqlite3_open("services.db", &db) == SQLITE_OK) {
        const char* sqlQuery = "SELECT ServiceName, DisplayName, ServiceType, StartType, ErrorControl, BinaryPath, Account, CurrentState, Win32ExitCode, ServiceSpecificExitCode, CheckPoint, WaitHint, ProcessID, ServiceFlags, Description FROM Services";
        if (sqlite3_prepare_v2(db, sqlQuery, -1, &stmt, NULL) == SQLITE_OK) {
            for (int rowIndex = 0; sqlite3_step(stmt) == SQLITE_ROW; ++rowIndex) {
                for (int colIndex = 0; colIndex < sqlite3_column_count(stmt); ++colIndex) {
                    LVITEM lvItem = { 0 };
                    lvItem.mask = LVIF_TEXT;
                    lvItem.pszText = (LPWSTR)sqlite3_column_text16(stmt, colIndex);
                    if (colIndex == 0) { // Для первой колонки используем ListView_InsertItem
                        lvItem.iItem = rowIndex;
                        lvItem.iSubItem = 0; // Основной элемент
                        ListView_InsertItem(hWndListView, &lvItem);
                    }
                    else { // Для подэлементов
                        lvItem.iItem = rowIndex;
                        lvItem.iSubItem = colIndex; // Установить подэлемент
                        ListView_SetItem(hWndListView, &lvItem);
                    }
                }
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
}

//
//   ФУНКЦИЯ: InitInstance(HINSTANCE, int)
//
//   ЦЕЛЬ: Сохраняет маркер экземпляра и создает главное окно
//
//   КОММЕНТАРИИ:
//
//        В этой функции маркер экземпляра сохраняется в глобальной переменной, а также
//        создается и выводится главное окно программы.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{

    INITCOMMONCONTROLSEX icex;    // Структура для инициализации элементов управления
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES;  // Указываем, какие именно классы элементов управления мы хотим инициализировать
    InitCommonControlsEx(&icex);  // Вызов функции инициализации

   hInst = hInstance; // Сохранить маркер экземпляра в глобальной переменной

   HWND hWnd = CreateWindowW(szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, 1400, 700, nullptr, nullptr, hInstance, nullptr);

   if (!hWnd)
   {
      return FALSE;
   }

   ShowWindow(hWnd, nCmdShow);

   UpdateWindow(hWnd);

   return TRUE;
}

//
//  ФУНКЦИЯ: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  ЦЕЛЬ: Обрабатывает сообщения в главном окне.
//
//  WM_COMMAND  - обработать меню приложения
//  WM_PAINT    - Отрисовка главного окна
//  WM_DESTROY  - отправить сообщение о выходе и вернуться
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    
    case WM_CREATE :
    { 
        // Получаем HINSTANCE из HWND
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtr(hWnd, GWLP_HINSTANCE);

        // Создание кнопки "Открыть базу данных"
        CreateWindow(
            L"BUTTON",  
            L"Состояния служб",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON, 
            40, // x 
            20, // y
            150, // ширина
            40, // высота
            hWnd,
            (HMENU)ID_BUTTON_OPENDB,
            hInst,
            NULL);

        // Создание кнопки "Проверить службы"
        CreateWindow(
            L"BUTTON", L"Проверить службы (сканирование по запросу)",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            250, 20, 340, 40, hWnd, (HMENU)ID_BUTTON_SCAN, hInst, NULL);

        // Добавляем кнопку "Настроить мониторинг"
        CreateWindow(
            L"BUTTON", L"Настроить мониторинг",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            650, 20, 200, 40, hWnd, (HMENU)ID_BUTTON_MONITORING, hInst, NULL);

        // Создание статической надписи "Для администратора:"
        CreateWindow(
            L"STATIC", L"Для администратора:",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            1160, 80, 170, 20, hWnd, (HMENU)ID_BUTTON_ADD_VIRUS, hInst, NULL);

        // Создание кнопки "Добавить описания вирусов"
        CreateWindow(
            L"BUTTON", L"Добавить описания вирусов",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            1145, 150, 200, 40, hWnd, (HMENU)ID_BUTTON_ADD_VIRUS, hInst, NULL);

        // Создание кнопки "Изменить службы, которые не должны быть отключены"
        CreateWindow(
            L"BUTTON", L"Не отключены",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            1145, 230, 200, 40, hWnd, (HMENU)ID_BUTTON_EDIT_DISABLE, hInst, NULL);

        // Создание кнопки "Изменить службы, которые не должны быть остановлены"
        CreateWindow(
            L"BUTTON", L"Не остановлены",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            1145, 310, 200, 40, hWnd, (HMENU)ID_BUTTON_EDIT_STOP, hInst, NULL);

        hEditResult = CreateWindow(L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | WS_VSCROLL,
            10, 80, 1100, 530, 
            hWnd, (HMENU)IDC_RESULT_TEXT, hInst, NULL);

        // Создание кнопки "Пользовательские службы"
        CreateWindow(
            L"BUTTON", L"Пользовательские службы",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            1145, 390, 200, 40, hWnd, (HMENU)ID_BUTTON_EDIT_CUSTOM, hInst, NULL);
        
        // Создание кнопки "Изменить пароль администратора"
        CreateWindow(
            L"BUTTON", L"Изменить пароль",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            1145, 470, 200, 40, hWnd, (HMENU)ID_BUTTON_CHANGE_PASSWORD, hInst, NULL);

        break;
    }
    
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            switch (wmId)
            {

            case ID_BUTTON_MONITORING:
                if (DialogBox(hInst, MAKEINTRESOURCE(IDD_MONITORING_DIALOG), hWnd, MonitoringDialogProc) == IDCANCEL) {
                    StopMonitoring();
                }
                break;
            case ID_BUTTON_CHANGE_PASSWORD:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_CHANGE_PASSWORD_DIALOG), hWnd, ChangePasswordDialogProc);
                break;
            case ID_BUTTON_OPENDB:{
                // Обновить данные служб и затем обновить ListView
                InitializeDatabase();
                FillListViewFromDatabase(hWndListView);
                DialogBox(hInst, MAKEINTRESOURCE(IDD_DATABASE_DIALOG), hWnd, DatabaseDialogProc);
            }
                break;
            case ID_BUTTON_SCAN: {
                std::wstring finalResult = UpdateResults();
                // Получение дескриптора элемента управления (предполагается, что элемент уже создан)
                HWND hResultText = GetDlgItem(hWnd, IDC_RESULT_TEXT);

                // Отображение итоговой строки в текстовом поле
                SetWindowTextW(hResultText, finalResult.c_str());
            }
                break;
            case ID_BUTTON_ADD_VIRUS:
                if (promptForAdminPassword()) {
                    OpenNotepadAndWait(L"viruses.json");
                    criticalServicesNotDisabled = loadJson("viruses.json");
                }
                break; 
            case ID_BUTTON_EDIT_DISABLE:
                if (promptForAdminPassword()) {
                    OpenNotepadAndWait(L"services_not_disabled.json");
                    criticalServicesNotDisabled = loadJson("services_not_disabled.json");
                }
                break;
            case ID_BUTTON_EDIT_STOP:
                if (promptForAdminPassword()) {
                    OpenNotepadAndWait(L"services_not_stopped.json");
                    criticalServicesNotDisabled = loadJson("services_not_stopped.json");
                }
                break;
            case ID_BUTTON_EDIT_CUSTOM:
                if (promptForAdminPassword()) {
                    OpenNotepadAndWait(L"custom_services.json");
                    criticalServicesNotDisabled = loadJson("custom_services.json");
                    UpdateDynamicNamesNotDisabled();
                }
                break;
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), hWnd, About);
                break;
            case IDM_EXIT:
                DestroyWindow(hWnd);
                break;
            default:
                return DefWindowProc(hWnd, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hWnd, &ps);
            EndPaint(hWnd, &ps);
        }
        break;
    case WM_DESTROY:
        StopMonitoring();
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

void OpenNotepadAndWait(const wchar_t* filename) {
    SHELLEXECUTEINFO shExecInfo = { 0 };
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExecInfo.hwnd = NULL;
    shExecInfo.lpVerb = L"open";
    shExecInfo.lpFile = L"notepad.exe";
    shExecInfo.lpParameters = filename;
    shExecInfo.lpDirectory = NULL;
    shExecInfo.nShow = SW_SHOWNORMAL;
    shExecInfo.hInstApp = NULL;

    if (ShellExecuteEx(&shExecInfo)) {
        WaitForSingleObject(shExecInfo.hProcess, INFINITE);
        CloseHandle(shExecInfo.hProcess);
    }
    else {
        MessageBox(NULL, L"Не удалось открыть блокнот.", L"Ошибка", MB_ICONERROR);
    }
}

std::wstring UpdateResults() {
    InitializeDatabase();

    std::wstring virusDetectionResult;
    bool virusFound = false;

    // Проход по массиву вирусов в JSON
    for (const auto& virus : viruses["viruses"]) {
        std::wstring result = CheckServiceGroup(virus);
        if (!result.empty()) {
            virusDetectionResult += result;
            virusFound = true;
        }
    }

    // Если вирусы не обнаружены, добавляем соответствующее сообщение
    if (!virusFound) {
        virusDetectionResult = L"Вирусные угрозы не обнаружены.\r\n\r\n";
    }

    // Выполнение остальных проверок
    std::wstring criticalServicesResult = CheckServiceNotStopped(criticalServicesNotStopped);
    std::wstring notDisabledServicesResult = CheckServiceNotDisabled(criticalServicesNotDisabled);

    // Формирование итоговой строки с результатами
    std::wstring finalResult = L"Проверка на вирусы: \r\n\r\n" + virusDetectionResult +
        L"Проверка служб, которые не должны быть остановлены: \r\n\r\n" + criticalServicesResult +
        L"\nПроверка служб, что они не отключены: \r\n\r\n" + notDisabledServicesResult;

    return finalResult;
}

////////////////////////////МОНИТОРИНГ В РЕАЛЬНОМ ВРЕМЕНИ/////////////////////////////

std::future<void> monitoringFuture;
bool stopMonitoringFlag = false;

void StartMonitoring(int intervalSeconds) {
    stopMonitoringFlag = false;
    monitoringFuture = std::async(std::launch::async, [intervalSeconds]() {
        while (!stopMonitoringFlag) {
            std::wstring finalResult = UpdateResults();

            // Отправка сообщения для обновления EDIT элемента
            SendMessage(hEditResult, WM_SETTEXT, 0, (LPARAM)finalResult.c_str());

            // Интервал мониторинга
            std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
        }
        });
}

void StopMonitoring() {
    stopMonitoringFlag = true;
    if (monitoringFuture.valid()) {
        monitoringFuture.get(); // Ждем завершения асинхронной задачи
    }
}

INT_PTR CALLBACK MonitoringDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);
    switch (message) {
    case WM_INITDIALOG: {
        HWND hCombo = GetDlgItem(hDlg, IDC_COMBO_INTERVAL);
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)L"5 секунд");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)L"10 секунд");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)L"1 час");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)L"12 часов");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)L"1 день");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)L"3 дня");
        SendMessage(hCombo, CB_ADDSTRING, 0, (LPARAM)L"7 дней");
        SendMessage(hCombo, CB_SETCURSEL, 0, 0); // Устанавливаем 5 секунд по умолчанию
        return (INT_PTR)TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK) {
            int intervalSeconds = 5; // Интервал по умолчанию
            HWND hCombo = GetDlgItem(hDlg, IDC_COMBO_INTERVAL);
            int sel = SendMessage(hCombo, CB_GETCURSEL, 0, 0);

            switch (sel) {
            case 0: intervalSeconds = 5; break;
            case 1: intervalSeconds = 10; break;
            case 2: intervalSeconds = 3600; break;
            case 3: intervalSeconds = 43200; break;
            case 4: intervalSeconds = 86400; break;
            case 5: intervalSeconds = 259200; break;
            case 6: intervalSeconds = 604800; break;
            }

            wchar_t customIntervalText[100];
            GetDlgItemText(hDlg, IDC_EDIT_CUSTOM_INTERVAL, customIntervalText, 100);
            if (wcslen(customIntervalText) > 0) {
                intervalSeconds = _wtoi(customIntervalText);
                if (intervalSeconds <= 0) {
                    intervalSeconds = 5; // Если пользователь ввел некорректное значение, используем интервал по умолчанию
                }
            }

            StartMonitoring(intervalSeconds);

            EndDialog(hDlg, IDOK);
            return (INT_PTR)TRUE;
        }
        else if (LOWORD(wParam) == IDCANCEL) {
            StopMonitoring();
            EndDialog(hDlg, IDCANCEL);
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

INT_PTR CALLBACK DatabaseDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {

    case WM_NOTIFY:
    {
        LPNMITEMACTIVATE pnmItem = (LPNMITEMACTIVATE)lParam;
        if (pnmItem->hdr.code == NM_DBLCLK) {
            HWND hListView = pnmItem->hdr.hwndFrom;
            int iSelectedItem = pnmItem->iItem;
            WCHAR szText[1024]; // Буфер для текста

            if (iSelectedItem != -1) {
                // Обработка двойного клика по столбцу "DisplayName"
                if (pnmItem->iSubItem == 1) {
                    ListView_GetItemText(hListView, iSelectedItem, 1, szText, ARRAYSIZE(szText));
                    MessageBox(hDlg, szText, L"DisplayName", MB_OK);
                }
                // Обработка двойного клика по столбцу "BinaryPath"
                else if (pnmItem->iSubItem == 5) {
                    ListView_GetItemText(hListView, iSelectedItem, 5, szText, ARRAYSIZE(szText));
                    MessageBox(hDlg, szText, L"BinaryPath", MB_OK);
                }
                // Обработка двойного клика по столбцу "Description"
                else if (pnmItem->iSubItem == 14) {
                    ListView_GetItemText(hListView, iSelectedItem, 14, szText, ARRAYSIZE(szText));
                    MessageBox(hDlg, szText, L"Description", MB_OK);
                }
            }
        }
    } break;

    case WM_INITDIALOG: {
        // Создаем и настраиваем ListView
        HWND hWndListView = CreateWindow(WC_LISTVIEW, L"",
            WS_CHILD | LVS_REPORT | WS_VISIBLE | WS_VSCROLL | LVS_EDITLABELS,
            10, 10, 850, 400, // X, Y, ширина и высота ListView
            hDlg, (HMENU)IDC_LISTVIEW, // Идентификатор ListView
            (HINSTANCE)GetWindowLongPtr(hDlg, GWLP_HINSTANCE), NULL);

        ListView_SetExtendedListViewStyle(hWndListView, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_INFOTIP);

        // Массив с названиями колонок
        const wchar_t* columnNames[] = {
            L"ServiceName", L"DisplayName", L"ServiceType", L"StartType", L"ErrorControl",
            L"BinaryPath", L"Account", L"CurrentState", L"Win32ExitCode",
            L"ServiceSpecificExitCode", L"CheckPoint", L"WaitHint",
            L"ProcessID", L"ServiceFlags", L"Description"
        };

        // Массив с ширинами колонок
        int columnWidths[] = {
            250, 150, 90, 90, 90, 150, 180, 80, 100,
            150, 80, 60, 70, 80, 200
        };

        LVCOLUMN lvColumn;
        lvColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;

        for (int i = 0; i < sizeof(columnNames) / sizeof(columnNames[0]); ++i) {
            lvColumn.pszText = (LPWSTR)columnNames[i];
            lvColumn.cx = columnWidths[i];
            ListView_InsertColumn(hWndListView, i, &lvColumn);
        }

        // Заполнение ListView данными из базы данных
        FillListViewFromDatabase(hWndListView);

        return (INT_PTR)TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;

    case WM_CLOSE:{
        EndDialog(hDlg, IDCANCEL);
        return (INT_PTR)TRUE; }
        break;

    case WM_DESTROY:
        if (db != nullptr) {
            sqlite3_close(db);
            db = nullptr;
        }
        //PostQuitMessage(0);
        break;
    }
    return (INT_PTR)FALSE;
}

// Обработчик сообщений для окна "О программе".
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}
