// main.cpp
// Build: cl /EHsc /MD main.cpp iphlpapi.lib ws2_32.lib Shlwapi.lib Advapi32.lib
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <http.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <Shlwapi.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winreg.h>

#pragma comment(lib, "httpapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")

static const std::wstring REG_KEY = L"SOFTWARE\\AgentExample";
static const std::wstring REG_VAL = L"Token";
static const std::wstring BASE_DIR = L"C:\\AgentFiles"; // can be changed or read from registry

// Helper: read token from registry or env
std::wstring GetAuthToken()
{
    HKEY hKey = nullptr;
    std::wstring token;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD type = 0;
        WCHAR buf[512]; DWORD cb = sizeof(buf);
        if (RegQueryValueExW(hKey, REG_VAL.c_str(), NULL, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS && type == REG_SZ) {
            token = buf;
        }
        RegCloseKey(hKey);
    }
    if (token.empty()) {
        DWORD len = GetEnvironmentVariableW(L"AGENT_TOKEN", NULL, 0);
        if (len) {
            std::vector<wchar_t> buf(len);
            GetEnvironmentVariableW(L"AGENT_TOKEN", buf.data(), len);
            token = buf.data();
        }
    }
    return token;
}

// Simple URL-decoder
std::wstring UrlDecode(const std::wstring& s)
{
    std::wstring out;
    for (size_t i=0;i<s.size();++i) {
        if (s[i] == L'%' && i+2 < s.size()) {
            wchar_t hi = s[i+1], lo = s[i+2];
            wchar_t hex[3] = {hi, lo, 0};
            wchar_t* end = nullptr;
            int val = wcstol(hex, &end, 16);
            out.push_back((wchar_t)val);
            i += 2;
        } else if (s[i] == L'+') out.push_back(L' ');
        else out.push_back(s[i]);
    }
    return out;
}

// Combine base dir and user path and ensure sandbox
bool ResolvePath(const std::wstring& base, const std::wstring& rel, std::wstring& out)
{
    wchar_t combined[MAX_PATH];
    PathCombineW(combined, base.c_str(), rel.c_str());
    wchar_t full[MAX_PATH];
    if (GetFullPathNameW(combined, MAX_PATH, full, NULL) == 0) return false;
    wchar_t baseFull[MAX_PATH];
    if (GetFullPathNameW(base.c_str(), MAX_PATH, baseFull, NULL) == 0) return false;
    if (_wcsnicmp(full, baseFull, wcslen(baseFull)) != 0) return false;
    out = full;
    return true;
}

// Send a simple HTTP response
ULONG SendSimpleResponse(HTTP_REQUEST_ID requestId, HTTP_RESPONSE* pResp, const std::string& body, USHORT statusCode = 200)
{
    HTTP_DATA_CHUNK chunk;
    chunk.DataChunkType = HttpDataChunkFromMemory;
    chunk.FromMemory.pBuffer = (PVOID)body.c_str();
    chunk.FromMemory.BufferLength = (ULONG)body.size();

    HTTP_RESPONSE response;
    RtlZeroMemory(&response, sizeof(response));
    response.StatusCode = statusCode;
    response.pEntityChunks = &chunk;
    response.EntityChunkCount = 1;

    ULONG bytesSent = 0;
    return HttpSendHttpResponse(NULL, requestId, 0, &response, NULL, &bytesSent, NULL, 0, NULL, NULL);
}

// Helper to build JSON arrays and objects (very small helpers)
std::string JsonEscape(const std::string& s) {
    std::string out; out.reserve(s.size()*1.2);
    for (char c: s) {
        switch(c) {
        case '\"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out.push_back(c); break;
        }
    }
    return out;
}

// Build process list JSON
std::string GetProcessListJson()
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "[]";
    std::ostringstream ss;
    ss << "[";
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    BOOL first = TRUE;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (!first) ss << ",";
            first = FALSE;
            // Convert name to UTF-8
            int len = WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,NULL,0,NULL,NULL);
            std::string name(len,0);
            WideCharToMultiByte(CP_UTF8,0,pe.szExeFile,-1,&name[0],len,NULL,NULL);
            // trim trailing NUL
            if (!name.empty() && name.back()==0) name.pop_back();
            ss << "{\"id\":" << pe.th32ProcessID << ",\"name\":\"" << JsonEscape(name) << "\"}";
        } while (Process32NextW(snap, &pe));
    }
    ss << "]";
    CloseHandle(snap);
    return ss.str();
}

// Net info JSON using GetExtendedTcpTable/GetExtendedUdpTable
std::string GetNetJson()
{
    std::ostringstream ss;
    // TCP connections
    PMIB_TCPTABLE_OWNER_PID tcpTable = NULL;
    ULONG size = 0;
    if (GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == ERROR_INSUFFICIENT_BUFFER) {
        tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
        if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            ss << "{\"tcpConnections\":[";
            for (DWORD i=0;i<tcpTable->dwNumEntries;i++) {
                PMIB_TCPROW_OWNER_PID row = &tcpTable->table[i];
                IN_ADDR la; la.S_un.S_addr = row->dwLocalAddr;
                IN_ADDR ra; ra.S_un.S_addr = row->dwRemoteAddr;
                char local[64], remote[64];
                sprintf_s(local, "%s:%u", inet_ntoa(la), ntohs((u_short)row->dwLocalPort));
                sprintf_s(remote, "%s:%u", inet_ntoa(ra), ntohs((u_short)row->dwRemotePort));
                if (i) ss << ",";
                ss << "{\"local\":\"" << local << "\",\"remote\":\"" << remote << "\",\"state\":" << row->dwState << ",\"pid\":" << row->dwOwningPid << "}";
            }
            ss << "],";
        }
        free(tcpTable);
    }
    // UDP listeners
    PMIB_UDPTABLE_OWNER_PID udpTable = NULL;
    size = 0;
    if (GetExtendedUdpTable(NULL, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == ERROR_INSUFFICIENT_BUFFER) {
        udpTable = (PMIB_UDPTABLE_OWNER_PID)malloc(size);
        if (GetExtendedUdpTable(udpTable, &size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
            ss << "\"udpListeners\":[";
            for (DWORD i=0;i<udpTable->dwNumEntries;i++) {
                MIB_UDPROW_OWNER_PID row = udpTable->table[i];
                IN_ADDR la; la.S_un.S_addr = row.dwLocalAddr;
                char local[64];
                sprintf_s(local, "%s:%u", inet_ntoa(la), ntohs((u_short)row.dwLocalPort));
                if (i) ss << ",";
                ss << "\"" << local << "\"";
            }
            ss << "]";
        }
        free(udpTable);
    } else {
        ss << "\"udpListeners\":[]";
    }
    ss << "}";
    return ss.str();
}

// Read query parameter value by name
std::wstring GetQueryParam(PCWSTR query, PCWSTR name)
{
    if (!query) return L"";
    std::wstring q = query;
    size_t pos = q.find(name);
    if (pos==std::wstring::npos) return L"";
    pos += wcslen(name);
    if (pos >= q.size() || q[pos] != L'=') return L"";
    pos++;
    size_t end = q.find(L'&', pos);
    std::wstring val = (end==std::wstring::npos) ? q.substr(pos) : q.substr(pos, end-pos);
    return UrlDecode(val);
}

int wmain()
{
    wprintf(L"Starting VibeRATor!\n");
    std::wstring token = GetAuthToken();
    CreateDirectoryW(BASE_DIR.c_str(), NULL);
    wprintf(L"[+] Base Dir Exists\n");

    // Initialize HTTP Server API
    ULONG ret = HttpInitialize(HTTPAPI_VERSION_1, HTTP_INITIALIZE_SERVER, NULL);
    if (ret != NO_ERROR) {
        wprintf(L"HttpInitialize failed %u\n", ret);
        return 1;
    }
    wprintf(L"[+] HttpInit\n");
    // Create URL group and listener
    HTTP_SERVER_SESSION_ID sessionId = 0;
    HTTP_URL_GROUP_ID urlGroupId = 0;
    //HTTP_LISTENER_REQUEST_ID reqId = 0;

    // Create a server session
    HttpCreateServerSession(HTTPAPI_VERSION_1, &sessionId, 0);
    wprintf(L"ServerSession Created\n");
    // Create a URL group
    HttpCreateUrlGroup(sessionId, &urlGroupId, 0);
    wprintf(L"Url Group Created\n");

    // Add URL: use localhost binding by default; change to 0.0.0.0:5000 if needed
    PCWSTR url = L"http://0.0.0.0:5000/"; // restrict via firewall or change to 127.0.0.1:5000
    HttpAddUrlToUrlGroup(urlGroupId, url, 0, 0);
    wprintf(L"Url added to URL Group\n");

    // Create request queue and set url group
    HANDLE reqQueue = NULL;
    HttpCreateHttpHandle(&reqQueue, 0); // use HttpCreateRequestQueue on older SDKs
    wprintf(L"HttpCreateHttpHandle\n");
    // Newer approach: HttpCreateRequestQueue not available; but for compactness, use HttpCreateRequestQueue in practice.
    // For simplicity in this sample, use HttpCreateRequestQueueA via header shim. In production use full error checks and correct APIs.

    // Use HttpCreateRequestQueue (older API) for single-file example
    HTTP_SERVER_SESSION_ID tmpSess=0;
    //HANDLE hReqQueue = CreateThreadpoolIo(NULL, NULL, NULL, NULL); // dummy to avoid compile issues; replace below with proper request queue creation in production
    //wprintf(L"CreateThreadpoolIo\n");
    // Fallback: We'll use HttpReceiveHttpRequest in a loop with a request handle created by HttpCreateRequestQueue (omitted here).
    // Due to complexity of full http.sys setup in a single snippet, implement a simple WinSock HTTP listener here instead.

    // Simple socket-based HTTP listener (synchronous, single-threaded)
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in sa; sa.sin_family = AF_INET; sa.sin_port = htons(5000); sa.sin_addr.s_addr = INADDR_ANY;
    bind(listenSock, (sockaddr*)&sa, sizeof(sa));
    listen(listenSock, SOMAXCONN);
    wprintf(L"Listening on port 5000\n");

    while (true) {
        SOCKET cl = accept(listenSock, NULL, NULL);
        if (cl == INVALID_SOCKET) break;

        // read request (very naive, sufficient for small payloads)
        std::string req;
        char buf[8192];
        int r = recv(cl, buf, sizeof(buf), 0);
        if (r <= 0) { closesocket(cl); continue; }
        req.append(buf, r);

        // parse request line
        std::istringstream rs(req);
        std::string method, urlpath, version;
        rs >> method >> urlpath >> version;

        // parse headers, look for Authorization and Content-Length
        std::string line;
        std::string authHeader;
        size_t contentLen = 0;
        while (std::getline(rs, line) && line != "\r") {
            if (line.size() > 0 && line.back()=='\r') line.pop_back();
            std::string lower = line;
            for (auto &c: lower) c = tolower(c);
            if (lower.rfind("authorization:",0) == 0) {
                authHeader = line.substr(strlen("authorization:"));
                // trim
                while (!authHeader.empty() && (authHeader.front()==' '||authHeader.front()=='\t')) authHeader.erase(authHeader.begin());
            }
            if (lower.rfind("content-length:",0) == 0) {
                std::string v = line.substr(strlen("content-length:"));
                while (!v.empty() && (v.front()==' '||v.front()=='\t')) v.erase(v.begin());
                contentLen = std::stoul(v);
            }
        }

        // Simple auth check
        bool authorized = false;
        if (!token.empty()) {
            std::string expect = "Bearer ";
            // convert token to UTF8
            int len = WideCharToMultiByte(CP_UTF8,0,token.c_str(),-1,NULL,0,NULL,NULL);
            std::string tokenUtf(len,0); WideCharToMultiByte(CP_UTF8,0,token.c_str(),-1,&tokenUtf[0],len,NULL,NULL);
            if (!tokenUtf.empty() && tokenUtf.back()==0) tokenUtf.pop_back();
            if (!authHeader.empty()) {
                if (authHeader.find(expect + tokenUtf) != std::string::npos) authorized = true;
            }
        } else {
            authorized = true; // no token configured -> allow (not recommended)
        }

        if (!authorized) {
            std::string resp = "HTTP/1.1 401 Unauthorized\r\nContent-Length:0\r\n\r\n";
            send(cl, resp.c_str(), (int)resp.size(), 0);
            closesocket(cl);
            continue;
        }

        // split urlpath into path and query
        std::string pathPart = urlpath;
        std::string queryPart;
        size_t qpos = pathPart.find('?');
        if (qpos != std::string::npos) {
            queryPart = pathPart.substr(qpos+1);
            pathPart = pathPart.substr(0,qpos);
        }

        // handle endpoints
        if (method=="GET" && pathPart=="/processes") {
            std::string body = GetProcessListJson();
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
            std::string s = resp.str();
            send(cl, s.c_str(), (int)s.size(), 0);
        } else if (method=="GET" && pathPart=="/net") {
            std::string body = GetNetJson();
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
            std::string s = resp.str();
            send(cl, s.c_str(), (int)s.size(), 0);
        } else if ((method=="GET" || method=="DELETE" || method=="POST") && pathPart=="/file") {
            // parse query for path=...
            std::wstring qutf;
            {
                // convert queryPart to wide
                int len = MultiByteToWideChar(CP_UTF8,0,queryPart.c_str(),-1,NULL,0);
                std::wstring wq(len,0);
                MultiByteToWideChar(CP_UTF8,0,queryPart.c_str(),-1,&wq[0],len);
                if (!wq.empty() && wq.back()==0) wq.pop_back();
                qutf = wq;
            }
            std::wstring rawPath = GetQueryParam(qutf.c_str(), L"path");
            if (rawPath.empty()) {
                std::string body = "{\"error\":\"missing path\"}";
                std::ostringstream resp;
                resp << "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
                std::string s = resp.str();
                send(cl, s.c_str(), (int)s.size(), 0);
                closesocket(cl);
                continue;
            }
            std::wstring resolved;
            if (!ResolvePath(BASE_DIR, rawPath, resolved)) {
                std::string body = "{\"error\":\"forbidden path\"}";
                std::ostringstream resp;
                resp << "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
                std::string s = resp.str();
                send(cl, s.c_str(), (int)s.size(), 0);
                closesocket(cl);
                continue;
            }

            if (method=="GET") {
                HANDLE h = CreateFileW(resolved.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (h==INVALID_HANDLE_VALUE) {
                    std::string body = "{\"error\":\"not found\"}";
                    std::ostringstream resp;
                    resp << "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
                    std::string s = resp.str();
                    send(cl, s.c_str(), (int)s.size(), 0);
                } else {
                    LARGE_INTEGER size; GetFileSizeEx(h, &size);
                    std::ostringstream header;
                    header << "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: " << (unsigned long long)size.QuadPart << "\r\n\r\n";
                    std::string hdr = header.str();
                    send(cl, hdr.c_str(), (int)hdr.size(), 0);
                    const int chunk = 64*1024;
                    std::vector<char> buffer(chunk);
                    DWORD read = 0;
                    while (ReadFile(h, buffer.data(), chunk, &read, NULL) && read>0) {
                        send(cl, buffer.data(), read, 0);
                    }
                    CloseHandle(h);
                }
            } else if (method=="DELETE") {
                if (DeleteFileW(resolved.c_str())) {
                    std::string body = "{\"result\":\"deleted\"}";
                    std::ostringstream resp;
                    resp << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
                    std::string s = resp.str();
                    send(cl, s.c_str(), (int)s.size(), 0);
                } else {
                    std::string body = "{\"error\":\"not found or delete failed\"}";
                    std::ostringstream resp;
                    resp << "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
                    std::string s = resp.str();
                    send(cl, s.c_str(), (int)s.size(), 0);
                }
            } else if (method=="POST") {
                // find body start
                size_t headerEnd = req.find("\r\n\r\n");
                std::string bodyPart;
                if (headerEnd != std::string::npos) {
                    headerEnd += 4;
                    // remaining already read
                    bodyPart = req.substr(headerEnd);
                    // if contentLen > bodyPart.size(), read remaining from socket
                    while (bodyPart.size() < contentLen) {
                        int rr = recv(cl, buf, sizeof(buf), 0);
                        if (rr <= 0) break;
                        bodyPart.append(buf, rr);
                    }
                }
                // write file
                // create directories if needed
                std::wstring dir = resolved;
                PathRemoveFileSpecW((LPWSTR)dir.c_str());
                // ensure parent directory exists
                // naive: call CreateDirectory recursively could be added; for brevity assume parent exists or base dir structure is present
                HANDLE h = CreateFileW(resolved.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                if (h == INVALID_HANDLE_VALUE) {
                    std::string rsp = "{\"error\":\"write failed\"}";
                    std::ostringstream resp;
                    resp << "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: " << rsp.size() << "\r\n\r\n" << rsp;
                    std::string s = resp.str();
                    send(cl, s.c_str(), (int)s.size(), 0);
                } else {
                    DWORD written = 0;
                    WriteFile(h, bodyPart.data(), (DWORD)bodyPart.size(), &written, NULL);
                    CloseHandle(h);
                    std::string rsp = "{\"result\":\"ok\",\"size\":" + std::to_string(written) + "}";
                    std::ostringstream resp;
                    resp << "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " << rsp.size() << "\r\n\r\n" << rsp;
                    std::string s = resp.str();
                    send(cl, s.c_str(), (int)s.size(), 0);
                }
            }
        } else {
            std::string body = "{\"error\":\"unknown endpoint\"}";
            std::ostringstream resp;
            resp << "HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: " << body.size() << "\r\n\r\n" << body;
            std::string s = resp.str();
            send(cl, s.c_str(), (int)s.size(), 0);
        }

        closesocket(cl);
    }

    closesocket(listenSock);
    WSACleanup();
    HttpTerminate(HTTP_INITIALIZE_SERVER, NULL);
    return 0;
}