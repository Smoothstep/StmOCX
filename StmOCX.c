/*
	This file has not been modified since 2015.

	Chances are low that any generated value does not apply any longer to
	the aspects of the current used methods of printing device tokens because any change
	to the core would also invalidate all data records from the owner's database, which were 
	created before the change has happened.

	Many web-based implementations rely on temporary data. Therefore it would be beneficial
	to remove any flash tokens and browser internal-database entries after visiting a site which uses iesnare.

	Note:
	Chrome's inbuilt incognito mode can be useful when dealing with registration problems.
	Some sites blacklist IP addresses from malicious devices.
*/

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#pragma comment(lib, "Rpcrt4.lib")

typedef int(*TStmOCX)(char**);

static char* GetBlackboxToken()
{
	FARPROC fIoBegin;
	char* token;
	HMODULE hModule = GetModuleHandle(L"StmOCX.dll");

	if (!hModule)
	{
		hModule = LoadLibrary(L"StmOCX.dll");

		if (!hModule)
		{
			return NULL;
		}
	}

	fIoBegin = GetProcAddress(hModule, "io_Begin");

	if (!fIoBegin)
	{
		return NULL;
	}

	if ((TStmOCX)(fIoBegin)(&token) == -1)
	{
		return NULL;
	}

	return token;
}

void RemoveReg()
{
	RegDeleteKey(HKEY_CLASSES_ROOT, L"CLSID\\{D06F0FFC-A2E7-D06D-DC03-A7A4470A5F49}\\{CDADA18F-6E19-2167-CF33-24CACB5E3D15}");
	RegDeleteKey(HKEY_CLASSES_ROOT, L"CLSID\\{EA4F5CEC-BC42-4b64-8B18-EFFC62ADDA31}");
	RegDeleteKey(HKEY_CLASSES_ROOT, L"CLSID\\{4287694D-708B-B28D-501C-C5EB6CFDEA65}");
	RegDeleteKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\ProgramChecksum");
	RegDeleteKey(HKEY_CLASSES_ROOT, L"CLSID\\{C6CC27F6-AEE9-96CB-19F0-3F41A577F343}\\{358424AA-3F12-E6E5-E815-7C3B8BBAD991}");
	RegDeleteKey(HKEY_LOCAL_MACHINE, L"CLSID\\{EA4F5CEC-BC42-4b64-8B18-EFFC62ADDA31}");
}

HANDLE GetModuleInfo(MODULEENTRY32W* mod32, unsigned pId, const wchar_t* pModuleName)
{
	HANDLE hSnap = INVALID_HANDLE_VALUE;

	if ((hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pId)) == INVALID_HANDLE_VALUE)
	{
		return hSnap;
	}

	mod32->dwSize = sizeof(MODULEENTRY32);

	while (Module32Next(hSnap, mod32))
	{
		if (wcscmp(pModuleName, mod32->szModule) == 0)
		{
			CloseHandle(hSnap);
			return hSnap;
		}
	}

	CloseHandle(hSnap);

	return INVALID_HANDLE_VALUE;
}

// Only used as a buffer for AES key and other object variables.
struct SAes
{
	unsigned char d[0x1000];
};

struct SPath
{
	char* p0;
	char* p1;
};

struct SPath CreatePath()
{
	struct SPath p;
	p.p0 = (char*)0x1001E4E4;
	p.p1 = 0;

	return p;
}

char* CopyData(char* p, unsigned s, unsigned terminate)
{
	char* r;

	if (p == NULL)
	{
		return 0;
	}

	if (s == 0)
	{
		s = strlen(p);
	}

	if (s)
	{
		r = (char*)(malloc(s));

		if (r == NULL)
		{
			return 0;
		}

		memcpy(r, p, s);

		if (terminate == 1)
		{
			r[s - 1] = 0;
		}

		return r;
	}

	return 0;
}

typedef struct SPath*(__cdecl*THash)(struct SPath*, char*, int);
typedef struct SPath*(__cdecl*TConcat)(struct SPath*, char*, struct SPath*);
typedef int(__thiscall*TAesSetKey)(struct SAes*, unsigned char*, int);
typedef char*(__thiscall*TAesCryptMD5)(struct SAes*, char*, unsigned, int*);
typedef int(__thiscall*TAesBegin)(struct SAes*, char, char*, int, char);
typedef void(__thiscall*TDestruct)(struct SPath*);
typedef void(__cdecl*TFree)(char*);
typedef int(__thiscall*TCopyTo)(struct SPath*, struct SPath*);
typedef char(__cdecl*TInitPath)(struct SPath*, int);
typedef void(__thiscall*TCopy)(struct SPath*, struct SPath*);

static THash Hash;
static TAesSetKey SetAESKey;
static TAesCryptMD5 AESMD5;
static TAesBegin AESInit;
static TDestruct Destruct;
static TFree Free;
static TCopyTo CopyTo;
static TCopy Copy;
static TInitPath PathInit;
static TConcat Concat;

enum Offsets
{
	RVAHash = 0x6BD0,
	RVAAESSetKey = 0x6D80,
	RVAAESMD5Crypt = 0x6F40,
	RVAAESInit = 0x6EC0,
	RVADestruct = 0x6330,
	RVAFree = 0x12276,
	RVACopy = 0x6270,
	RVACopyTo = 0x6610,
	RVAPathInit = 0x6A60,
	RVAConcat = 0x69B0,
	RVAAesObject = 0x273C8,
	RVAAesObjectBody = 0x27660
};

struct StmOCX
{
	BYTE* AesStruct;
	BYTE* AesBodyStruct;
	HMODULE Module;
};

char LoadStmModule(struct StmOCX * pStmOcx)
{
	if (pStmOcx->Module)
	{
		return 1;
	}

	pStmOcx->Module = GetModuleHandle(L"StmOCX.dll");

	if (!pStmOcx->Module)
	{
		pStmOcx->Module = LoadLibrary(L"StmOCX.dll");
	}

	return pStmOcx->Module != NULL;
}

char InitializeFunctionPointers(struct StmOCX * pStmOcx)
{
	MODULEENTRY32W info;

	if (GetModuleInfo(&info, GetCurrentProcessId(), L"StmOCX.dll") == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	Hash = (THash)(info.modBaseAddr + RVAHash);
	SetAESKey = (TAesSetKey)(info.modBaseAddr + RVAAESSetKey);
	AESMD5 = (TAesCryptMD5)(info.modBaseAddr + RVAAESMD5Crypt);
	AESInit = (TAesBegin)(info.modBaseAddr + RVAAESInit);
	Destruct = (TDestruct)(info.modBaseAddr + RVADestruct);
	Free = (TFree)(info.modBaseAddr + RVAFree);
	CopyTo = (TCopyTo)(info.modBaseAddr + RVACopyTo);
	Copy = (TCopy)(info.modBaseAddr + RVACopy);
	PathInit = (TInitPath)(info.modBaseAddr + RVAPathInit);
	Concat = (TConcat)(info.modBaseAddr + RVAConcat);

	pStmOcx->AesStruct = info.modBaseAddr + RVAAesObject;
	pStmOcx->AesBodyStruct = info.modBaseAddr + RVAAesObjectBody;

	return 1;
}

char* Md5Aes(struct SPath* pResult, BYTE* pAes, char* pTimeCopy, char* pInput, unsigned iSize, char bReverse, char* pAdd)
{
	struct SAes aes;
	char* pMD5Aes;
	int iLen;
	struct SPath result = CreatePath();
	struct SPath pOld = CreatePath();

	if (!SetAESKey(&aes, pAes, 16))
	{
		return NULL;
	}

	if (!AESInit(&aes, bReverse, pTimeCopy, 16, 1))
	{
		return NULL;
	}

	pMD5Aes = AESMD5(&aes, pInput, iSize, &iLen);

	if (!pMD5Aes)
	{
		return NULL;
	}

	if (!Hash(&result, pMD5Aes, iLen))
	{
		return NULL;
	}

	Free(pMD5Aes);

	if (pAdd)
	{
		if (!Concat(&pOld, pAdd, &result))
		{
			Destruct(&result);
			return NULL;
		}

		CopyTo(&result, &pOld);
		Destruct(&pOld);
		Copy(pResult, &result);

		return pResult->p1;
	}

	Copy(pResult, &result);

	return pResult->p1;
}

char* GenerateUUIDToken(struct StmOCX * pStmOcx, char* pTime)
{
	UUID Uuid;
	SYSTEMTIME sysTime;
	char uuid[65];
	char* pCopy;
	char* pResult;
	struct SPath path = CreatePath();

	if (pTime == NULL)
	{
		pTime = malloc(24);
		{
			GetSystemTime(&sysTime);
		}

		if (!snprintf(pTime, 24, "%04d %02d %02d %02d:%02d:%02d.%03d",
			sysTime.wYear,
			sysTime.wDay,
			sysTime.wMonth,
			sysTime.wHour,
			sysTime.wMinute,
			sysTime.wSecond,
			sysTime.wMilliseconds))
		{
			return NULL;
		}
	}

	if (!!UuidCreate(&Uuid))
	{
		return NULL;
	}

	if (!snprintf(uuid, 65, "%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
		Uuid.Data1,
		Uuid.Data2,
		Uuid.Data3,
		Uuid.Data4[0],
		Uuid.Data4[1],
		Uuid.Data4[2],
		Uuid.Data4[3],
		Uuid.Data4[4],
		Uuid.Data4[5],
		Uuid.Data4[6],
		Uuid.Data4[7]))
	{
		return NULL;
	}

	pCopy = CopyData(pTime, 16, 1);

	if (!pCopy)
	{
		return NULL;
	}

	pResult = Md5Aes(&path, pStmOcx->AesStruct, pCopy, uuid, strlen(uuid) + 1, 0, 0);

	if (!pResult)
	{
		free(pCopy);
		return NULL;
	}

	pResult = CopyData(pResult, strlen(pResult) + 1, 1);

	Destruct(&path);
	free(pCopy);

	return pResult;
}

struct DeviceSignature
{
	char* Header;
	char* Size;

	unsigned DateTimeSize;
	char DateTime[24];

	unsigned Unk_0;

	unsigned SNPR1ValueSize;
	char* SNPR1Value;

	unsigned Unk_1;
	unsigned Unk_2;

	unsigned VersionSize;
	char* Version;

	unsigned Unk_3;

	unsigned WMPLValueSize;
	char* WMPLValue;

	unsigned WPIDValueSize;
	char* WPIDValue;

	unsigned WINDValue;

	unsigned IEIDValueSize;
	char* IEIDValue;

	unsigned ROWNValueSize;
	char* ROWNValue;

	unsigned RORGValueSize;
	char* RORGValue;

	unsigned HDMNValueSize;
	char* HDMNValue;

	unsigned HDSNValueSize;
	char* HDSNValue;

	unsigned HDIDValueSize;
	char* HDIDValue;

	unsigned WKEYValueSize;
	char* WKEYValue;

	unsigned EUIPValueSize;
	char* EUIPValue;

	unsigned MACAValueSize;
	char* MACAValue;

	unsigned WVERValueSize;
	char* WVERValue;

	unsigned IEVRValueSize;
	char* IEVRValue;

	unsigned SVMWValueSize;
	char* SVMWValue;

	unsigned SVPCValueSize;
	char* SVPCValue;

	unsigned SDBGValue;

	unsigned SICEValueSize;
	char* SICEValue;

	unsigned SRMNValue;

	unsigned REGXValueSize;
	char* REGXValue;
};


#define ValueFormatString(pBuffer, pFormat, iMax, vaList) snprintf(pBuffer, iMax, pFormat, vaList)

char* HashBody(struct DeviceSignature * pDeviceSignature, struct StmOCX * pStmOcx, char* pSignature, unsigned iLen)
{
	struct SPath path;
	char* pResult;
	char* pCopy = CopyData(pDeviceSignature->DateTime, 16, 0);

	if (!pCopy)
	{
		return NULL;
	}

	pResult = Md5Aes(&path, pStmOcx->AesBodyStruct, pCopy, pSignature, iLen, 1, "0200");

	if (!pResult)
	{
		free(pCopy);
		return NULL;
	}

	free(pCopy);

	return pResult;
}

struct DeviceSignature * CreateDeviceSignature()
{
	struct DeviceSignature * signature = malloc(sizeof(struct DeviceSignature));

	signature->DateTimeSize = 23;
	signature->Unk_1 = 0;
	signature->Unk_2 = 0;
	signature->Unk_3 = 0x15;
	signature->VersionSize = 9;
	signature->Version = "2.70.0002";
	signature->WMPLValueSize = 0;
	signature->WMPLValue = 0;
	signature->WPIDValueSize = 0;
	signature->WPIDValue = 0;
	signature->WINDValue = 0;
	signature->IEIDValue = 0;
	signature->IEIDValueSize = 0;
	signature->ROWNValue = 0;
	signature->ROWNValueSize = 0;
	signature->RORGValue = 0;
	signature->RORGValueSize = 0;
	signature->HDMNValue = 0;
	signature->HDMNValueSize = 0;
	signature->HDSNValue = 0;
	signature->HDSNValueSize = 0;
	signature->HDIDValue = 0;
	signature->HDIDValueSize = 0;
	signature->WKEYValue = 0;
	signature->WKEYValueSize = 0;
	signature->EUIPValue = 0;
	signature->EUIPValueSize = 0;
	signature->MACAValue = 0;
	signature->MACAValueSize = 0;
	signature->WVERValue = 0;
	signature->WVERValueSize = 0;
	signature->IEVRValue = 0;
	signature->IEVRValueSize = 0;
	signature->SVMWValue = 0;
	signature->SVMWValueSize = 0;
	signature->SVPCValue = 0;
	signature->SVPCValueSize = 0;
	signature->SDBGValue = 0x11;
	signature->SICEValue = 0;
	signature->SICEValueSize = 0;
	signature->SRMNValue = 0;
	signature->REGXValue = 0;
	signature->REGXValueSize = 0;

	return signature;
}

static char* RandomString(char* pString)
{
	srand(time(0));

	for (unsigned i = 0; i < strlen(pString); ++i)
	{
		if (pString[i] >= '0' && pString[i] <= '9')
			pString[i] = rand() % ('9' - '0' + 1) + '0';
		else if (pString[i] >= 'a' && pString[i] <= 'f')
			pString[i] = rand() % ('f' - 'a' + 1) + 'a';
		else if (pString[i] >= 'A' && pString[i] <= 'F')
			pString[i] = rand() % ('F' - 'A' + 1) + 'A';
	}

	return pString;
}


char* CreateSignature(struct DeviceSignature * pDeviceSignature)
{
	char szSize[5];
	unsigned iOffset = 0;
	char * szSignature = malloc(1024);
	{
		iOffset += ValueFormatString(szSignature, "%s", 1024, pDeviceSignature->Header);
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, 0);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->DateTimeSize);
		if (pDeviceSignature->DateTime)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->DateTime);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->Unk_0);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("SNPR1"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "SNPR1");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->SNPR1ValueSize);
		if (pDeviceSignature->SNPR1Value)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->SNPR1Value);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->Unk_1);
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->Unk_2);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->VersionSize);
		if (pDeviceSignature->Version)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->Version);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->Unk_3);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("WMPL"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "WMPL");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->WMPLValueSize);
		if (pDeviceSignature->WMPLValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->WMPLValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("WPID"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "WPID");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->WPIDValueSize);
		if (pDeviceSignature->WPIDValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->WPIDValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("WIND"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "WIND");
		iOffset += ValueFormatString(szSignature + iOffset, "%05X", 1024 - iOffset, pDeviceSignature->WINDValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("IEID"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "IEID");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->IEIDValueSize);
		if (pDeviceSignature->IEIDValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->IEIDValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("ROWN"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "ROWN");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->ROWNValueSize);
		if (pDeviceSignature->ROWNValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->ROWNValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("RORG"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "RORG");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->RORGValueSize);
		if (pDeviceSignature->RORGValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->RORGValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("HDMN"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "HDMN");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->HDMNValueSize);
		if (pDeviceSignature->HDMNValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->HDMNValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("HDSN"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "HDSN");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->HDSNValueSize);
		if (pDeviceSignature->HDSNValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->HDSNValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("HDID"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "HDID");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->HDIDValueSize);
		if (pDeviceSignature->HDIDValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->HDIDValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("WKEY"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "WKEY");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->WKEYValueSize);
		if (pDeviceSignature->WKEYValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->WKEYValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("EUIP"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "EUIP");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->EUIPValueSize);
		if (pDeviceSignature->EUIPValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->EUIPValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("MACA"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "MACA");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->MACAValueSize);
		if (pDeviceSignature->MACAValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->MACAValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("WVER"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "WVER");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->WVERValueSize);
		if (pDeviceSignature->WVERValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->WVERValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("IEVR"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "IEVR");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->IEVRValueSize);
		if (pDeviceSignature->IEVRValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->IEVRValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("SVMW"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "SVMW");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->SVMWValueSize);
		if (pDeviceSignature->SVMWValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->SVMWValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("SVPC"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "SVPC");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->SVPCValueSize);
		if (pDeviceSignature->SVPCValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->SVPCValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("SDBG"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "SDBG");
		iOffset += ValueFormatString(szSignature + iOffset, "%05X", 1024 - iOffset, pDeviceSignature->SDBGValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("SICE"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "SICE");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->SICEValueSize);
		if (pDeviceSignature->SICEValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->SICEValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("SRMN"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "SRMN");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->SRMNValue);

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("BBSC"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "BBSC");

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("WDLL"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "WDLL");

		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, strlen("REGX"));
		iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, "REGX");
		iOffset += ValueFormatString(szSignature + iOffset, "%04X", 1024 - iOffset, pDeviceSignature->REGXValueSize);
		if (pDeviceSignature->REGXValue)
			iOffset += ValueFormatString(szSignature + iOffset, "%s", 1024 - iOffset, pDeviceSignature->REGXValue);

		ValueFormatString(szSize, "%04X", 5, iOffset);

		memcpy(szSignature + 4, szSize, 4);
	}

	return szSignature;
}

char* GenerateRandomSignature(struct StmOCX * pStmOcx, struct DeviceSignature * pDeviceSignature)
{
	SYSTEMTIME sysTime;
	char hdsn[] = "S21PNXAG569165Y";
	char hdid[] = "c7f582ad-db20207b-A";
	char maca[] = "F3-D5-6C-78-9B-00";
	GetSystemTime(&sysTime);

	pDeviceSignature->Header = "0200";

	if (!snprintf(pDeviceSignature->DateTime, 24, "%04d %02d %02d %02d:%02d:%02d.%03d",
		sysTime.wYear,
		sysTime.wDay,
		sysTime.wMonth,
		sysTime.wHour,
		sysTime.wMinute,
		sysTime.wSecond,
		sysTime.wMilliseconds))
	{
		return NULL;
	}

	pDeviceSignature->SNPR1Value = GenerateUUIDToken(pStmOcx, pDeviceSignature->DateTime);
	pDeviceSignature->SNPR1ValueSize = strlen(pDeviceSignature->SNPR1Value);

	pDeviceSignature->HDMNValue = "Samsung SSD 850 EVO 250GB";
	pDeviceSignature->HDMNValueSize = 0x19;

	pDeviceSignature->HDSNValue = RandomString(hdsn);
	pDeviceSignature->HDSNValueSize = 0x0F;

	pDeviceSignature->HDIDValue = RandomString(hdid);
	pDeviceSignature->HDIDValueSize = 0x13;

	pDeviceSignature->MACAValue = RandomString(maca);
	pDeviceSignature->MACAValueSize = 0x11;

	pDeviceSignature->WVERValue = "2.6.2.9200 ()";
	pDeviceSignature->WVERValueSize = 0x0D;

	pDeviceSignature->IEVRValue = "10.0.10011";
	pDeviceSignature->IEVRValueSize = 0x0A;

	return CreateSignature(pDeviceSignature);
}

BOOL IsElevated() 
{
	TOKEN_ELEVATION Elevation;
	DWORD cbSize;
    BOOL bRet;
    HANDLE hToken = NULL;

    if(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hToken)) 
	{
        if(GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) 
		{
			bRet = Elevation.TokenIsElevated;
        }
		else
		{
			bRet = FALSE;
		}

		CloseHandle(hToken);
    }
	else
	{
		bRet = FALSE;
	}

    return bRet;
}

int main()
{
	char* psig, *hash;
	FILE* pOut;
	struct DeviceSignature * signature = CreateDeviceSignature();
	struct StmOCX stmOcx;

	stmOcx.AesBodyStruct = 0;
	stmOcx.AesStruct = 0;
	stmOcx.Module = 0;

	if (!IsElevated())
	{
		printf("Admin rights are most likely required.\n");
	}

	RemoveReg();

	LoadStmModule(&stmOcx);

	if (!InitializeFunctionPointers(&stmOcx))
	{
		printf("Failed to initialize StmOCX.\n");
		_fgetchar();
		return -1;
	}

	psig = GenerateRandomSignature(&stmOcx, signature);
	hash = HashBody(signature, &stmOcx, psig, strlen(psig) + 1);

	if (!hash)
	{
		printf("Failed to generate hash.\n");
		_fgetchar();
		return -2;
	}

	printf("Hash: %s\n", hash);

	fopen_s(&pOut, "hash.txt", "w+");

	if (!pOut)
	{
		printf("Unable to write hash to: hash.txt.\n");
		_fgetchar();
		return -3;
	}

	fwrite(hash, strlen(hash), 1, pOut);
	fclose(pOut);

	RemoveReg();

	_fgetchar();

	return 0;
}