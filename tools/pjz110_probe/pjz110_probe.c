typedef unsigned char      UINT8;
typedef unsigned short     UINT16;
typedef unsigned int       UINT32;
typedef unsigned long long UINT64;
typedef UINT64             UINTN;
typedef UINT64             EFI_STATUS;
typedef void              *EFI_HANDLE;
typedef UINT16             CHAR16;
typedef UINT8              BOOLEAN;

#define EFI_SUCCESS 0
#define EFIAPI
#define OFFSETOF(type, field) __builtin_offsetof(type, field)

typedef struct {
    UINT64 Signature;
    UINT32 Revision;
    UINT32 HeaderSize;
    UINT32 CRC32;
    UINT32 Reserved;
} EFI_TABLE_HEADER;

typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_TEXT_RESET)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, BOOLEAN);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_STRING)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, CHAR16 *);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_TEST_STRING)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, CHAR16 *);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_QUERY_MODE)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, UINTN, UINTN *, UINTN *);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_SET_MODE)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, UINTN);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_SET_ATTRIBUTE)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, UINTN);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_CLEAR_SCREEN)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_SET_CURSOR_POSITION)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, UINTN, UINTN);
typedef EFI_STATUS (EFIAPI *EFI_TEXT_ENABLE_CURSOR)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, BOOLEAN);

struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
    EFI_TEXT_RESET Reset;
    EFI_TEXT_STRING OutputString;
    EFI_TEXT_TEST_STRING TestString;
    EFI_TEXT_QUERY_MODE QueryMode;
    EFI_TEXT_SET_MODE SetMode;
    EFI_TEXT_SET_ATTRIBUTE SetAttribute;
    EFI_TEXT_CLEAR_SCREEN ClearScreen;
    EFI_TEXT_SET_CURSOR_POSITION SetCursorPosition;
    EFI_TEXT_ENABLE_CURSOR EnableCursor;
    void *Mode;
};

typedef EFI_STATUS (EFIAPI *EFI_STALL)(UINTN Microseconds);

typedef struct {
    UINT8 Prefix[248];
    EFI_STALL Stall;
} EFI_BOOT_SERVICES;

typedef struct {
    EFI_TABLE_HEADER Hdr;
    CHAR16 *FirmwareVendor;
    UINT32 FirmwareRevision;
    EFI_HANDLE ConsoleInHandle;
    void *ConIn;
    EFI_HANDLE ConsoleOutHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
    EFI_HANDLE StandardErrorHandle;
    EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;
    void *RuntimeServices;
    EFI_BOOT_SERVICES *BootServices;
    UINTN NumberOfTableEntries;
    void *ConfigurationTable;
} EFI_SYSTEM_TABLE;

_Static_assert(OFFSETOF(EFI_SYSTEM_TABLE, ConOut) == 64,
               "EFI_SYSTEM_TABLE layout mismatch");
_Static_assert(OFFSETOF(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL, OutputString) == 8,
               "ConOut layout mismatch");
_Static_assert(OFFSETOF(EFI_BOOT_SERVICES, Stall) == 248,
               "BootServices Stall offset mismatch");

static CHAR16 banner1[] = L"PJZ110 EFI PROBE: EXECUTION OK\r\n";
static CHAR16 banner2[] = L"READ-ONLY PROBE: no block/variable writes performed\r\n";
static CHAR16 banner3[] = L"Holding for 5 seconds, then returning to firmware boot manager.\r\n";

/* Force one base relocation so the PE can be relocated safely by UEFI. */
static void *volatile relocation_anchor = (void *)banner1;

EFI_STATUS EFIAPI
efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    (void)ImageHandle;
    (void)relocation_anchor;

    if (SystemTable == (void *)0 ||
        SystemTable->ConOut == (void *)0 ||
        SystemTable->ConOut->OutputString == (void *)0) {
        return EFI_SUCCESS;
    }

    SystemTable->ConOut->OutputString(SystemTable->ConOut, banner1);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, banner2);
    SystemTable->ConOut->OutputString(SystemTable->ConOut, banner3);

    if (SystemTable->BootServices != (void *)0 &&
        SystemTable->BootServices->Stall != (void *)0) {
        SystemTable->BootServices->Stall(5000000);
    }
    return EFI_SUCCESS;
}
