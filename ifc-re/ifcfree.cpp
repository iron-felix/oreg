
#include <npapi.h>
#include <npfunctions.h>
#include <memory.h>
#include <stdio.h>

static NPNetscapeFuncs *NPNFuncs;

// This is version of original plugin expected by site
static char IFCVersion[] = "2.0.6.0";
static const char IFCMime[] = "application/x-ifcplugin:ESIA";
static const char PLUGIN_NAME[] = "Открытое Электронное Правительство";
static const char PLUGIN_DESCRIPTION[] = "Свободный Плагин для авторизации с помощью средств электронной подписи в ЕСИА";

static int INSTANCE_NUMBER;

static NPP INSTANCE;

static bool NPHasMethodFunction(NPObject *npobj, NPIdentifier name);
static bool NPHasPropertyFunction(NPObject *npobj, NPIdentifier name);
static bool NPGetPropertyFunction(NPObject *npobj, NPIdentifier name, NPVariant *result);
static bool NPInvokeFunction(NPObject *npobj, NPIdentifier name,
                             const NPVariant *args, uint32_t argCount,
                             NPVariant *result);
static bool NPInvokeDefaultFunction(NPObject *npobj,
                                    const NPVariant *args,
                                    uint32_t argCount,
                                    NPVariant *result);


static NPN_MemAllocProcPtr fNPN_MemAlloc;
static NPN_MemFreeProcPtr fNPN_MemFree;
static NPN_UTF8FromIdentifierProcPtr fNPN_UTF8FromIdentifier;
static NPN_CreateObjectProcPtr fNPN_CreateObject;
static NPN_SetPropertyProcPtr fNPN_SetProperty;
static NPN_GetStringIdentifierProcPtr fNPN_GetStringIdentifier;

static NPClass CLASS = {
    .structVersion = NP_CLASS_STRUCT_VERSION,
    .allocate = NULL,
    .deallocate = NULL,
    .invalidate = NULL,
    .hasMethod = NPHasMethodFunction,
    .invoke = NPInvokeFunction,
    .invokeDefault = NPInvokeDefaultFunction,
    .hasProperty = NPHasPropertyFunction,
    .getProperty = NPGetPropertyFunction,
    .setProperty = NULL,
    .removeProperty = NULL,
    .enumerate = NULL,
    .construct = NULL
};

struct Instance
{
    int num;
};

bool NPHasMethodFunction(NPObject *npobj, NPIdentifier name)
{
    bool res = false;
    NPUTF8 *method = fNPN_UTF8FromIdentifier(name);

    if(strcmp(method, "create") == 0)
    {
        res = true;
    }
    else if(strcmp(method, "get_last_error") == 0)
    {
        res = true;
    }
    else if(strcmp(method, "get_list_info_size") == 0)
    {
        res = true;
    }
    else if(strcmp(method, "get_list_info") == 0)
    {
        res = true;
    }
    else if(strcmp(method, "get_list_certs_size") == 0)
    {
        res = true;
    }
    else if(strcmp(method, "get_list_certs") == 0)
    {
        res = true;
    }
    else if(strcmp(method, "info_x509") == 0)
    {
        res = true;
    }
    else if(strcmp(method, "load_x509_from_container") == 0)
    {
        res = true;
    }
    else if(strcmp(method, "sign") == 0)
    {
        res = true;
    }
    else
    {
        fprintf(stderr, "NPHasMethodFunction: %s\n", method);
    }

    fNPN_MemFree(method);

    return res;
}

// Should return crypto-storage meta information
// Arguments:
//   [0, in, int32] - number of container
//   [1, out, object] - object containing meta information
static
bool get_list_info(const NPVariant *args, uint32_t argCount)
{
    if(argCount != 2)
        return false;

    if(!NPVARIANT_IS_INT32(args[0]))
        return false;

    if(!NPVARIANT_IS_OBJECT(args[1]))
        return false;

    // { file, alias, path, num, type, description, serial number}
    NPObject* object = NPVARIANT_TO_OBJECT(args[1]);

    NPVariant value;

    STRINGZ_TO_NPVARIANT("file", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("alias"), &value);

    STRINGZ_TO_NPVARIANT("File base certificate storage", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("name"), &value);

    STRINGZ_TO_NPVARIANT("/tmp/cert.crt", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("path"), &value);

    STRINGZ_TO_NPVARIANT("75", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("num"), &value);

    // Can be "pkcs11" to ask PIN code in browser
    STRINGZ_TO_NPVARIANT("capi", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("type"), &value);

    STRINGZ_TO_NPVARIANT("", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("description"), &value);

    STRINGZ_TO_NPVARIANT("", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("serial_number"), &value);

    return true;
}

// Should return certificate information
// Arguments:
//   [0, in, int32] - number of certificat
//   [1, out, object] - object containing certificate information
static
bool get_list_certs(const NPVariant *args, uint32_t argCount)
{
    if(argCount != 2)
        return false;

    if(!NPVARIANT_IS_INT32(args[0]))
        return false;

    if(!NPVARIANT_IS_OBJECT(args[1]))
        return false;

    // { id, cert_issuer, cert_subject, cert_valid_from, cert_valid_to, cert_sn }
    NPObject* object = NPVARIANT_TO_OBJECT(args[1]);

    NPVariant value;

    STRINGZ_TO_NPVARIANT("TEST", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("id"), &value);

    STRINGZ_TO_NPVARIANT("1.2.643.100.1 = 1027711111111\n1.2.643.3.131.1.1 = 007711111111\nemailAddress = ca@test-ca.ru\ncountryName = RU\nstateOrProvinceName = 77 г.Москва\nlocalityName = Москва\norganizationName = ООО УЦ\ncommonName = Test Certification Authority", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("cert_issuer"), &value);

    STRINGZ_TO_NPVARIANT("givenName = Иван Иваныч\nsurname = Иванов\ncommonName = Иванов Иван Ивановоич\ntitle = Генеральный директор\norganizationUnitName = Администрация\norganizationName = ООО \"Рога и Копыта\"\nlocalityName = Москва\nstateOrProvinceName = 77 г.Москва\nstreetAddress= бул.Молодых дарований, д.1\nemailAddress = dir@rik.ru\n1.2.643.100.1 = 1117711111111\n1.2.643.3.131.1.1 = 007700000000\n1.2.643.100.3 = 12300000000\ncountryName = RU", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("cert_subject"), &value);

    STRINGZ_TO_NPVARIANT("Apr 1 00:00:00 2015 GMT", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("cert_valid_from"), &value);

    STRINGZ_TO_NPVARIANT("Apr 1 00:00:00 2020 GMT", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("cert_valid_to"), &value);

    STRINGZ_TO_NPVARIANT("4D:FF:FF:FF:FF:FF:00:00:00:39", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("cert_sn"), &value);

    return true;
}

// Should return base64 encoded asn.1 x509 certificate
// Arguments:
//   [0, in, string] - asn.1 encoded certificate
//   [1, in, int32] - unknown, mostly 1
//   [1, in, object] - object containing encoded certificate
static
bool info_x509(const NPVariant *args, uint32_t argCount)
{
    if(argCount != 3)
        return false;

    if(!NPVARIANT_IS_STRING(args[0]))
        return false;

    if(!NPVARIANT_IS_INT32(args[1]))
        return false;

    if(!NPVARIANT_IS_OBJECT(args[2]))
        return false;

    // { info, info_length }
    NPObject* object = NPVARIANT_TO_OBJECT(args[2]);

    NPVariant value;

    STRINGZ_TO_NPVARIANT("MIIHLDCC", value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("info"), &value);

    INT32_TO_NPVARIANT(6, value);

    fNPN_SetProperty(INSTANCE, object, fNPN_GetStringIdentifier("info_length"), &value);

    return true;
}

// Should return asn.1 encoded x509 certificate
// Arguments:
//   [0, in, string] - certificate identificator in form <storage>/<cert-id>
// Result:
//   [string] - asn.1 encoded certificate
static
bool load_x509_from_container(const NPVariant *args, uint32_t argCount, NPVariant *result)
{
    if(argCount != 1)
        return false;

    if(!NPVARIANT_IS_STRING(args[0]))
        return false;

    static const char TEST[] = "TEST";

    size_t len = strlen(TEST);
    NPUTF8* string = (NPUTF8*)fNPN_MemAlloc(len);

    memcpy(string, TEST, len);

    STRINGN_TO_NPVARIANT(string, len, *result);

    return true;
}

// Sign specific test with specified certificate
// Arguments:
//   [0, in, string] - certificate identificator in form <storage>/<cert-id>
//   [1, in, string] - PIN-code (only for PKCS#11 crypto storages)
//   [2, in, object] - text to sign
//   [3, in, unknown] - Unknown
//   [4, in, unknown] - Unknown
//   [5, in, unknown] - Unknown
//   [6, in, unknown] - Unknown
//   [7, out, object] - signature
static
bool sign(const NPVariant *args, uint32_t argCount, NPVariant *result)
{
    if(argCount != 8)
        return false;

    /* Certificate name */
    if(!NPVARIANT_IS_STRING(args[0]))
        return false;

    /* PIN-code */
    if(!NPVARIANT_IS_STRING(args[1]))
        return false;

    /* Value to sign { data: "value" } */
    if(!NPVARIANT_IS_OBJECT(args[2]))
        return false;

    /* Value to put result to { sign_base64: "<signature>"; sign_base64_length: length } */
    if(!NPVARIANT_IS_OBJECT(args[7]))
        return false;

    return true;
}

bool NPInvokeFunction(NPObject *npobj, NPIdentifier name,
                             const NPVariant *args, uint32_t argCount,
                             NPVariant *result)
{
    bool res = false;
    NPUTF8 *method = fNPN_UTF8FromIdentifier(name);

    fprintf(stderr, "NPInvokeFunction: %s\n", method);

    if(strcmp(method, "create") == 0)
    {
        res = true;
        // Initialize instance, scan for crytpo storages
        // Arguments:
        //   none:
        // Result:
        //   [int32] - 0 - ok, non-zero fail
        INT32_TO_NPVARIANT(0, *result);
    }
    else if(strcmp(method, "get_last_error") == 0)
    {
        res = true;
        // Should return crypto-storage meta information
        // Arguments:
        //   none:
        // Result:
        //   [int32] - 0 - ok, non-zero fail
        INT32_TO_NPVARIANT(0, *result);
    }
    else if(strcmp(method, "get_list_info_size") == 0)
    {
        res = true;
        // Should return crypto-storage meta information
        // Arguments:
        //   none:
        // Result:
        //   number of crypto storages in system
        INT32_TO_NPVARIANT(1, *result);
    }
    else if(strcmp(method, "get_list_info") == 0)
    {
        res = get_list_info(args, argCount);
    }
    else if(strcmp(method, "get_list_certs_size") == 0)
    {
        res = true;
        // Should return crypto-container meta information
        // Arguments:
        //   [0, in, string] - storage name
        // Result:
        //   number of certificates in selected storage
        // Notes:
        //   selected storage becomes remembered. Further access of get_list_certs() implicitly refers to this storage
        INT32_TO_NPVARIANT(1, *result);
    }
    else if(strcmp(method, "get_list_certs") == 0)
    {
        res = get_list_certs(args, argCount);
    }
    else if(strcmp(method, "info_x509") == 0)
    {
        res = info_x509(args, argCount);
    }
    else if(strcmp(method, "load_x509_from_container") == 0)
    {
        res = load_x509_from_container(args, argCount, result);
    }
    else if(strcmp(method, "sign") == 0)
    {
        res = sign(args, argCount, result);
    }

    fNPN_MemFree(method);

    return res;
}

static bool NPInvokeDefaultFunction(NPObject *npobj,
                                    const NPVariant *args,
                                    uint32_t argCount,
                                    NPVariant *result)
{
    fprintf(stderr, "NPInvokeDefaultFunction\n");

    return false;
}

bool NPHasPropertyFunction(NPObject *npobj, NPIdentifier name)
{
    bool res = false;
    NPUTF8 *prop = fNPN_UTF8FromIdentifier(name);

    if(strcmp(prop, "valid") == 0)
    {
        res = true;
    }
    else if(strcmp(prop, "version") == 0)
    {
        res = true;
    }
    else
    {
        fprintf(stderr, "NPHasPropertyFunction: %s\n", prop);
    }

    fNPN_MemFree(prop);

    return res;
}

bool NPGetPropertyFunction(NPObject *npobj, NPIdentifier name, NPVariant *result)
{
    bool res = false;
    NPUTF8 *prop = fNPN_UTF8FromIdentifier(name);

    if(strcmp(prop, "valid") == 0)
    {
        res = true;
        BOOLEAN_TO_NPVARIANT(true, *result);
    }
    else if(strcmp(prop, "version") == 0)
    {
        size_t len = strlen(IFCVersion);
        NPUTF8* string = (NPUTF8*)fNPN_MemAlloc(len);

        memcpy(string, IFCVersion, len);

        STRINGN_TO_NPVARIANT(string, len, *result);

        res = true;
    }
    else
    {
        fprintf(stderr, "NPGetPropertyFunction: %s\n", prop);
    }

    fNPN_MemFree(prop);

    return res;
}

static
NPError NPP_NewProc(NPMIMEType pluginType, NPP instance, uint16_t mode, int16_t argc, char* argn[], char* argv[], NPSavedData* saved)
{
    fprintf(stderr, "NPP_NewProc\n");
    if(instance == NULL)
        return NPERR_INVALID_INSTANCE_ERROR;

    Instance *_this = (Instance*)fNPN_MemAlloc(sizeof(Instance));
    _this->num = INSTANCE_NUMBER++;

    instance->pdata = _this;

    return NPERR_NO_ERROR;
}

static
NPError NPP_DestroyProc(NPP instance, NPSavedData** save)
{
    fprintf(stderr, "NPP_DestroyProc\n");

    if(instance == NULL)
        return NPERR_INVALID_INSTANCE_ERROR;

    fNPN_MemFree(instance->pdata);
    instance->pdata = NULL;

    return NPERR_NO_ERROR;
}

static
NPError NPP_GetValueProc(NPP instance, NPPVariable variable, void *ret_value)
{
    if(instance == NULL || instance->pdata == NULL)
        return NPERR_INVALID_INSTANCE_ERROR;

    Instance *_this = (Instance*)instance->pdata;

    switch(variable)
    {
    case NPPVpluginNeedsXEmbed:
        *((bool *)ret_value) = false;
        return NPERR_NO_ERROR;
    case NPPVpluginScriptableNPObject:
    {
        fprintf(stderr, "NPP_GetValueProc: instance %d, scriptable object\n", _this->num);

        INSTANCE = instance;

        NPObject *object = fNPN_CreateObject(instance, &CLASS);

        *((NPObject**)ret_value) = object;

        return NPERR_NO_ERROR;
    }
    default:
        fprintf(stderr, "NPP_GetValueProc: instance %d, variable=%d\n", _this->num, variable);

        return NPERR_NO_DATA;
    }
}

static
NPError NPP_SetValueProc(NPP instance, NPNVariable variable, void *value)
{
    if(instance == NULL || instance->pdata == NULL)
        return NPERR_INVALID_INSTANCE_ERROR;

    Instance *_this = (Instance*)instance->pdata;
    fprintf(stderr, "NPP_SetValueProc: instance %d, variable=%d\n", _this->num, variable);

    return NPERR_NO_DATA;
}

#if defined(XP_UNIX)
NPError NP_Initialize(NPNetscapeFuncs *aNPNFuncs, NPPluginFuncs *aNPPFuncs)
{
    fprintf(stderr, "NP_Initialize\n");

    if(aNPPFuncs == 0 || aNPPFuncs == 0)
        return NPERR_INVALID_FUNCTABLE_ERROR;

    if((aNPNFuncs->version >> 8) > NP_VERSION_MAJOR)
        return NPERR_INCOMPATIBLE_VERSION_ERROR;

    if(aNPPFuncs->size < sizeof(NPPluginFuncs))
        return NPERR_INCOMPATIBLE_VERSION_ERROR;

    fprintf(stderr, "NP_Initialize: version check passed\n");

    NPNFuncs = aNPNFuncs;

    fNPN_MemAlloc = NPNFuncs->memalloc;
    fNPN_MemFree = NPNFuncs->memfree;
    fNPN_UTF8FromIdentifier = NPNFuncs->utf8fromidentifier;
    fNPN_CreateObject = NPNFuncs->createobject;
    fNPN_SetProperty = NPNFuncs->setproperty;
    fNPN_GetStringIdentifier = NPNFuncs->getstringidentifier;

    aNPPFuncs->version = (NP_VERSION_MAJOR << 8) + NP_VERSION_MINOR;
    aNPPFuncs->size = sizeof(NPPluginFuncs);
    aNPPFuncs->newp = NPP_NewProc;
    aNPPFuncs->destroy = NPP_DestroyProc;
    aNPPFuncs->getvalue = NPP_GetValueProc;
    aNPPFuncs->setvalue = NPP_SetValueProc;

    return NPERR_NO_ERROR;
}
#endif

NPError NP_Shutdown(void)
{
    return NPERR_NO_ERROR;
}

NPError NP_GetValue(void *future, NPPVariable aVariable, void *aValue)
{
    fprintf(stderr, "NP_GetValue: %d\n", aVariable);
    switch(aVariable)
    {
    case NPPVpluginNameString:
        *((const char**)aValue) = PLUGIN_NAME;
        return NPERR_NO_ERROR;
    case NPPVpluginDescriptionString:
        *((const char**)aValue) = PLUGIN_DESCRIPTION;
        return NPERR_NO_ERROR;
    default:
        return NPERR_GENERIC_ERROR;
    }
}

char* NP_GetPluginVersion(void)
{
    return IFCVersion;
}

const char* NP_GetMIMEDescription(void)
{
    return IFCMime;
}
