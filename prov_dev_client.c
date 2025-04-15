// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// CAVEAT: This sample is to demonstrate azure IoT client concepts only and is not a guide design principles or style
// Checking of return codes and error values shall be omitted for brevity.  Please practice sound engineering practices
// when writing production code.
#include <stdio.h>
#include <stdlib.h>

#include "iothub.h"
#include "application.h"
#include "iothub_message.h"
#include "iothub_client_version.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/tickcounter.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "azure_c_shared_utility/http_proxy_io.h"

#include "iothub_device_client.h"
#include "iothub_device_client_ll.h"
#include "iothub_client_options.h"
#include "azure_prov_client/prov_device_ll_client.h"
#include "azure_prov_client/prov_device_client.h"
#include "azure_prov_client/prov_security_factory.h"
#include "parson.h"

#include "iothub_deviceconfiguration.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
#include "certs.h"
#endif // SET_TRUSTED_CERT_IN_SAMPLES

//
// The protocol you wish to use should be uncommented
//
#define SAMPLE_MQTT
//#define SAMPLE_MQTT_OVER_WEBSOCKETS
//#define SAMPLE_AMQP
//#define SAMPLE_AMQP_OVER_WEBSOCKETS
//#define SAMPLE_HTTP

#ifdef SAMPLE_MQTT
#include "iothubtransportmqtt.h"
#include "azure_prov_client/prov_transport_mqtt_client.h"
#endif // SAMPLE_MQTT
#ifdef SAMPLE_MQTT_OVER_WEBSOCKETS
#include "iothubtransportmqtt_websockets.h"
#include "azure_prov_client/prov_transport_mqtt_ws_client.h"
#endif // SAMPLE_MQTT_OVER_WEBSOCKETS
#ifdef SAMPLE_AMQP
#include "iothubtransportamqp.h"
#include "azure_prov_client/prov_transport_amqp_client.h"
#endif // SAMPLE_AMQP
#ifdef SAMPLE_AMQP_OVER_WEBSOCKETS
#include "iothubtransportamqp_websockets.h"
#include "azure_prov_client/prov_transport_amqp_ws_client.h"
#endif // SAMPLE_AMQP_OVER_WEBSOCKETS
#ifdef SAMPLE_HTTP
#include "iothubtransporthttp.h"
#include "azure_prov_client/prov_transport_http_client.h"
#endif // SAMPLE_HTTP

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
#include "certs.h"
#endif // SET_TRUSTED_CERT_IN_SAMPLES

// This sample is to demostrate iothub reconnection with provisioning and should not
// be confused as production code

#pragma region Global_Variables
static const char* global_prov_uri = "global.azure-devices-provisioning.net";
static const char* id_scope = "0ne006CD7CA";

IOTHUB_DEVICE_CLIENT_LL_HANDLE device_ll_handle;

MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_RESULT, PROV_DEVICE_RESULT_VALUE);
MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_REG_STATUS, PROV_DEVICE_REG_STATUS_VALUES);

static bool g_use_proxy = false;
static const char* PROXY_ADDRESS = "127.0.0.1";

static size_t g_message_count_send_confirmations = 0;

#define PROXY_PORT                  8888
#define TIME_BETWEEN_MESSAGES       600

static size_t g_message_recv_count = 0;

/*   DEFAULT CONFIG PARAMTERS */
char* provClientFirmwareVersion = "1.0.0";
char* provClientFirmwareURI = "swthesis.testuser0001@swthesis.blob.core.windows.net:/prov_dev_client.enc";
char* provClientConnectionIP = "ConnectionIP";
char* provClientCheckSumKey = "ChecksumKey";
char* provClientHashKey = "swthesis.testuser0001@swthesis.blob.core.windows.net:/key.bin.enc";
char* provClientFirmwareUpdateStatus = "IDLE";
char* provClientStartDownload = "false";
char* provClientApplyChanges = "false";
char* provClientCheckForUpdates = "false";
char* fileDownloadPath = "/home/pi/Downloads/FirmwareUpdate/";

bool traceOn = false;

typedef struct CLIENT_SAMPLE_INFO_TAG
{
    unsigned int sleep_time;
    char* iothub_uri;
    char* access_key_name;
    char* device_key;
    char* device_id;
    int registration_complete;
} CLIENT_SAMPLE_INFO;

typedef struct IOTHUB_CLIENT_SAMPLE_INFO_TAG
{
    int connected;
    int stop_running;
} IOTHUB_CLIENT_SAMPLE_INFO;

typedef struct IOT_DEVICE_TAG
{
    char* firmwareVersion;
    char* firmwareURI;
    char* connectionIP;
    char* checkSumKey;
    char* hashKey;
    char* firmwareUpdateStatus;
    char* startDownload;
    char* applyChanges;
    char* checkForUpdates;

}IoT_Device;

IoT_Device iot_device;

#pragma endregion

#pragma region registeration_callback
static void registration_status_callback(PROV_DEVICE_REG_STATUS reg_status, void* user_context)
{
    (void)user_context;
    (void)printf("Provisioning Status: %s\r\n", MU_ENUM_TO_STRING(PROV_DEVICE_REG_STATUS, reg_status));
}
#pragma endregion

#pragma region iothub_connection_status
static void iothub_connection_status(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void* user_context)
{
    (void)reason;
    if (user_context == NULL)
    {
        printf("iothub_connection_status user_context is NULL\r\n");
    }
    else
    {
        IOTHUB_CLIENT_SAMPLE_INFO* iothub_info = (IOTHUB_CLIENT_SAMPLE_INFO*)user_context;
        if (result == IOTHUB_CLIENT_CONNECTION_AUTHENTICATED)
        {
            iothub_info->connected = 1;
        }
        else
        {
            iothub_info->connected = 0;
            iothub_info->stop_running = 1;
        }
    }
}
#pragma endregion

#pragma region register_device_callback
static void register_device_callback(PROV_DEVICE_RESULT register_result, const char* iothub_uri, const char* device_id, void* user_context)
{
    if (user_context == NULL)
    {
        printf("user_context is NULL\r\n");
    }
    else
    {
        CLIENT_SAMPLE_INFO* user_ctx = (CLIENT_SAMPLE_INFO*)user_context;
        if (register_result == PROV_DEVICE_RESULT_OK)
        {
            (void)printf("Registration Information received from service: %s!\r\n", iothub_uri);
            (void)mallocAndStrcpy_s(&user_ctx->iothub_uri, iothub_uri);
            (void)mallocAndStrcpy_s(&user_ctx->device_id, device_id);
            user_ctx->registration_complete = 1;
        }
        else
        {
            (void)printf("Failure encountered on registration %s\r\n", MU_ENUM_TO_STRING(PROV_DEVICE_RESULT, register_result) );
            user_ctx->registration_complete = 2;
        }
    }
}
#pragma endregion

#pragma region send_confirm_callback
static void send_confirm_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{
    (void)userContextCallback;
    // When a message is sent this callback will get invoked
    g_message_count_send_confirmations++;
    (void)printf("Confirmation callback received for message %lu with result %s\r\n", (unsigned long)g_message_count_send_confirmations, MU_ENUM_TO_STRING(IOTHUB_CLIENT_CONFIRMATION_RESULT, result));
}
#pragma endregion

#pragma region Serialize and Deserialize functions

static char* serializeToJson(IoT_Device* iot_device)
{
    char* result;

    JSON_Value* root_value = json_value_init_object();
    JSON_Object* root_object = json_value_get_object(root_value);

    // Only reported properties
    (void)json_object_set_string(root_object, "firmwareVersion", iot_device->firmwareVersion);
    (void)json_object_set_string(root_object, "firmwareURI", iot_device->firmwareURI);
    (void)json_object_set_string(root_object, "connectionIP", iot_device->connectionIP);
    (void)json_object_set_string(root_object, "checkSumKey", iot_device->checkSumKey);
    (void)json_object_set_string(root_object, "hashKey", iot_device->hashKey);
    (void)json_object_set_string(root_object, "firmwareUpdateStatus", iot_device->firmwareUpdateStatus);
    (void)json_object_set_string(root_object, "startDownload", iot_device->startDownload);
    (void)json_object_set_string(root_object, "applyChanges", iot_device->applyChanges);
    (void)json_object_set_string(root_object, "checkForUpdates", iot_device->checkForUpdates);

    result = json_serialize_to_string(root_value);

    json_value_free(root_value);

    return result;
}

//  Converts the desired properties of the Device Twin JSON blob received from IoT Hub into a Car object.
static IoT_Device* parseFromJson(const char* json, DEVICE_TWIN_UPDATE_STATE update_state)
{
    IoT_Device* iot_device = malloc(sizeof(IoT_Device));
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    if(iot_device == NULL)
    {
        (void)printf("ERROR: Failed to allocate memory\r\n");
    }
    else
    {
        (void)memset(iot_device, 0, sizeof(IoT_Device));

        root_value = json_parse_string(json);
        root_object = json_value_get_object(root_value);

        // Only desired properties
        JSON_Value* firmwareVersion;
        JSON_Value* firmwareURI;
        JSON_Value* connectionIP;
        JSON_Value* checkSumKey;
        JSON_Value* hashKey;
        JSON_Value* startDownload;
        JSON_Value* applyChanges;
        JSON_Value* checkForUpdates;

        if(update_state == DEVICE_TWIN_UPDATE_COMPLETE)
        {
            firmwareVersion = json_object_dotget_value(root_object, "desired.firmwareVersion");
            firmwareURI= json_object_dotget_value(root_object, "desired.firmwareURI");
            connectionIP= json_object_dotget_value(root_object, "desired.connectionIP");
            checkSumKey= json_object_dotget_value(root_object, "desired.checkSumKey");
            hashKey= json_object_dotget_value(root_object, "desired.hashKey");
            startDownload= json_object_dotget_value(root_object, "desired.startDownload");
            applyChanges= json_object_dotget_value(root_object, "desired.applyChanges");
            checkForUpdates= json_object_dotget_value(root_object, "desired.checkForUpdates");
        }
        else
        {
            firmwareVersion = json_object_get_value(root_object, "firmwareVersion");
            firmwareURI= json_object_get_value(root_object, "firmwareURI");
            connectionIP= json_object_get_value(root_object, "connectionIP");
            checkSumKey= json_object_get_value(root_object, "checkSumKey");
            hashKey= json_object_get_value(root_object, "hashKey");
            startDownload= json_object_get_value(root_object, "startDownload");
            applyChanges= json_object_get_value(root_object, "applyChanges");
            checkForUpdates= json_object_get_value(root_object, "checkForUpdates");
        }

        if(firmwareVersion != NULL){

            const char* data = json_value_get_string(firmwareVersion);

            if (data != NULL)
            {
                iot_device->firmwareVersion = malloc(strlen(data) + 1);
                if (NULL != iot_device->firmwareVersion)
                {
                    (void)strcpy(iot_device->firmwareVersion, data);
                }
            }

        }

        if(firmwareURI != NULL){

            const char* data = json_value_get_string(firmwareURI);

            if (data != NULL)
            {
                iot_device->firmwareURI = malloc(strlen(data) + 1);
                if (NULL != iot_device->firmwareURI)
                {
                    (void)strcpy(iot_device->firmwareURI, data);
                }
            }

        }

        if(connectionIP != NULL){

            const char* data = json_value_get_string(connectionIP);

            if (data != NULL)
            {
                iot_device->connectionIP = malloc(strlen(data) + 1);
                if (NULL != iot_device->connectionIP)
                {
                    (void)strcpy(iot_device->connectionIP, data);
                }
            }

        }

        if(checkSumKey != NULL){

            const char* data = json_value_get_string(checkSumKey);

            if (data != NULL)
            {
                iot_device->checkSumKey = malloc(strlen(data) + 1);
                if (NULL != iot_device->checkSumKey)
                {
                    (void)strcpy(iot_device->checkSumKey, data);
                }
            }

        }

        if(hashKey != NULL){

            const char* data = json_value_get_string(hashKey);

            if (data != NULL)
            {
                iot_device->hashKey = malloc(strlen(data) + 1);
                if (NULL != iot_device->hashKey)
                {
                    (void)strcpy(iot_device->hashKey, data);
                }
            }

        }

        if(startDownload != NULL){

            const char* data = json_value_get_string(startDownload);

            if (data != NULL)
            {
                iot_device->startDownload = malloc(strlen(data) + 1);
                if (NULL != iot_device->startDownload)
                {
                    (void)strcpy(iot_device->startDownload, data);
                }
            }

        }

        if(applyChanges != NULL){

            const char* data = json_value_get_string(applyChanges);

            if (data != NULL)
            {
                iot_device->applyChanges = malloc(strlen(data) + 1);
                if (NULL != iot_device->applyChanges)
                {
                    (void)strcpy(iot_device->applyChanges, data);
                }
            }

        }

        if(checkForUpdates != NULL){

            const char* data = json_value_get_string(checkForUpdates);

            if (data != NULL)
            {
                iot_device->checkForUpdates = malloc(strlen(data) + 1);
                if (NULL != iot_device->checkForUpdates)
                {
                    (void)strcpy(iot_device->checkForUpdates, data);
                }
            }

        }

        json_value_free(root_value);

    }

    return iot_device;
}

#pragma endregion

#pragma region using_c2d_messages_asynchronously

#ifdef USE_C2D_ASYNC_ACK
#include "azure_c_shared_utility/singlylinkedlist.h"

static SINGLYLINKEDLIST_HANDLE g_cloudMessages;

// `ack_and_remove_message` is a function that is executed by `singlylinkedlist_remove_if` for each list element.
// In this implementation it is used to send a delayed acknowledgement of receipt to Azure IoT Hub for each message.
static bool ack_and_remove_message(const void* item, const void* match_context, bool* continue_processing)
{
    IOTHUB_DEVICE_CLIENT_LL_HANDLE device_ll_handle = (IOTHUB_DEVICE_CLIENT_LL_HANDLE)match_context;
    IOTHUB_MESSAGE_HANDLE message = (IOTHUB_MESSAGE_HANDLE)item;

    const char* messageId;
    if ((messageId = IoTHubMessage_GetMessageId(message)) == NULL)
    {
        messageId = "<unavailable>";
    }

    (void)printf("Sending ACK for cloud message (Message ID: %s)\r\n", messageId);

    // If using AMQP protocol, this function results in sending a MESSAGE DISPOSITION (ACCEPTED) for the given cloud-to-device message.
    // If using MQTT protocol, a PUBACK is sent for the cloud-to-device message (only) if `IOTHUBMESSAGE_ACCEPTED` is used.
    // If using HTTP protocol no delayed acknowledgement is sent for the cloud-to-device message, as this protocol does not support that.
    // Independent of the protocol used, this function MUST be called by the user application if using delayed acknowledgement of 
    // cloud-to-device messages, as it will free the memory allocated for each of those messages received.
    if (IoTHubDeviceClient_LL_SendMessageDisposition(device_ll_handle, message, IOTHUBMESSAGE_ACCEPTED) != IOTHUB_CLIENT_OK)
    {
        (void)printf("ERROR: IoTHubDeviceClient_LL_SendMessageDisposition..........FAILED!\r\n");
    }

    // Setting `continue_processing` to true informs `singlylinkedlist_remove_if` to continue iterating
    // through all the remaining items in the `g_cloudMessages` list.
    *continue_processing = true;

    // Returning true informs `singlylinkedlist_remove_if` to effectively remove the current list node (`item`).
    return true;
}

static void acknowledge_cloud_messages(IOTHUB_DEVICE_CLIENT_LL_HANDLE device_ll_handle)
{
    // The following function performs a conditional removal of items from a singly-linked list.
    // It can be used to perform one or more actions (through `ack_and_remove_message`) over each list item before removing them.
    // In this case, `ack_and_remove_message` sends an acknowledgement to Azure IoT Hub for each cloud-to-device message
    // previously received and still stored in the `g_cloudMessages` list.
    // This implementation also guarantees the cloud-to-device messages are acknowledged
    // in the order they have been received by the Azure IoT Hub.
    (void)singlylinkedlist_remove_if(g_cloudMessages, ack_and_remove_message, device_ll_handle);
}
#endif

#pragma endregion

#pragma region receive_msg_callback
static IOTHUBMESSAGE_DISPOSITION_RESULT receive_msg_callback(IOTHUB_MESSAGE_HANDLE message, void* user_context)
{
    (void)user_context;
    const char* messageId;
    const char* correlationId;

    // Message properties
    if ((messageId = IoTHubMessage_GetMessageId(message)) == NULL)
    {
        messageId = "<unavailable>";
    }

    if ((correlationId = IoTHubMessage_GetCorrelationId(message)) == NULL)
    {
        correlationId = "<unavailable>";
    }

    IOTHUBMESSAGE_CONTENT_TYPE content_type = IoTHubMessage_GetContentType(message);
    if (content_type == IOTHUBMESSAGE_BYTEARRAY)
    {
        const unsigned char* buff_msg;
        size_t buff_len;

        if (IoTHubMessage_GetByteArray(message, &buff_msg, &buff_len) != IOTHUB_MESSAGE_OK)
        {
            (void)printf("Failure retrieving byte array message\r\n");
        }
        else
        {
            (void)printf("Received Binary message\r\nMessage ID: %s\r\n Correlation ID: %s\r\n Data: <<<%.*s>>> & Size=%d\r\n", messageId, correlationId, (int)buff_len, buff_msg, (int)buff_len);
        }
    }
    else
    {
        const char* string_msg = IoTHubMessage_GetString(message);
        if (string_msg == NULL)
        {
            (void)printf("Failure retrieving byte array message\r\n");
        }
        else
        {
            (void)printf("Received String Message\r\nMessage ID: %s\r\n Correlation ID: %s\r\n Data: <<<%s>>>\r\n", messageId, correlationId, string_msg);
        }
    }
    const char* property_value = "property_value";
    const char* property_key = IoTHubMessage_GetProperty(message, property_value);
    if (property_key != NULL)
    {
        printf("\r\nMessage Properties:\r\n");
        printf("\tKey: %s Value: %s\r\n", property_value, property_key);
    }
    g_message_recv_count++;

#ifdef USE_C2D_ASYNC_ACK
    // For a delayed acknowledgement of the cloud-to-device message, we must save the message first.
    // The `g_cloudMessages` list is used to save incoming cloud-to-device messages.
    // An user application would then process these messages according to the user application logic,
    // and finally send an acknowledgement to the Azure IoT Hub for each by calling `IoTHubDeviceClient_LL_SendMessageDisposition`.
    // When using convenience-layer or module clients of this SDK the respective `*_SendMessageDisposition` functions shall be used.
    (void)singlylinkedlist_add(g_cloudMessages, message);

    // Returning IOTHUBMESSAGE_ASYNC_ACK means that the SDK will NOT acknowledge receipt the
    // C2D message to the service.  The application itself is responsible for this.  See ack_and_remove_message() in the sample
    // to see how to do this.
    return IOTHUBMESSAGE_ASYNC_ACK;
#else
    // Returning IOTHUBMESSAGE_ACCEPTED causes the SDK to acknowledge receipt of the message to
    // the service.  The application does not need to take further action to ACK at this point.
    return IOTHUBMESSAGE_ACCEPTED;
#endif
}

#pragma endregion

#pragma region Reported properties callback
static void reportedStateCallback(int status_code, void* userContextCallback)
{
    (void)userContextCallback;
    printf("\nDevice Twin reported properties update completed with result: %d\r\n", status_code);
}

static void sendDeviceReportedProperties(IoT_Device* iot_device)
{
	if (iot_device != NULL && device_ll_handle != NULL)
	{
		char* reportedProperties = serializeToJson(iot_device);
		if (reportedProperties)
		{
			(void)IoTHubDeviceClient_LL_SendReportedState(device_ll_handle, (const unsigned char*)reportedProperties, strlen(reportedProperties), reportedStateCallback, NULL);
			free(reportedProperties);
		}
	}
}
#pragma endregion

#pragma region Download and Update Methods

static int compVersions ( const char * version1, const char * version2 ) {
	unsigned major1 = 0, minor1 = 0, bugfix1 = 0;
	unsigned major2 = 0, minor2 = 0, bugfix2 = 0;
	sscanf(version1, "%u.%u.%u", &major1, &minor1, &bugfix1);
	sscanf(version2, "%u.%u.%u", &major2, &minor2, &bugfix2);
	if (major1 < major2) return -1;
	if (major1 > major2) return 1;
	if (minor1 < minor2) return -1;
	if (minor1 > minor2) return 1;
	if (bugfix1 < bugfix2) return -1;
	if (bugfix1 > bugfix2) return 1;
	return 0;
}

static int do_firmware_update(void *param)
{

    IoT_Device *iot_device = (IoT_Device *)param;

    printf("DOWNLOAD BEGINS...\r\n");
	iot_device->firmwareUpdateStatus = "DOWNLOADING";
	sendDeviceReportedProperties(iot_device);

    pid_t pid1 = fork();
    if(pid1 == 0)
    {
        if (access(fileDownloadPath, F_OK) != 0) {
            mkdir(fileDownloadPath, 0700);
        }
        
        execl("/usr/bin/sftp", "sftp", iot_device->firmwareURI, fileDownloadPath,  (char *)0);
    }
    else
    {
        int child_status;
        waitpid(pid1, &child_status, 0);
    }

    pid_t pid2 = fork();
    if(pid2 == 0)
    {
        if (access(fileDownloadPath, F_OK) != 0) {
            mkdir(fileDownloadPath, 0700);
        }
        
        execl("/usr/bin/sftp", "sftp", iot_device->hashKey, fileDownloadPath,  (char *)0);
    }
    else
    {
        int child_status;
        waitpid(pid2, &child_status, 0);
    }

    printf("DOWNLOAD FINISHED...\r\n");

    FILE* file;
	char buffer[64] = {0x0};
    if((file = popen("sha256sum /home/pi/Downloads/FirmwareUpdate/prov_dev_client.enc", "r")) != NULL)
    {
        printf("\n file is not null\n");
        
        if(fscanf(file,"%s",buffer) == 1){
            printf("buffer is %s\n",buffer);
            printf("checksum key is %s\n",iot_device->checkSumKey);
        }
    }

    if(strncmp(buffer, iot_device->checkSumKey, 64) == 0)
    {
        printf("\n***********Checksum matched********** \n");
        
        system("/home/pi/Documents/prov_dev_client_ll_sample/Decryption.sh");

    }
    else
    {
        printf("\n***********Checksum not matched********** \n");
    }

	iot_device->firmwareUpdateStatus = "IDLE";
	sendDeviceReportedProperties(iot_device);
}

#pragma endregion

#pragma region Device Twin Methods



static void getCompleteDeviceTwinOnDemandCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payLoad, size_t size, void* userContextCallback)
{
    (void)update_state;
    (void)userContextCallback;
    printf("\nGetTwinAsync result:\r\n%.*s\r\n", (int)size, payLoad);
}

char * extract_file_name(char *path)
{
    int len = strlen(path);
    int flag=0;
    
    for(int i=len-1; i>0; i--)
    {
        if(path[i]=='\\' || path[i]=='//' || path[i]=='/' )
        {
            flag=1;
            path = path+i+1;
            break;
        }
    }
    return path;
}

static void deviceTwinCallback(DEVICE_TWIN_UPDATE_STATE update_state, const unsigned char* payLoad, size_t size, void* userContextCallback)
{
    IoT_Device* currentConfig = (IoT_Device*)userContextCallback;
    IoT_Device* newConfig = parseFromJson((const char*)payLoad, update_state);

    if(NULL == newConfig)
    {
        printf("ERROR: parseFromJson returned NULL\r\n");
    }
    else
    {
        /* Notify when the update is available */
        if(newConfig->firmwareVersion != NULL){

            int result = compVersions(newConfig->firmwareVersion, currentConfig->firmwareVersion);

            // If new firmware is available
            if(result == 1){
                printf("\n******* New firmware version available :  v%s\n", newConfig->firmwareVersion);
            }
            else{
                printf("\n******* The Software is up-to-date  ******* \n");
            }
        }

        /* Check for update manually*/ 

        if( newConfig->checkForUpdates != NULL)
        {
            if(strcmp("true",newConfig->checkForUpdates) == 0 || strcmp("True",newConfig->checkForUpdates) == 0 || strcmp("TRUE",newConfig->checkForUpdates) == 0){
                if(newConfig->firmwareVersion != NULL){

                int result = compVersions(newConfig->firmwareVersion, currentConfig->firmwareVersion);

                // If new firmware is available
                if(result == 1){
                    printf("\n******* New firmware version available :  v%s\n", newConfig->firmwareVersion);
                }
                else{
                    printf("\n******* The Software is up-to-date  ******* \n");
                }
            }

            if (newConfig->checkForUpdates != NULL)
            {
                if ((currentConfig->checkForUpdates != NULL) && (strcmp(currentConfig->checkForUpdates, newConfig->checkForUpdates) != 0))
                {
                    free(currentConfig->checkForUpdates);
                    currentConfig->checkForUpdates = NULL;
                }

                if (currentConfig->checkForUpdates == NULL)
                {
                    printf("\nReceived a check for updates flag = %s\n", newConfig->checkForUpdates);
                    if ( NULL != (currentConfig->checkForUpdates = malloc(strlen(newConfig->checkForUpdates) + 1)))
                    {
                        (void)strcpy(currentConfig->checkForUpdates, newConfig->checkForUpdates);
                        free(newConfig->checkForUpdates);
                    }
                }
            }
            }
            
        }

        /* Start Download  */

        if(newConfig->startDownload != NULL){
            if(strcmp("true",newConfig->startDownload) == 0 || strcmp("True",newConfig->startDownload) == 0 ||strcmp("TRUE",newConfig->startDownload) == 0)
            {
                if(newConfig->firmwareVersion != NULL){
                    
                    int result = compVersions(newConfig->firmwareVersion, currentConfig->firmwareVersion);

                    // If new firmware is available
                    if(result == 1){
                        
                        // Change Firmware URI
                        if (newConfig->firmwareURI != NULL)
                        {
                            if ((currentConfig->firmwareURI != NULL) && (strcmp(currentConfig->firmwareURI, newConfig->firmwareURI) != 0))
                            {
                                free(currentConfig->firmwareURI);
                                currentConfig->firmwareURI = NULL;
                            }

                            if (currentConfig->firmwareURI == NULL)
                            {
                                printf("Received a new Firmware URI = %s\n", newConfig->firmwareURI);
                                if ( NULL != (currentConfig->firmwareURI = malloc(strlen(newConfig->firmwareURI) + 1)))
                                {
                                    (void)strcpy(currentConfig->firmwareURI, newConfig->firmwareURI);
                                    free(newConfig->firmwareURI);
                                }
                            }
                        }

                        if (newConfig->checkSumKey != NULL)
                        {
                            if ((currentConfig->checkSumKey != NULL) && (strcmp(currentConfig->checkSumKey, newConfig->checkSumKey) != 0))
                            {
                                free(currentConfig->checkSumKey);
                                currentConfig->checkSumKey = NULL;
                            }

                            if (currentConfig->checkSumKey == NULL)
                            {
                                printf("Received a new Checksum Key = %s\n", newConfig->checkSumKey);
                                if ( NULL != (currentConfig->checkSumKey = malloc(strlen(newConfig->checkSumKey) + 1)))
                                {
                                    (void)strcpy(currentConfig->checkSumKey, newConfig->checkSumKey);
                                    free(newConfig->checkSumKey);
                                }
                            }
                        }

                        if (newConfig->hashKey != NULL)
                        {
                            if ((currentConfig->hashKey != NULL) && (strcmp(currentConfig->hashKey, newConfig->hashKey) != 0))
                            {
                                free(currentConfig->hashKey);
                                currentConfig->hashKey = NULL;
                            }

                            if (currentConfig->hashKey == NULL)
                            {
                                printf("Received a new Firmware = %s\n", newConfig->hashKey);
                                if ( NULL != (currentConfig->hashKey = malloc(strlen(newConfig->hashKey) + 1)))
                                {
                                    (void)strcpy(currentConfig->hashKey, newConfig->hashKey);
                                    free(newConfig->hashKey);
                                }
                            }
                        }

                        if (newConfig->startDownload != NULL)
                        {
                            if ((currentConfig->startDownload != NULL) && (strcmp(currentConfig->startDownload, newConfig->startDownload) != 0))
                            {
                                free(currentConfig->startDownload);
                                currentConfig->startDownload = NULL;
                            }

                            if (currentConfig->startDownload == NULL)
                            {
                                printf("Received a download flag = %s\n", newConfig->startDownload);
                                if ( NULL != (currentConfig->startDownload = malloc(strlen(newConfig->startDownload) + 1)))
                                {
                                    (void)strcpy(currentConfig->startDownload, newConfig->startDownload);
                                    free(newConfig->startDownload);
                                }
                            }
                        }

                        THREAD_HANDLE thread_apply;
                        THREADAPI_RESULT t_result = ThreadAPI_Create(&thread_apply, do_firmware_update, currentConfig);
                        if (t_result == THREADAPI_OK)
                        {
                            (void)printf("Starting firmware update\r\n");
                        }
                        else
                        {
                            (void)printf("Failed to start firmware update\r\n");
                        }
                    }
                    else{
                        printf("\n******* The Software is up-to-date  ******* \n");
                    }
                }
            }
        }

        

        /* Applying changes*/
        if(newConfig->applyChanges != NULL){
            if(strcmp("true",newConfig->applyChanges) == 0 ||strcmp("True",newConfig->applyChanges) == 0 || strcmp("TRUE",newConfig->applyChanges) == 0)
            {
                printf("\n\n************ Applying changes and Rebooting ************   \n\n");
                if (newConfig->applyChanges != NULL)
                {
                    if ((currentConfig->applyChanges != NULL) && (strcmp(currentConfig->applyChanges, newConfig->applyChanges) != 0))
                    {
                        free(currentConfig->applyChanges);
                        currentConfig->applyChanges = NULL;
                    }

                    if (currentConfig->applyChanges == NULL)
                    {
                        printf("Received a apply flag = %s\n", newConfig->applyChanges);
                        if ( NULL != (currentConfig->applyChanges = malloc(strlen(newConfig->applyChanges) + 1)))
                        {
                            (void)strcpy(currentConfig->applyChanges, newConfig->applyChanges);
                            free(newConfig->applyChanges);
                        }
                    }
                }

                if (newConfig->firmwareURI != NULL)
                {
                    if ((currentConfig->firmwareURI != NULL) && (strcmp(currentConfig->firmwareURI, newConfig->firmwareURI) != 0))
                    {
                        free(currentConfig->firmwareURI);
                        currentConfig->firmwareURI = NULL;
                    }

                    if (currentConfig->firmwareURI == NULL)
                    {
                        printf("Received a new Firmware URI = %s\n", newConfig->firmwareURI);
                        if ( NULL != (currentConfig->firmwareURI = malloc(strlen(newConfig->firmwareURI) + 1)))
                        {
                            (void)strcpy(currentConfig->firmwareURI, newConfig->firmwareURI);
                            free(newConfig->firmwareURI);
                        }
                    }
                }

                currentConfig->firmwareUpdateStatus = "APPLYING AND REBOOTING";
	            sendDeviceReportedProperties(currentConfig);
                ThreadAPI_Sleep(100);

                char fname[300] = "";
                strcpy(fname, fileDownloadPath);
                strcat(fname, extract_file_name(currentConfig->firmwareURI));

                char ans[] = "";

                printf("\nfilename :  %s\n", fname);

                if (access(fname, F_OK) == 0) {

                    fflush(stdout);

                    system("sudo reboot");
                    
                } else {

                    printf("\n**** Please download the latest version of software : %s \n", fname);

                }
            }
        }

        free(newConfig);
        newConfig = NULL;
    }

}


#pragma endregion


int main()
{
    #pragma region variables
    SECURE_DEVICE_TYPE hsm_type;
    //hsm_type = SECURE_DEVICE_TYPE_TPM;
    hsm_type = SECURE_DEVICE_TYPE_X509;
    //hsm_type = SECURE_DEVICE_TYPE_SYMMETRIC_KEY;

    size_t messages_count = 0;
    
#pragma region protocol defination

#ifdef USE_C2D_ASYNC_ACK
    g_cloudMessages = singlylinkedlist_create();
#endif
    

    (void)IoTHub_Init();
    (void)prov_dev_security_init(hsm_type);
    // Set the symmetric key if using they auth type
    // If using DPS with an enrollment group, this must the the derived device key from the DPS Primary Key
    // https://docs.microsoft.com/azure/iot-dps/concepts-symmetric-key-attestation?tabs=azure-cli#group-enrollments
    //prov_dev_set_symmetric_key_info("<symm_registration_id>", "<symmetric_Key>");

    PROV_DEVICE_TRANSPORT_PROVIDER_FUNCTION prov_transport;
    HTTP_PROXY_OPTIONS http_proxy;
    CLIENT_SAMPLE_INFO user_ctx;

    memset(&http_proxy, 0, sizeof(HTTP_PROXY_OPTIONS));
    memset(&user_ctx, 0, sizeof(CLIENT_SAMPLE_INFO));

    // Protocol to USE - HTTP, AMQP, AMQP_WS, MQTT, MQTT_WS
#ifdef SAMPLE_MQTT
    prov_transport = Prov_Device_MQTT_Protocol;
#endif // SAMPLE_MQTT
#ifdef SAMPLE_MQTT_OVER_WEBSOCKETS
    prov_transport = Prov_Device_MQTT_WS_Protocol;
#endif // SAMPLE_MQTT_OVER_WEBSOCKETS
#ifdef SAMPLE_AMQP
    prov_transport = Prov_Device_AMQP_Protocol;
#endif // SAMPLE_AMQP
#ifdef SAMPLE_AMQP_OVER_WEBSOCKETS
    prov_transport = Prov_Device_AMQP_WS_Protocol;
#endif // SAMPLE_AMQP_OVER_WEBSOCKETS
#ifdef SAMPLE_HTTP
    prov_transport = Prov_Device_HTTP_Protocol;
#endif // SAMPLE_HTTP

    // Set ini
    user_ctx.registration_complete = 0;
    user_ctx.sleep_time = 10;

    printf("Provisioning API Version: %s\r\n", Prov_Device_LL_GetVersionString());
    printf("Iothub API Version: %s\r\n", IoTHubClient_GetVersionString());

    if (g_use_proxy)
    {
        http_proxy.host_address = PROXY_ADDRESS;
        http_proxy.port = PROXY_PORT;
    }

    PROV_DEVICE_LL_HANDLE handle;
    #pragma endregion 

#pragma endregion

    #pragma region registration_of_device
    if ((handle = Prov_Device_LL_Create(global_prov_uri, id_scope, prov_transport)) == NULL)
    {
        (void)printf("failed calling Prov_Device_LL_Create\r\n");
    }
    else
    {
        if (http_proxy.host_address != NULL)
        {
            Prov_Device_LL_SetOption(handle, OPTION_HTTP_PROXY, &http_proxy);
        }

        Prov_Device_LL_SetOption(handle, PROV_OPTION_LOG_TRACE, &traceOn);
#ifdef SET_TRUSTED_CERT_IN_SAMPLES
        // Setting the Trusted Certificate. This is only necessary on systems without
        // built in certificate stores.
        Prov_Device_LL_SetOption(handle, OPTION_TRUSTED_CERT, certificates);
#endif // SET_TRUSTED_CERT_IN_SAMPLES

        // This option sets the registration ID it overrides the registration ID that is 
        // set within the HSM so be cautious if setting this value
        //Prov_Device_LL_SetOption(handle, PROV_REGISTRATION_ID, "[REGISTRATION ID]");

        if (Prov_Device_LL_Register_Device(handle, register_device_callback, &user_ctx, registration_status_callback, &user_ctx) != PROV_DEVICE_RESULT_OK)
        {
            (void)printf("failed calling Prov_Device_LL_Register_Device\r\n");
        }
        else
        {
            do
            {
                Prov_Device_LL_DoWork(handle);
                ThreadAPI_Sleep(user_ctx.sleep_time);
            } while (user_ctx.registration_complete == 0);
        }
        Prov_Device_LL_Destroy(handle);
    }
    #pragma endregion

    #pragma region creating_direct_link_telemetry_c2d_sw_fm_update_execution
    if (user_ctx.registration_complete != 1)
    {
        (void)printf("registration failed!\r\n");
    }
    else
    {
        IOTHUB_CLIENT_TRANSPORT_PROVIDER iothub_transport;

        // Protocol to USE - HTTP, AMQP, AMQP_WS, MQTT, MQTT_WS
#if defined(SAMPLE_MQTT) || defined(SAMPLE_HTTP) // HTTP sample will use mqtt protocol
        iothub_transport = MQTT_Protocol;
#endif // SAMPLE_MQTT
#ifdef SAMPLE_MQTT_OVER_WEBSOCKETS
        iothub_transport = MQTT_WebSocket_Protocol;
#endif // SAMPLE_MQTT_OVER_WEBSOCKETS
#ifdef SAMPLE_AMQP
        iothub_transport = AMQP_Protocol;
#endif // SAMPLE_AMQP
#ifdef SAMPLE_AMQP_OVER_WEBSOCKETS
        iothub_transport = AMQP_Protocol_over_WebSocketsTls;
#endif // SAMPLE_AMQP_OVER_WEBSOCKETS

        (void)printf("Creating IoTHub Device handle\r\n");
        if ((device_ll_handle = IoTHubDeviceClient_LL_CreateFromDeviceAuth(user_ctx.iothub_uri, user_ctx.device_id, iothub_transport) ) == NULL)
        {
            (void)printf("failed create IoTHub client from connection string %s!\r\n", user_ctx.iothub_uri);
        }
        else
        {
            IOTHUB_CLIENT_SAMPLE_INFO iothub_info;
            TICK_COUNTER_HANDLE tick_counter_handle = tickcounter_create();
            tickcounter_ms_t current_tick;
            tickcounter_ms_t last_send_time = 0;
            size_t msg_count = 0;
            iothub_info.stop_running = 0;
            iothub_info.connected = 0;

            (void)IoTHubDeviceClient_LL_SetConnectionStatusCallback(device_ll_handle, iothub_connection_status, &iothub_info);

            // Set any option that are necessary.
            // For available options please see the iothub_sdk_options.md documentation

            IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_LOG_TRACE, &traceOn);

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
            // Setting the Trusted Certificate. This is only necessary on systems without
            // built in certificate stores.
            IoTHubDeviceClient_LL_SetOption(device_ll_handle, OPTION_TRUSTED_CERT, certificates);
#endif // SET_TRUSTED_CERT_IN_SAMPLES

            
            memset(&iot_device, 0 , sizeof(IoT_Device));

            #pragma region Assign and Allocate default reported parmeters
            
            size_t size = strlen(provClientFirmwareVersion) + 1;
            iot_device.firmwareVersion = malloc(size);
            if (iot_device.firmwareVersion != NULL)
            {
                memcpy(iot_device.firmwareVersion, provClientFirmwareVersion, size);
            }

            size = strlen(provClientFirmwareURI) + 1;
            iot_device.firmwareURI = malloc(size);
            if (iot_device.firmwareURI != NULL)
            {
                memcpy(iot_device.firmwareURI, provClientFirmwareURI, size);
            }

            size = strlen(provClientConnectionIP) + 1;
            iot_device.connectionIP = malloc(size);
            if (iot_device.connectionIP != NULL)
            {
                memcpy(iot_device.connectionIP, provClientConnectionIP, size);
            }

            size = strlen(provClientCheckSumKey) + 1;
            iot_device.checkSumKey = malloc(size);
            if (iot_device.checkSumKey != NULL)
            {
                memcpy(iot_device.checkSumKey, provClientCheckSumKey, size);
            }

            size = strlen(provClientHashKey) + 1;
            iot_device.hashKey = malloc(size);
            if (iot_device.hashKey != NULL)
            {
                memcpy(iot_device.hashKey, provClientHashKey, size);
            }

            size = strlen(provClientFirmwareUpdateStatus) + 1;
            iot_device.firmwareUpdateStatus = malloc(size);
            if (iot_device.firmwareUpdateStatus != NULL)
            {
                memcpy(iot_device.firmwareUpdateStatus, provClientFirmwareUpdateStatus, size);
            }

            size = strlen(provClientStartDownload) + 1;
            iot_device.startDownload = malloc(size);
            if (iot_device.startDownload != NULL)
            {
                memcpy(iot_device.startDownload, provClientStartDownload, size);
            }

            size = strlen(provClientApplyChanges) + 1;
            iot_device.applyChanges = malloc(size);
            if (iot_device.applyChanges != NULL)
            {
                memcpy(iot_device.applyChanges, provClientApplyChanges, size);
            }

            size = strlen(provClientCheckForUpdates) + 1;
            iot_device.checkForUpdates = malloc(size);
            if (iot_device.checkForUpdates != NULL)
            {
                memcpy(iot_device.checkForUpdates, provClientCheckForUpdates, size);
            }

            #pragma endregion

            char* reportedProperties = serializeToJson(&iot_device);

            (void)IoTHubDeviceClient_LL_GetTwinAsync(device_ll_handle, getCompleteDeviceTwinOnDemandCallback, NULL);

            (void)IoTHubDeviceClient_LL_SendReportedState(device_ll_handle, (const unsigned char*)reportedProperties, strlen(reportedProperties), reportedStateCallback, NULL);

            (void)IoTHubDeviceClient_LL_SetDeviceTwinCallback(device_ll_handle, deviceTwinCallback, &iot_device);

            THREAD_HANDLE thread_apply;
            THREADAPI_RESULT t_result = ThreadAPI_Create(&thread_apply, Application, device_ll_handle);
            if (t_result == THREADAPI_OK)
            {
                (void)printf("Starting application thread...\r\n");
            }
            else
            {
                (void)printf("Failed to start application thread\r\n");
            }


            // set the callback function for c2d messages
            if (IoTHubDeviceClient_LL_SetMessageCallback(device_ll_handle, receive_msg_callback, &messages_count) != IOTHUB_CLIENT_OK)
            {
                (void)printf("ERROR: IoTHubClient_LL_SetMessageCallback..........FAILED!\r\n");
            }
            else{
                (void)printf("Updating reported properties every %d second\r\n", TIME_BETWEEN_MESSAGES);

                do
                {
                    if (iothub_info.connected != 0)
                    {
                        // Send a message every TIME_BETWEEN_MESSAGES seconds
                        (void)tickcounter_get_current_ms(tick_counter_handle, &current_tick);
                        if ((current_tick - last_send_time) / 1000 > TIME_BETWEEN_MESSAGES)
                        {
                            
                            sendDeviceReportedProperties(&iot_device);
                            (void)tickcounter_get_current_ms(tick_counter_handle, &last_send_time);
                        }
                    }

#ifdef USE_C2D_ASYNC_ACK
                    // If using delayed acknowledgement of cloud-to-device messages, this function serves as an example of
                    // how to do so for all the previously received messages still present in the list used by this sample.
                    acknowledge_cloud_messages(device_ll_handle);
#endif

                    IoTHubDeviceClient_LL_DoWork(device_ll_handle);
                    ThreadAPI_Sleep(1);
                } while (iothub_info.stop_running == 0);

                size_t index = 0;
                for (index = 0; index < 10; index++)
                {
                    IoTHubDeviceClient_LL_DoWork(device_ll_handle);
                    ThreadAPI_Sleep(1);
                }
                tickcounter_destroy(tick_counter_handle);
                // Clean up the iothub sdk handle
                IoTHubDeviceClient_LL_Destroy(device_ll_handle);
            }
        }
    }

    #pragma endregion
    free(user_ctx.iothub_uri);
    free(user_ctx.device_id);
    prov_dev_security_deinit();

    // Free all the sdk subsystem
    IoTHub_Deinit();

#ifdef USE_C2D_ASYNC_ACK
    singlylinkedlist_destroy(g_cloudMessages);
#endif

    (void)printf("Press any enter to continue:\r\n");
    (void)getchar();

    return 0;
}
