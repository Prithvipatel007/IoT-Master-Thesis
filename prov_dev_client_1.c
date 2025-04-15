// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// CAVEAT: This sample is to demonstrate azure IoT client concepts only and is not a guide design principles or style
// Checking of return codes and error values shall be omitted for brevity.  Please practice sound engineering practices
// when writing production code.
#include <stdio.h>
#include <stdlib.h>

#include "iothub.h"
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

#define MESSAGERESPONSE(code, message) const char deviceMethodResponse[] = message; \
	*response_size = sizeof(deviceMethodResponse) - 1;                              \
	*response = malloc(*response_size);                                             \
	(void)memcpy(*response, deviceMethodResponse, *response_size);                  \
	result = code;    

#define FIRMWARE_UPDATE_STATUS_VALUES \
    DOWNLOADING,                      \
    APPLYING,                         \
    REBOOTING,                        \
    IDLE                              \

IOTHUB_DEVICE_CLIENT_LL_HANDLE device_ll_handle;

MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_RESULT, PROV_DEVICE_RESULT_VALUE);
MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(PROV_DEVICE_REG_STATUS, PROV_DEVICE_REG_STATUS_VALUES);

/*Enumeration specifying firmware update status */
MU_DEFINE_ENUM(FIRMWARE_UPDATE_STATUS, FIRMWARE_UPDATE_STATUS_VALUES);
MU_DEFINE_ENUM_STRINGS_WITHOUT_INVALID(FIRMWARE_UPDATE_STATUS, FIRMWARE_UPDATE_STATUS_VALUES);

static bool g_use_proxy = false;
static const char* PROXY_ADDRESS = "127.0.0.1";

static size_t g_message_count_send_confirmations = 0;

#define PROXY_PORT                  8888
#define MESSAGES_TO_SEND            50
#define TIME_BETWEEN_MESSAGES       2

#define MESSAGE_COUNT        3
static bool g_continueRunning = true;
static size_t g_message_recv_count = 0;
static const char* initialFirmwareVersion = "1.0.0";

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

typedef struct MESSAGESCHEMA_TAG
{
	char* name;
	char* format;
	char* fields;
} MessageSchema;

typedef struct TELEMETRYSCHEMA_TAG
{
	MessageSchema messageSchema;
} TelemetrySchema;

typedef struct TELEMETRY_PROPERTIES_TAG{
    TelemetrySchema temperatureSchema;
    TelemetrySchema humiditySchema;
    TelemetrySchema pressureSchema;
} TelemetryProperties;

typedef struct IOT_DEVICE_TAG{

    // Reported properties
	char* protocol;
	char* supportedMethods;
	char* type;
	char* firmware;
	FIRMWARE_UPDATE_STATUS firmwareUpdateStatus;
	char* location;
	double latitude;
	double longitude;
	TelemetryProperties telemetry;

	// Manage firmware update process
	char* new_firmware_version;
	char* new_firmware_URI;
    char* new_firmware_key;

}IoT_device;

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

#pragma region serializeToJson

static char* serializeToJson(IoT_device* device){

    char* result = NULL;

    JSON_Value* root_value = json_value_init_object();
    if(root_value != NULL){

        JSON_Object* root_object = json_value_get_object(root_value);

        if(root_object != NULL){

            //  Only reported properties
            (void)json_object_set_string(root_object, "Protocol", device->protocol);
            (void)json_object_set_string(root_object, "SupportedMethods", device->supportedMethods);
            (void)json_object_set_string(root_object, "Type", device->type);
            (void)json_object_set_string(root_object, "Firmware", device->firmware);
            (void)json_object_set_string(root_object, "FirmwareUpdateStatus",MU_ENUM_TO_STRING(FIRMWARE_UPDATE_STATUS, device->firmwareUpdateStatus));
            (void)json_object_set_string(root_object, "Location", device->location);
            (void)json_object_set_number(root_object, "Latitude", device->latitude);
            (void)json_object_set_number(root_object, "Longitude", device->longitude);
            (void)json_object_dotset_string(root_object, "Telemetry.TemperatureSchema.MessageSchema.Name", device->telemetry.temperatureSchema.messageSchema.name);
			(void)json_object_dotset_string(root_object, "Telemetry.TemperatureSchema.MessageSchema.Format", device->telemetry.temperatureSchema.messageSchema.format);
			(void)json_object_dotset_string(root_object, "Telemetry.TemperatureSchema.MessageSchema.Fields", device->telemetry.temperatureSchema.messageSchema.fields);
			(void)json_object_dotset_string(root_object, "Telemetry.HumiditySchema.MessageSchema.Name", device->telemetry.humiditySchema.messageSchema.name);
			(void)json_object_dotset_string(root_object, "Telemetry.HumiditySchema.MessageSchema.Format", device->telemetry.humiditySchema.messageSchema.format);
			(void)json_object_dotset_string(root_object, "Telemetry.HumiditySchema.MessageSchema.Fields", device->telemetry.humiditySchema.messageSchema.fields);
			(void)json_object_dotset_string(root_object, "Telemetry.PressureSchema.MessageSchema.Name", device->telemetry.pressureSchema.messageSchema.name);
			(void)json_object_dotset_string(root_object, "Telemetry.PressureSchema.MessageSchema.Format", device->telemetry.pressureSchema.messageSchema.format);
			(void)json_object_dotset_string(root_object, "Telemetry.PressureSchema.MessageSchema.Fields", device->telemetry.pressureSchema.messageSchema.fields);
        }

        result = json_serialize_to_string(root_value);

        json_value_free(root_value);

    }

    return result;

}

#pragma endregion


#pragma region deserializeJson


static IoT_device* deserializeJson(const char* json){

    IoT_device* device = malloc(sizeof(device));
    JSON_Value* root_value = NULL;
    JSON_Object* root_object = NULL;

    if(device == NULL){
        (void)printf("ERROR: Failed to allocate memory \r\n");
    }
    else{

        (void)memset(device, 0, sizeof(IoT_device));

        root_value = json_parse_string(json);
        root_object = json_value_get_object(root_value);

        // Only desired properties
        JSON_Value* new_firmware_version;
        JSON_Value* new_firmware_URI;
        JSON_Value* new_firmware_key;

        new_firmware_version = json_object_dotget_value(root_object, "new_firmware_version");
        new_firmware_URI = json_object_dotget_value(root_object, "new_firmware_URI");
        new_firmware_key = json_object_dotget_value(root_object,"new_firmware_key");

        const char* new_firmware_version_s = json_value_get_string(new_firmware_version);
        const char* new_firmware_URI_s = json_value_get_string(new_firmware_URI);
        const char* new_firmware_key_s = json_value_get_string(new_firmware_key);

        if(new_firmware_version_s != NULL && new_firmware_URI_s != NULL && new_firmware_key_s != NULL){
            
            device->new_firmware_version = malloc(strlen(new_firmware_version_s)+1);
            device->new_firmware_URI = malloc(strlen(new_firmware_URI_s)+1);
            device->new_firmware_key = malloc(strlen(new_firmware_key_s)+1);

            if(device->new_firmware_version != NULL && device->new_firmware_URI != NULL && device->new_firmware_key != NULL){
                (void)strcpy(device->new_firmware_version, new_firmware_version_s);
                (void)strcpy(device->new_firmware_URI, new_firmware_URI_s);
                (void)strcpy(device->new_firmware_key, new_firmware_key_s);
            }
        }
        json_value_free(root_value);
    }

    return device;
}

#pragma endregion

#pragma region ReportedProperties_functions
static void reported_state_callback(int status_code, void* userContextCallback)
{
	(void)userContextCallback;
	(void)printf("Device Twin reported properties update completed with result: %d\r\n", status_code);
}

static void sendIoTDeviceReportedProperties(IoT_device* iot_device){
    if(iot_device != NULL && device_ll_handle != NULL){
        char* reportedProperties = serializeToJson(iot_device);
        if(reportedProperties){
            (void)IoTHubDeviceClient_LL_SendReportedState(device_ll_handle, (const unsigned char*)reportedProperties, strlen(reportedProperties), reported_state_callback, NULL);
			free(reportedProperties);
        }
    }
}
#pragma endregion

#pragma region send_message

static void send_message(IOTHUB_DEVICE_CLIENT_LL_HANDLE device_ll_handle, char* message, char* schema){
    
    IOTHUB_MESSAGE_HANDLE message_handle = IoTHubMessage_CreateFromString(message);
    
    if(message_handle != NULL){
        // set system properties
        (void)IoTHubMessage_SetMessageId(message_handle, "MSG_ID");
        (void)IoTHubMessage_SetCorrelationId(message_handle, "CORE_ID");
        (void)IoTHubMessage_SetContentTypeSystemProperty(message_handle, "application%2fjson");
        (void)IoTHubMessage_SetContentEncodingSystemProperty(message_handle, "utf-8");

        // Set application properties
        MAP_HANDLE propMap = IoTHubMessage_Properties(message_handle);
        (void)Map_AddOrUpdate(propMap, "$$MessageSchema", schema);
		(void)Map_AddOrUpdate(propMap, "$$ContentType", "JSON");

        time_t now = time(0);
		struct tm* timeinfo;
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4996) /* Suppress warning about possible unsafe function in Visual Studio */
#endif
		timeinfo = gmtime(&now);
#ifdef _MSC_VER
#pragma warning(pop)
#endif
		char timebuff[50];
		strftime(timebuff, 50, "%Y-%m-%dT%H:%M:%SZ", timeinfo);
		(void)Map_AddOrUpdate(propMap, "$$CreationTimeUtc", timebuff);

        IoTHubDeviceClient_LL_SendEventAsync(device_ll_handle, message_handle, send_confirm_callback, NULL);

        IoTHubMessage_Destroy(message_handle);
    }
}

#pragma endregion

#pragma region device_methods

static int do_firmware_update(void *param){

    IoT_device *iot_device = (IoT_device *)param;
    printf("Running firmware update: URI: %s, Version: %s \r\n", iot_device->new_firmware_URI, iot_device->new_firmware_version);

    printf("Download started... \r\n");
    iot_device->firmwareUpdateStatus = DOWNLOADING;
    sendIoTDeviceReportedProperties(iot_device);

    ThreadAPI_Sleep(5000);

    printf("Download finished.... \r\n");

    printf("Setting Configurations.... \r\n");
    iot_device->firmwareUpdateStatus = APPLYING;
    sendIoTDeviceReportedProperties(iot_device);

    ThreadAPI_Sleep(5000);

    printf("Setting configuration finished.... \r\n");

    printf("Rebooting.... \r\n");
    iot_device->firmwareUpdateStatus = REBOOTING;
    sendIoTDeviceReportedProperties(iot_device);

    ThreadAPI_Sleep(5000);

    size_t size = strlen(iot_device->new_firmware_version) + 1;
    (void)memcpy(iot_device->firmware, iot_device->new_firmware_version, size);

    iot_device->firmwareUpdateStatus = IDLE;
    sendIoTDeviceReportedProperties(iot_device);

    return 0;
}

void getFirmwareUpdateValues(IoT_device* iot_device, const unsigned char* payload){

    if(iot_device != NULL){
        free(iot_device->new_firmware_version);
        free(iot_device->new_firmware_URI);
        iot_device->new_firmware_version = NULL;
        iot_device->new_firmware_URI = NULL;

        JSON_Value* root_value = json_parse_string((char*)payload);
        JSON_Object* root_object = json_value_get_object(root_value);

        JSON_Value* newFirmwareVersion = json_object_get_value(root_object, "Firmware");

        if(newFirmwareVersion != NULL){

            const char* data = json_value_get_string(newFirmwareVersion);
            if(data != NULL){

                size_t size = strlen(data) + 1;
                iot_device->new_firmware_version = malloc(size);
                if(iot_device->new_firmware_version != NULL){
                    (void)memcpy(iot_device->new_firmware_version, data, size);
                }
            }
        }

        JSON_Value* newFirmwareURI = json_object_get_value(root_object, "FirmwareUri");

        if(newFirmwareURI != NULL){
            const char* data = json_value_get_string(newFirmwareURI);
            if(data != NULL){
                size_t size = strlen(data)+1;
                iot_device->new_firmware_URI = malloc(size);
                if(iot_device->new_firmware_URI != NULL)
                {
                    (void)memcpy(iot_device->new_firmware_URI, data, size);
                }
            }
        }

        json_value_free(root_value);
    }

}

static int device_method_callback(const char* method_name, const unsigned char* payload, size_t size, unsigned char** response, size_t* response_size, void* userContextCallback)
{
    IoT_device *iot_device = (IoT_device *)userContextCallback;

    int result;

    (void)printf("Direct method name: %s \r\n", method_name);

    (void)printf("Direct method payload: %s\r\n", (int)size, (const char*)payload);

    if (strcmp(method_name,"Reboot_name") == 0){
        MESSAGERESPONSE(201, "{ \"Response\": \"Rebooting\" }")
    }
    else if(strcmp(method_name, "EmergencyValueRelease") == 0){
        MESSAGERESPONSE(201, "{ \"Response\": \"Releasing emergency valve\" }")
    }
    else if(strcmp(method_name, "IncreasePressure") == 0){
        MESSAGERESPONSE(201, "{ \"Response\": \"Increaing pressue\" }")
    }
    else if(strcmp(method_name, "FirmwareUpdate") == 0){
        if(iot_device->firmwareUpdateStatus != IDLE){
            (void)printf("Attempt to invoke firmware update out of order \n\n");
            MESSAGERESPONSE(400, "{ \"Response\": \"Attempting to initiate a firmware update out of order\" }")
        }
        else{
            getFirmwareUpdateValues(iot_device, payload);

            if(iot_device->new_firmware_version != NULL && iot_device->new_firmware_URI != NULL){

                // Create a thread for the long running firmware update process
                THREAD_HANDLE thread_apply;
                THREADAPI_RESULT t_result = ThreadAPI_Create(&thread_apply, do_firmware_update, iot_device);
				if (t_result == THREADAPI_OK)
				{
					(void)printf("Starting firmware update thread\r\n");
					MESSAGERESPONSE(201, "{ \"Response\": \"Starting firmware update thread\" }")
				}
				else
				{
					(void)printf("Failed to start firmware update thread\r\n");
					MESSAGERESPONSE(500, "{ \"Response\": \"Failed to start firmware update thread\" }")
				}
            }
            else
			{
				(void)printf("Invalid method payload\r\n");
				MESSAGERESPONSE(400, "{ \"Response\": \"Invalid payload\" }")
			}
        }
    }
    else
	{
		// All other entries are ignored.
		(void)printf("Method not recognized\r\n");
		MESSAGERESPONSE(400, "{ \"Response\": \"Method not recognized\" }")
	}

    return result;
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
    char msgText[1024];

    double minTemperature = 50.0;
	double minPressure = 55.0;
	double minHumidity = 30.0;
	double temperature = 0;
	double pressure = 0;
	double humidity = 0;
    
    bool traceOn = true;

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

            IoT_device iot_device;
            memset(&iot_device, 0, sizeof(iot_device));
            iot_device.protocol = "MQTT";
            iot_device.supportedMethods = "Reboot,FirmwareUpdate,EmergencyValveRelease,IncreasePressure";
            iot_device.type = "IoT_device";
            size_t size = strlen(initialFirmwareVersion) + 1;
            iot_device.firmware = malloc(size);

            if(iot_device.firmware == NULL){
                (void)printf("Device firmware failed to allocate memory. \r\n");
            }
            else{
                memcpy(iot_device.firmware, initialFirmwareVersion, size);
                iot_device.firmwareUpdateStatus = IDLE;
                iot_device.location = "Weingarten";
                iot_device.latitude = 47.638928;
                iot_device.longitude = -122.13476;
                iot_device.telemetry.temperatureSchema.messageSchema.name = "iot-device-temperature;v1";
                iot_device.telemetry.temperatureSchema.messageSchema.format = "JSON";
                iot_device.telemetry.temperatureSchema.messageSchema.fields = "{\"temperature\":\"Double\",\"temperature_unit\":\"Text\"}";
                iot_device.telemetry.humiditySchema.messageSchema.name = "iot-device-humidity;v1";
                iot_device.telemetry.humiditySchema.messageSchema.format = "JSON";
                iot_device.telemetry.humiditySchema.messageSchema.fields = "{\"humidity\":\"Double\",\"humidity_unit\":\"Text\"}";
                iot_device.telemetry.pressureSchema.messageSchema.name = "iot-device-pressure;v1";
                iot_device.telemetry.pressureSchema.messageSchema.format = "JSON";
                iot_device.telemetry.pressureSchema.messageSchema.fields = "{\"pressure\":\"Double\",\"pressure_unit\":\"Text\"}";

                sendIoTDeviceReportedProperties(&iot_device);

                (void)IoTHubDeviceClient_LL_SetDeviceMethodCallback(device_ll_handle, device_method_callback, &iot_device);

                while(1){

                    temperature = minTemperature + ((double)(rand() % 10) + 5);
                    pressure = minPressure + ((double)(rand() % 10) + 5);
                    humidity = minHumidity + ((double)(rand() % 20) + 5);

                    if(iot_device.firmwareUpdateStatus == IDLE){

                        (void)printf("Sending cuurrent value of Temperature sensor = %f %s \r\n", temperature, "F");
                        (void)sprintf_s(msgText, sizeof(msgText), "{\"temperature\":%.2f,\"temperature_unit\":\"F\"}", temperature);
                        send_message(device_ll_handle, msgText, iot_device.telemetry.temperatureSchema.messageSchema.name);

                        (void)printf("Sending sensor value Pressure = %f %s,\r\n", pressure, "psig");
                        (void)sprintf_s(msgText, sizeof(msgText), "{\"pressure\":%.2f,\"pressure_unit\":\"psig\"}", pressure);
                        send_message(device_ll_handle, msgText, iot_device.telemetry.pressureSchema.messageSchema.name);


                        (void)printf("Sending sensor value Humidity = %f %s,\r\n", humidity, "%");
                        (void)sprintf_s(msgText, sizeof(msgText), "{\"humidity\":%.2f,\"humidity_unit\":\"%%\"}", humidity);
                        send_message(device_ll_handle, msgText, iot_device.telemetry.humiditySchema.messageSchema.name);

                    }

                    ThreadAPI_Sleep(5000);
                }

                (void)printf("\r\nShutting down\r\n");

                // Clean up the iothub sdk handle and free resources
                IoTHubDeviceClient_LL_Destroy(device_ll_handle);
                free(iot_device.firmware);
                free(iot_device.new_firmware_URI);
                free(iot_device.new_firmware_version);
            }
        }
    }

    #pragma endregion
    
    // Free all the sdk subsystem
    IoTHub_Deinit();

#ifdef USE_C2D_ASYNC_ACK
    singlylinkedlist_destroy(g_cloudMessages);
#endif

    return 0;
}
