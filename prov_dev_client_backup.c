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

typedef struct IOT_DEVICE_TAG{

    // desired properties
    char* desired_firmwareVersion;
    char* desired_firmwareURI

    // Reported properties
	char* current_firmware_version;
	FIRMWARE_UPDATE_STATUS firmwareUpdateStatus;

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
            (void)json_object_set_string(root_object, "CurrentFirmwareVersion", device->current_firmware_version);
            (void)json_object_set_string(root_object, "FirmwareUpdateStatus",MU_ENUM_TO_STRING(FIRMWARE_UPDATE_STATUS, device->firmwareUpdateStatus));
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
        JSON_Value* desired_firmware_version;
        JSON_Value* desired_firmware_URI;

        desired_firmware_version = json_object_dotget_value(root_object, "DesiredFirmwareVersion");
        desired_firmware_URI = json_object_dotget_value(root_object, "DesiredFirmwareURI");

        const char* new_firmware_version_s = json_value_get_string(desired_firmware_version);
        const char* new_firmware_URI_s = json_value_get_string(desired_firmware_URI);

        if(new_firmware_version_s != NULL && new_firmware_URI_s != NULL){
            
            device->desired_firmwareVersion = malloc(strlen(new_firmware_version_s)+1);
            device->desired_firmwareURI = malloc(strlen(new_firmware_URI_s)+1);

            if(device->desired_firmwareVersion != NULL && device->desired_firmwareURI != NULL){
                (void)strcpy(device->desired_firmwareVersion, new_firmware_version_s);
                (void)strcpy(device->desired_firmwareURI, new_firmware_URI_s);
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


            // set the callback function for c2d messages
            //(void)IoTHubDeviceClient_LL_SetMessageCallback(device_ll_handle, receive_msg_callback, &iothub_info);
            if (IoTHubDeviceClient_LL_SetMessageCallback(device_ll_handle, receive_msg_callback, &messages_count) != IOTHUB_CLIENT_OK)
            {
                (void)printf("ERROR: IoTHubClient_LL_SetMessageCallback..........FAILED!\r\n");
            }
            else{
                (void)printf("Sending 1 messages to IoTHub every %d seconds for %d messages (Send any message to stop)\r\n", TIME_BETWEEN_MESSAGES, MESSAGES_TO_SEND);
                do
                {
                    if (iothub_info.connected != 0)
                    {
                        // Send a message every TIME_BETWEEN_MESSAGES seconds
                        (void)tickcounter_get_current_ms(tick_counter_handle, &current_tick);
                        if ((current_tick - last_send_time) / 1000 > TIME_BETWEEN_MESSAGES)
                        {
                            /* Sending telemetry data to cloud*/
                            temperature = minTemperature + ((double)(rand() % 10) + 5);
                            pressure = minPressure + ((double)(rand() % 10) + 5);
                            humidity = minHumidity + ((double)(rand() % 20) + 5);

                            sprintf(msgText, "{\"temperature\":%.2f,\"humidity\":%.2f,\"pressure\":\"%.2f\"}", temperature, humidity, pressure);
                            printf("\n \n %s \n \n", msgText);
                            msg_count++;
                            
                            //IOTHUB_MESSAGE_HANDLE msg_handle = IoTHubMessage_CreateFromString((const unsigned char*)msgText, strlen(msgText));
                            IOTHUB_MESSAGE_HANDLE msg_handle = IoTHubMessage_CreateFromString(msgText);

                            (void)IoTHubMessage_SetContentTypeSystemProperty(msg_handle, "application%2fjson");
                            (void)IoTHubMessage_SetContentEncodingSystemProperty(msg_handle, "utf-8");

                            if (msg_handle == NULL)
                            {
                                (void)printf("ERROR: iotHubMessageHandle is NULL!\r\n");
                            }
                            else
                            {
                                //if (IoTHubDeviceClient_LL_SendEventAsync(device_ll_handle, msg_handle, NULL, NULL) != IOTHUB_CLIENT_OK)
                                if (IoTHubDeviceClient_LL_SendEventAsync(device_ll_handle, msg_handle, send_confirm_callback, NULL) != IOTHUB_CLIENT_OK)
                                {
                                    (void)printf("ERROR: IoTHubClient_LL_SendEventAsync..........FAILED!\r\n");
                                }
                                else
                                {
                                    (void)tickcounter_get_current_ms(tick_counter_handle, &last_send_time);
                                    (void)printf("IoTHubClient_LL_SendEventAsync accepted message [%zu] for transmission to IoT Hub.\r\n", msg_count);

                                }
                                IoTHubMessage_Destroy(msg_handle);
                            }
                        }
                    }

                    if (g_message_recv_count >= MESSAGE_COUNT)
                    {
                        // After all messages are all received stop running
                        g_continueRunning = false;
                    }

#ifdef USE_C2D_ASYNC_ACK
                    // If using delayed acknowledgement of cloud-to-device messages, this function serves as an example of
                    // how to do so for all the previously received messages still present in the list used by this sample.
                    acknowledge_cloud_messages(device_ll_handle);
#endif

                    IoTHubDeviceClient_LL_DoWork(device_ll_handle);
                    ThreadAPI_Sleep(1);
                } while (iothub_info.stop_running == 0 && msg_count < MESSAGES_TO_SEND);

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
