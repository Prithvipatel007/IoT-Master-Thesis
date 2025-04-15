#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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

#include "iothub_deviceconfiguration.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <wiringPi.h>

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

#define TIME_BETWEEN_TELE_MESSAGES 60

#define LedPin 0

size_t g_message_count_send_confirmations = 0;

static void send_confirm_callback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{
    (void)userContextCallback;
    // When a message is sent this callback will get invoked
    g_message_count_send_confirmations++;
    (void)printf("Confirmation callback received for message %lu with result %s\r\n", (unsigned long)g_message_count_send_confirmations, MU_ENUM_TO_STRING(IOTHUB_CLIENT_CONFIRMATION_RESULT, result));
}

int Application(void *param)
{
    IOTHUB_DEVICE_CLIENT_LL_HANDLE device_ll_handle = (IOTHUB_DEVICE_CLIENT_LL_HANDLE)param;
    
    TICK_COUNTER_HANDLE tick_counter_handle = tickcounter_create();
    tickcounter_ms_t current_tick;
    tickcounter_ms_t last_send_time = 0;

    size_t msg_count = 0;
    char msgText[1024];

    double minTemperature = 50.0;
	double minPressure = 55.0;
	double minHumidity = 30.0;
	double temperature = 0;
	double pressure = 0;
	double humidity = 0;

    if(wiringPiSetup() == -1) { //when initialize wiringPi failed, print message to screen
        printf("setup wiringPi failed !\n");
        return -1;
    }

    pinMode (LedPin, OUTPUT);

    while(1){

        digitalWrite (0, HIGH) ; delay (500) ;
        digitalWrite (0,  LOW) ; delay (500) ;
        
        (void)tickcounter_get_current_ms(tick_counter_handle, &current_tick);
        if ((current_tick - last_send_time) / 1000 > TIME_BETWEEN_TELE_MESSAGES)
        {
            temperature = minTemperature + ((double)(rand() % 10) + 5);
            pressure = minPressure + ((double)(rand() % 10) + 5);
            humidity = minHumidity + ((double)(rand() % 20) + 5);

            sprintf(msgText, "{\"temperature\":%.2f,\"humidity\":%.2f,\"pressure\":\"%.2f\"}", temperature, humidity, pressure);
            msg_count++;

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

            (void)tickcounter_get_current_ms(tick_counter_handle, &last_send_time);
        }
    }


    



    

    
}