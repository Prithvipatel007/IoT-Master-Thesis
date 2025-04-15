#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.7)

PROJECT(provisioning_sample C)

# Set Azure IoT SDK C settings
set(use_mqtt ON CACHE  BOOL "Set mqtt on" FORCE )
set(skip_samples ON CACHE  BOOL "Set slip_samples on" FORCE )
set(BUILD_TESTING OFF CACHE  BOOL "Set BUILD_TESTING off" FORCE )

# Add Azure IoT SDK C
add_subdirectory(azure-iot-sdk-c out)

compileAsC99()

set(provisioning_sample_c_files
    prov_dev_client.c
    application.h
    application.c
)

set(prov_dev_client_h_files
)

IF(WIN32)
    #windows needs this define
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-DGB_MEASURE_MEMORY_FOR_THIS -DGB_DEBUG_ALLOC)
ENDIF(WIN32)

if(${use_sample_trusted_cert})
    add_definitions(-DSET_TRUSTED_CERT_IN_SAMPLES)
    include_directories(${PROJECT_SOURCE_DIR}/certs)
    set(provisioning_sample_c_files ${provisioning_sample_c_files} ${PROJECT_SOURCE_DIR}/certs/certs.c)
endif()

include_directories(.)
include_directories(azure-iot-sdk-c/iothub_service_client/inc)
include_directories(azure-iot-sdk-c/iothub_client/inc)
include_directories(${DEV_AUTH_MODULES_CLIENT_INC_FOLDER})
include_directories(azure-iot-sdk-c/c-utility/inc)
include_directories(azure-iot-sdk-c/c-utility/adapters)

include_directories(${MACRO_UTILS_INC_FOLDER})
include_directories(${IOTHUB_CLIENT_INC_FOLDER})
include_directories((azure-iot-sdk-c/deps/parson))
include_directories(azure-iot-sdk-c/deps/umock-c/inc)
include_directories(azure-iot-sdk-c/deps/c-utility/deps/azure-macro-utils-c/inc)


add_executable(prov_dev_client ${provisioning_sample_c_files} ${prov_dev_client_h_files})

if(${use_openssl})
    add_definitions(-DUSE_OPENSSL)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_OPENSSL")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_OPENSSL")
    if (WIN32)
        target_link_libraries(prov_dev_client $ENV{OpenSSLDir}/lib/ssleay32.lib $ENV{OpenSSLDir}/lib/libeay32.lib)
        file(COPY $ENV{OpenSSLDir}/bin/libeay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
        file(COPY $ENV{OpenSSLDir}/bin/ssleay32.dll DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/Debug)
    endif()
endif()

if (${use_http})
    target_link_libraries(prov_dev_client prov_http_transport)
    add_definitions(-DUSE_HTTP)
endif()
if (${use_mqtt})
    target_link_libraries(prov_dev_client prov_mqtt_transport prov_mqtt_ws_transport iothub_client_mqtt_transport)
    linkMqttLibrary(prov_dev_client)
    add_definitions(-DUSE_MQTT)
endif()
if (${use_amqp})
    target_link_libraries(prov_dev_client prov_amqp_ws_transport prov_amqp_transport iothub_client_amqp_transport)
    linkUAMQP(prov_dev_client)
    add_definitions(-DUSE_AMQP)
endif()

target_link_libraries(prov_dev_client
    iothub_client
    iothub_service_client
    prov_device_ll_client
    prov_auth_client
    aziotsharedutil
    hsm_security_client
    wiringPi
)
