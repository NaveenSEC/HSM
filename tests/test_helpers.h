/**
 * @file  test_helpers.h
 * @brief Common fixture: virgin ECU -> EOL provisioning -> (optional) app flash.
 */
#ifndef TEST_HELPERS_H
#define TEST_HELPERS_H

#include "unity_lite.h"
#include "Ecu.h"
#include "Eol.h"
#include "Backend.h"
#include "Tester.h"
#include "MemMap_Layout.h"

static const uint8 TEST_UID[15] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE };

static uint8  test_image[APP_HEADER_SIZE + 0x8000];
static uint32 test_image_len;

static inline Eol_ResultType fixture_provisioned_ecu(void)
{
    Ecu_SimSetEntropySeed(0xC0FFEEu);
    Ecu_FactoryInit(TEST_UID);
    (void)Ecu_Reset();
    return Eol_ProvisionEcu(TEST_UID, &Backend_DemoKeys);
}

static inline void build_image(uint32 swVersion, uint32 bodyLen)
{
    static uint8 body[0x8000];
    Backend_BuildDemoAppBody(swVersion, body, bodyLen);
    (void)Backend_BuildAppImage(swVersion, body, bodyLen, Backend_DemoKeys.flashVerifyKey,
                                test_image, sizeof(test_image), &test_image_len);
}

static inline Tester_ResultType flash_app(uint32 swVersion, uint32 bodyLen)
{
    build_image(swVersion, bodyLen);
    return Tester_FlashApplication(test_image, test_image_len, Backend_DemoKeys.diagKey);
}

#endif
