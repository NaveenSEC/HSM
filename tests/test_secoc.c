/**
 * @file  test_secoc.c
 * @brief SecOC tests: authenticated PDUs (MAC generate on TX, MAC verify on
 *        RX via CSM/HSM), tampering, replay, freshness reconstruction.
 */
#include "test_helpers.h"
#include "SecOC.h"
#include "App.h"
#include "hsm_cmac.h"

static void setup_app(void)
{
    TEST_ASSERT_EQUAL(EOL_OK, fixture_provisioned_ecu());
    TEST_ASSERT_EQUAL(TESTER_OK, flash_app(1, 0x1000));
    TEST_ASSERT_EQUAL(ECU_STATE_APPLICATION, Ecu_GetState());
}

static void test_secoc_roundtrip_and_layout(void)
{
    uint8 pdu[16], dta[16], mac[16];
    uint32 len = sizeof pdu;
    uint16 speed = 0;
    setup_app();
    TEST_ASSERT_EQUAL(E_OK, App_SendVehicleSpeed(1234, pdu, &len));
    /* 2 data + 1 freshness + 3 MAC */
    TEST_ASSERT_EQUAL(6, len);
    TEST_ASSERT_EQUAL(0x04, pdu[0]);
    TEST_ASSERT_EQUAL(0xD2, pdu[1]);
    TEST_ASSERT_EQUAL(0x01, pdu[2]);          /* freshness LSB = 1 */
    /* reference MAC: DataId | data | FV(32) */
    dta[0] = 0x01; dta[1] = 0x00; dta[2] = 0x04; dta[3] = 0xD2;
    dta[4] = 0; dta[5] = 0; dta[6] = 0; dta[7] = 1;
    Hsm_Cmac(Backend_DemoKeys.secocKey, dta, 8, mac);
    TEST_ASSERT_EQUAL_MEMORY(mac, &pdu[3], 3);

    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONSUCCESS, App_ReceiveVehicleSpeed(pdu, len, &speed));
    TEST_ASSERT_EQUAL(1234, speed);
}

static void test_secoc_detects_tampering(void)
{
    uint8 pdu[16];
    uint32 len = sizeof pdu;
    uint16 speed = 0;
    setup_app();
    TEST_ASSERT_EQUAL(E_OK, App_SendVehicleSpeed(50, pdu, &len));
    pdu[1] ^= 0x40;   /* attacker changes 50 -> 114 km/h */
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONFAILURE, App_ReceiveVehicleSpeed(pdu, len, &speed));
    pdu[1] ^= 0x40;
    pdu[5] ^= 0x01;   /* corrupted MAC */
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONFAILURE, App_ReceiveVehicleSpeed(pdu, len, &speed));
    pdu[5] ^= 0x01;
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONSUCCESS, App_ReceiveVehicleSpeed(pdu, len, &speed));
}

static void test_secoc_replay_rejected(void)
{
    uint8 pdu1[16], pdu2[16];
    uint32 l1 = sizeof pdu1, l2 = sizeof pdu2;
    uint16 speed;
    setup_app();
    TEST_ASSERT_EQUAL(E_OK, App_SendVehicleSpeed(10, pdu1, &l1));
    TEST_ASSERT_EQUAL(E_OK, App_SendVehicleSpeed(20, pdu2, &l2));
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONSUCCESS, App_ReceiveVehicleSpeed(pdu1, l1, &speed));
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONSUCCESS, App_ReceiveVehicleSpeed(pdu2, l2, &speed));
    TEST_ASSERT_EQUAL(20, speed);
    /* replay of the first PDU: truncated FV=1 reconstructs to 0x101 -> MAC fails */
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONFAILURE, App_ReceiveVehicleSpeed(pdu1, l1, &speed));
    /* replay of the last PDU */
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONFAILURE, App_ReceiveVehicleSpeed(pdu2, l2, &speed));
}

static void test_secoc_freshness_wraparound(void)
{
    uint8 pdu[16];
    uint32 len;
    uint16 speed = 0;
    uint32 i;
    setup_app();
    /* send 300 messages; receiver only sees each one -> truncated 8-bit FV wraps */
    for (i = 0; i < 300; i++)
    {
        len = sizeof pdu;
        TEST_ASSERT_EQUAL(E_OK, App_SendVehicleSpeed((uint16)i, pdu, &len));
        TEST_ASSERT_EQUAL(SECOC_VERIFICATIONSUCCESS, App_ReceiveVehicleSpeed(pdu, len, &speed));
    }
    TEST_ASSERT_EQUAL(299, speed);
    TEST_ASSERT_EQUAL(300, SecOC_GetRxFreshness(APP_PDU_VEHICLE_SPEED));
}

static void test_secoc_lost_messages_resync(void)
{
    uint8 pdu[16];
    uint32 len;
    uint16 speed = 0;
    uint32 i;
    setup_app();
    for (i = 0; i < 10; i++)
    {
        len = sizeof pdu;
        TEST_ASSERT_EQUAL(E_OK, App_SendVehicleSpeed((uint16)i, pdu, &len));
    }
    /* receiver missed 9 messages: still accepted (FV 10 > 0) */
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONSUCCESS, App_ReceiveVehicleSpeed(pdu, len, &speed));
    TEST_ASSERT_EQUAL(9, speed);
}

static void test_secoc_64bit_mac_pdu(void)
{
    uint8 data[8] = {1,2,3,4,5,6,7,8};
    uint8 sec[32], out[32];
    uint32 ls = sizeof sec, lo = 0;
    setup_app();
    TEST_ASSERT_EQUAL(E_OK, SecOC_Authenticate(APP_PDU_BRAKE_CMD, data, 8, sec, &ls));
    TEST_ASSERT_EQUAL(8 + 2 + 8, ls);
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONSUCCESS, SecOC_Verify(APP_PDU_BRAKE_CMD, sec, ls, out, &lo));
    TEST_ASSERT_EQUAL_MEMORY(data, out, 8);
    sec[ls - 1] ^= 0x80;
    SecOC_SetRxFreshness(APP_PDU_BRAKE_CMD, 0);
    TEST_ASSERT_EQUAL(SECOC_VERIFICATIONFAILURE, SecOC_Verify(APP_PDU_BRAKE_CMD, sec, ls, out, &lo));
}

int main(void)
{
    printf("Suite: SecOC (MAC generation / verification in the application)\n");
    RUN_TEST(test_secoc_roundtrip_and_layout);
    RUN_TEST(test_secoc_detects_tampering);
    RUN_TEST(test_secoc_replay_rejected);
    RUN_TEST(test_secoc_freshness_wraparound);
    RUN_TEST(test_secoc_lost_messages_resync);
    RUN_TEST(test_secoc_64bit_mac_pdu);
    return ut_summary("secoc");
}
