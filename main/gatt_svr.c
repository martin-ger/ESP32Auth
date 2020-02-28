/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"
#include "lwip/def.h"
#include "bleprph.h"

#include "ctap.h"
#include "u2f.h"

/**
 * Defines for the Device Information Service
 */

#define gatt_svr_chr_manufacturer_name_string_uuid 0x2A29
#define gatt_svr_chr_model_number_string_uuid 0x2A24
#define gatt_svr_chr_firmware_revision_string_uuid 0x2A26

const char* manufacturer_name =  "Espressif";
const char* model_number =  "ESP32";
const char* firmware_revision = "0.1.0";

const char* u2fServiceRevision = "1.0";
#define U2F_SERVICE_REVISION R1_0

static int
gatt_svr_chr_access_device_info(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt,
                             void *arg);

/**
 * Defines from the FIDO Bluetooth Specification v1.0
 */

/* F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB */
static const ble_uuid128_t gatt_svr_chr_u2fControlPoint_uuid =
    BLE_UUID128_INIT(0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
                     0xee, 0xec, 0xaa, 0xde, 0xf1, 0xff, 0xd0, 0xf1);

/* F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB */
static const ble_uuid128_t gatt_svr_chr_u2fStatus_uuid =
    BLE_UUID128_INIT(0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
                     0xee, 0xec, 0xaa, 0xde, 0xf2, 0xff, 0xd0, 0xf1);

/* F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB */
static const ble_uuid128_t gatt_svr_chr_u2fControlPointLength_uuid =
    BLE_UUID128_INIT(0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
                     0xee, 0xec, 0xaa, 0xde, 0xf3, 0xff, 0xd0, 0xf1);

#define gatt_svr_chr_u2fServiceRevision_uuid 0x2A28
#if U2F_SERVICE_REVISION != R1_0
/* F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB */
static const ble_uuid128_t gatt_svr_chr_u2fServiceRevisionBitfield_uuid =
    BLE_UUID128_INIT(0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
                     0xee, 0xec, 0xaa, 0xde, 0xf4, 0xff, 0xd0, 0xf1);
#endif

#define CONTROL_POINT_LENGTH 256
#define MAX_COMMAND_LEN 4096

#define CMD_PING        0x81
#define CMD_KEEPALIVE   0x82
#define CMD_MSG         0x83
#define CMD_ERROR       0xbf

#define ERR_INVALID_CMD	0x01
#define ERR_INVALID_PAR	0x02
#define ERR_INVALID_LEN	0x03
#define ERR_INVALID_SEQ	0x04
#define ERR_REQ_TIMEOUT	0x05
#define ERR_OTHER	    0x7f

static int
gatt_svr_chr_access_fido(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt,
                             void *arg);

static const struct ble_gatt_svc_def gatt_svr_svcs[] = {
    {
        /*** Service: FIDO Authenticator. */
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(gatt_svr_scv_fifo_uuid),
        .characteristics = (struct ble_gatt_chr_def[])
        { {
                /*** Characteristic: U2F Control Point. */
                .uuid = &gatt_svr_chr_u2fControlPoint_uuid.u,
                .access_cb = gatt_svr_chr_access_fido,
                .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
            }, {
                /*** Characteristic: U2F Status. */
                .uuid = &gatt_svr_chr_u2fStatus_uuid.u,
                .access_cb = gatt_svr_chr_access_fido,
                .flags = BLE_GATT_CHR_F_NOTIFY,
            }, {
                /*** Characteristic: U2F Control Point Length. */
                .uuid = &gatt_svr_chr_u2fControlPointLength_uuid.u,
                .access_cb = gatt_svr_chr_access_fido,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            }, {
                /*** Characteristic: U2F Service Revision. */
                .uuid = BLE_UUID16_DECLARE(gatt_svr_chr_u2fServiceRevision_uuid),
                .access_cb = gatt_svr_chr_access_fido,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            },
            /* Spec says: If only version 1.0 is supported, this characteristic SHALL be omitted. */
#if U2F_SERVICE_REVISION != R1_0
               {
                /*** Characteristic: U2F Service Revision Bitfield. */
                .uuid = &gatt_svr_chr_u2fServiceRevisionBitfield_uuid.u,
                .access_cb = gatt_svr_chr_access_fido,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC | 
                         BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
            },
#endif
            {
                0, /* No more characteristics in this service. */
            }
        },
    },

    {
        /*** Service: Device Information. */
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(gatt_svr_scv_device_information_uuid),
        .characteristics = (struct ble_gatt_chr_def[])
        { {
                /*** Characteristic: Manufacturer Name String. */
                .uuid = BLE_UUID16_DECLARE(gatt_svr_chr_manufacturer_name_string_uuid),
                .access_cb = gatt_svr_chr_access_device_info,
               .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            }, {
                /*** Characteristic: Model Number String. */
                .uuid = BLE_UUID16_DECLARE(gatt_svr_chr_model_number_string_uuid),
                .access_cb = gatt_svr_chr_access_device_info,
               .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            }, {                
                /*** Characteristic: Firmware Revision String. */
                .uuid = BLE_UUID16_DECLARE(gatt_svr_chr_firmware_revision_string_uuid),
                .access_cb = gatt_svr_chr_access_device_info,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC,
            }, {
                0, /* No more characteristics in this service. */
            }
        },
    },

    {
        0, /* No more services. */
    },
};

static int
gatt_svr_chr_write(struct os_mbuf *om, uint16_t min_len, uint16_t max_len,
                   void *dst, uint16_t *len)
{
    uint16_t om_len;
    int rc;

    om_len = OS_MBUF_PKTLEN(om);
    if (om_len < min_len || om_len > max_len) {
        return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
    }

    rc = ble_hs_mbuf_to_flat(om, dst, max_len, len);
    if (rc != 0) {
        return BLE_ATT_ERR_UNLIKELY;
    }

    return 0;
}

static uint8_t u2fControlPoint[CONTROL_POINT_LENGTH];
static uint8_t u2fCommand[MAX_COMMAND_LEN];
static uint8_t cmd;
static uint16_t next_frag = 0;
static uint16_t expected_total_len = 0;
static uint8_t packet_seqnr = 0;
static bool expect_fragment = false;
static uint16_t u2f_connection;

static int
gatt_svr_send_response(uint8_t resp_status, const uint8_t* resp_data, const uint16_t resp_len)
{
    uint16_t u2f_status_attr_handle;
    uint8_t resp_mesg[resp_len+3];

    MODLOG_DFLT(INFO, "Response: sending code %d, length %d\n", resp_status, resp_len);
    ble_gatts_find_chr(BLE_UUID16_DECLARE(gatt_svr_scv_fifo_uuid), 
                                          &gatt_svr_chr_u2fStatus_uuid.u, 
                                          NULL, &u2f_status_attr_handle);
    if (u2f_status_attr_handle == 0) {
        MODLOG_DFLT(INFO, "Response: lookup of handle failed\n");
        return -1;
    }

    resp_mesg[0] = resp_status;
    resp_mesg[1] = resp_len/0x100;
    resp_mesg[2] = resp_len%0x100;
    memcpy(&resp_mesg[3], resp_data, resp_len);
    ble_gattc_write_no_rsp_flat(u2f_connection, u2f_status_attr_handle, resp_mesg, resp_len+3);
    return 0;
}

int
gatt_svr_send_error(uint8_t error_code)
{
    return gatt_svr_send_response(CMD_ERROR, &error_code, 1);
}

static int
gatt_svr_chr_access_fido(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt,
                             void *arg)
{
    const ble_uuid_t *uuid;
    char buf[BLE_UUID_STR_LEN];
    int rc;

    u2f_connection = conn_handle;

    uuid = ctxt->chr->uuid;

    MODLOG_DFLT(INFO, "Access to char %s (handle %d)\n", ble_uuid_to_str(uuid, buf), attr_handle);

    /* Determine which characteristic is being accessed by examining its
     * 128-bit UUID.
     */
;
    if (ble_uuid_cmp(uuid, &gatt_svr_chr_u2fControlPoint_uuid.u) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR);
        uint16_t received_len;
        CTAP_RESPONSE ctap_resp;

        rc = gatt_svr_chr_write(ctxt->om,
                                1,
                                CONTROL_POINT_LENGTH,
                                (void*) &u2fControlPoint, &received_len);
        if (rc != 0) {
            MODLOG_DFLT(INFO, "Error %d during receive\n", rc);
            return rc;
        }

        MODLOG_DFLT(INFO, "Received %d bytes on char u2fControlPoint\n", received_len);
        MODLOG_DFLT(INFO, "[%d][%d][%d]...\n", u2fControlPoint[0], u2fControlPoint[1], u2fControlPoint[2]);

        if (u2fControlPoint[0] & 0x80)
        {
            // Is command
            cmd = u2fControlPoint[0];

            if (received_len < 3) {
                MODLOG_DFLT(INFO, "Command too short\n");
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            }
            expected_total_len = u2fControlPoint[1] * 0x100 + u2fControlPoint[2];
            if (expected_total_len > MAX_COMMAND_LEN || (received_len-3) > expected_total_len) {
                MODLOG_DFLT(INFO, "Command too long\n");
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
            }
            memcpy(u2fCommand, &u2fControlPoint[3], received_len-3);

            if (expected_total_len > (received_len-3)) {
                MODLOG_DFLT(INFO, "Expecting fragmented send of %d bytes\n", expected_total_len);
                next_frag = received_len-3;
                expect_fragment = true;
                packet_seqnr = 0;
                return 0;
            }
            // Got complete command

        } else {
            // Is continuation fragment
            if (!expect_fragment || u2fCommand[0] != packet_seqnr) {
                MODLOG_DFLT(INFO, "Fragmentation error: invalid frags\n");
                packet_seqnr = 0;
                next_frag = 0;
                expect_fragment = false;
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;                
            }
            uint16_t current_len = next_frag+received_len-1;
            if (current_len >  expected_total_len) {
                MODLOG_DFLT(INFO, "Fragmentation error: message too long\n");
                packet_seqnr = 0;
                next_frag = 0;
                expect_fragment = false;
                return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;                
            }
            memcpy(&u2fCommand[next_frag], &u2fControlPoint[1], received_len-1);

            if (current_len < expected_total_len) {
                // More to come
                MODLOG_DFLT(INFO, "Received %d/%d bytes\n", current_len, expected_total_len);
                next_frag = current_len;
                packet_seqnr++;
                expect_fragment = true;
                return 0;
            }
            // Got last frag
        }
        // Have complete message
        packet_seqnr = 0;
        next_frag = 0;
        expect_fragment = false;

        MODLOG_DFLT(INFO, "Received complete message of %d bytes, cmd: %d\n", expected_total_len, cmd);

        if (cmd == CMD_MSG) {
            ctap_response_init(&ctap_resp);
            MODLOG_DFLT(INFO, "Buffer init\n");
            u2f_request((struct u2f_request_apdu*)u2fCommand, &ctap_resp);
            MODLOG_DFLT(INFO, "Did response\n");            
        }

        gatt_svr_send_response(CMD_MSG, ctap_resp.data, ctap_resp.length);

        return rc;
    }

    if (ble_uuid_cmp(uuid, &gatt_svr_chr_u2fControlPointLength_uuid.u) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);

        uint16_t cpl = htons(CONTROL_POINT_LENGTH);
        rc = os_mbuf_append(ctxt->om, &cpl, sizeof cpl);
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    if (ble_uuid_cmp(uuid, BLE_UUID16_DECLARE(gatt_svr_chr_u2fServiceRevision_uuid)) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);

        rc = os_mbuf_append(ctxt->om, u2fServiceRevision, strlen(u2fServiceRevision));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
#if U2F_SERVICE_REVISION != R1_0
    if (ble_uuid_cmp(uuid, &gatt_svr_chr_u2fServiceRevisionBitfield_uuid.u) == 0) {
        switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_READ_CHR:
            // tbd

        case BLE_GATT_ACCESS_OP_WRITE_CHR:
            // tbd
        default:
            assert(0);
            return BLE_ATT_ERR_UNLIKELY;
        }
    }
#endif

    /* Unknown characteristic; the nimble stack should not have called this
     * function.
     */
    assert(0);
    return BLE_ATT_ERR_UNLIKELY;
}

static int
gatt_svr_chr_access_device_info(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt,
                             void *arg)
{
    const ble_uuid_t *uuid;
    char buf[BLE_UUID_STR_LEN];
    int rc;

    uuid = ctxt->chr->uuid;

    MODLOG_DFLT(INFO, "Access to char %s (handle %d)\n", ble_uuid_to_str(uuid, buf), attr_handle);

    /* Determine which characteristic is being accessed by examining its UUID.
     */

    if (ble_uuid_cmp(uuid, BLE_UUID16_DECLARE(gatt_svr_chr_manufacturer_name_string_uuid)) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);

        rc = os_mbuf_append(ctxt->om, manufacturer_name, strlen(manufacturer_name));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    if (ble_uuid_cmp(uuid, BLE_UUID16_DECLARE(gatt_svr_chr_model_number_string_uuid)) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);

        rc = os_mbuf_append(ctxt->om, model_number, strlen(model_number));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    if (ble_uuid_cmp(uuid, BLE_UUID16_DECLARE(gatt_svr_chr_firmware_revision_string_uuid)) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);

        rc = os_mbuf_append(ctxt->om, firmware_revision, strlen(firmware_revision));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    /* Unknown characteristic; the nimble stack should not have called this
     * function.
     */
    assert(0);
    return BLE_ATT_ERR_UNLIKELY;
}

void
gatt_svr_register_cb(struct ble_gatt_register_ctxt *ctxt, void *arg)
{
    char buf[BLE_UUID_STR_LEN];

    switch (ctxt->op) {
    case BLE_GATT_REGISTER_OP_SVC:
        MODLOG_DFLT(INFO, "registered service %s with handle=%d\n",
                    ble_uuid_to_str(ctxt->svc.svc_def->uuid, buf),
                    ctxt->svc.handle);
        break;

    case BLE_GATT_REGISTER_OP_CHR:
        MODLOG_DFLT(INFO, "registering characteristic %s with "
                    "def_handle=%d val_handle=%d\n",
                    ble_uuid_to_str(ctxt->chr.chr_def->uuid, buf),
                    ctxt->chr.def_handle,
                    ctxt->chr.val_handle);
        break;

    case BLE_GATT_REGISTER_OP_DSC:
        MODLOG_DFLT(INFO, "registering descriptor %s with handle=%d\n",
                    ble_uuid_to_str(ctxt->dsc.dsc_def->uuid, buf),
                    ctxt->dsc.handle);
        break;

    default:
        assert(0);
        break;
    }
}

int
gatt_svr_init(void)
{
    int rc;

    ble_svc_gap_init();
    ble_svc_gatt_init();

    rc = ble_gatts_count_cfg(gatt_svr_svcs);
    if (rc != 0) {
        return rc;
    }

    rc = ble_gatts_add_svcs(gatt_svr_svcs);
    if (rc != 0) {
        return rc;
    }

    return 0;
}
