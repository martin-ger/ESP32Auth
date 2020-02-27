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
#include "bleprph.h"

#define gatt_svr_chr_manufacturer_name_string_uuid 0x2A29
#define gatt_svr_chr_model_number_string_uuid 0x2A24
#define gatt_svr_chr_firmware_revision_string_uuid 0x2A26

const char* manufacturer_name =  "Espressif";
const char* model_number =  "ESP32";
const char* firmware_revision = "0.1.0";

#define CONTROL_POINT_LENGTH 512
const char* u2fServiceRevision = "1.0";

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

/* F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB */
static const ble_uuid128_t gatt_svr_chr_u2fServiceRevisionBitfield_uuid =
    BLE_UUID128_INIT(0xbb, 0x23, 0xd6, 0x7e, 0xba, 0xc9, 0x2f, 0xb4,
                     0xee, 0xec, 0xaa, 0xde, 0xf4, 0xff, 0xd0, 0xf1);

static const uint8_t gatt_svr_sec_test_static_val;

static int
gatt_svr_chr_access_fido(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt,
                             void *arg);

static int
gatt_svr_chr_access_device_info(uint16_t conn_handle, uint16_t attr_handle,
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
            }, {
                /*** Characteristic: U2F Service Revision Bitfield. */
                .uuid = &gatt_svr_chr_u2fServiceRevisionBitfield_uuid.u,
                .access_cb = gatt_svr_chr_access_fido,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_READ_ENC | 
                         BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_ENC,
            }, {
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

static int
gatt_svr_chr_access_fido(uint16_t conn_handle, uint16_t attr_handle,
                             struct ble_gatt_access_ctxt *ctxt,
                             void *arg)
{
    const ble_uuid_t *uuid;
    char buf[BLE_UUID_STR_LEN];
    int rc;

    uuid = ctxt->chr->uuid;

    MODLOG_DFLT(INFO, "Access to char %s (handle %d)\n", ble_uuid_to_str(uuid, buf), attr_handle);

    /* Determine which characteristic is being accessed by examining its
     * 128-bit UUID.
     */

    if (ble_uuid_cmp(uuid, &gatt_svr_chr_u2fControlPoint_uuid.u) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR);

        rc = gatt_svr_chr_write(ctxt->om,
                                sizeof gatt_svr_sec_test_static_val,
                                sizeof gatt_svr_sec_test_static_val,
                                (void*) &gatt_svr_sec_test_static_val, NULL);
        return rc;
    }

    if (ble_uuid_cmp(uuid, &gatt_svr_chr_u2fControlPointLength_uuid.u) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);

        uint16_t cpl = CONTROL_POINT_LENGTH;
        rc = os_mbuf_append(ctxt->om, &cpl, sizeof cpl);
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    if (ble_uuid_cmp(uuid, BLE_UUID16_DECLARE(gatt_svr_chr_u2fServiceRevision_uuid)) == 0) {
        assert(ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR);

        rc = os_mbuf_append(ctxt->om, u2fServiceRevision, strlen(u2fServiceRevision));
        return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }

    if (ble_uuid_cmp(uuid, &gatt_svr_chr_u2fServiceRevisionBitfield_uuid.u) == 0) {
        switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_READ_CHR:
            rc = os_mbuf_append(ctxt->om, &gatt_svr_sec_test_static_val,
                                sizeof gatt_svr_sec_test_static_val);
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;

        case BLE_GATT_ACCESS_OP_WRITE_CHR:
            rc = gatt_svr_chr_write(ctxt->om,
                                    sizeof gatt_svr_sec_test_static_val,
                                    sizeof gatt_svr_sec_test_static_val,
                                    (void*) &gatt_svr_sec_test_static_val, NULL);
            return rc;

        default:
            assert(0);
            return BLE_ATT_ERR_UNLIKELY;
        }
    }

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
