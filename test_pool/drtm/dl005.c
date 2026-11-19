/** @file
 * Copyright (c) 2024-2026, Arm Limited or its affiliates. All rights reserved.
 * SPDX-License-Identifier : Apache-2.0

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#include "acs_val.h"
#include "acs_memory.h"
#include "val_interface.h"

#define TEST_NUM   (ACS_DRTM_DL_TEST_NUM_BASE  +  5)
#define TEST_RULE  "R45260, R45270, R313010, R314050, R314060, R314090, R314100, " \
                   "R314110, R314120, R314130, R314140, R314150, R315040, R45160"
#define TEST_DESC  "Check DLME Data Rules                 "

static uint64_t acpi_region_address;
static DRTM_MEMORY_REGION_DESCRIPTOR_TABLE *prot_region;
static DRTM_MEMORY_REGION_DESCRIPTOR_TABLE *addr_map;
static DRTM_TCB_HASH_TABLE *tcb_hash_table;
static DRTM_TCB_HASH_TABLE_HDR tcb_header;
static DRTM_DLME_DATA_HDR *dlme_data_header;

static uint32_t validate_region_coverage(DRTM_MEMORY_REGION_DESCRIPTOR_TABLE *table,
                                         uint32_t count, uint64_t address, uint64_t size,
                                         uint32_t type)
{
  DRTM_MEMORY_REGION *region;
  uint64_t region_size, covered;
  uint32_t region_type;

  /* R314100/R314110: the required memory range must be described by the table. */
  for (uint32_t i = 0; i < count; i++) {
    region = &table->regions[i];
    /* A gap leaves address uncovered, later sorted descriptors cannot fill it. */
    if (region->start_addr > address) {
      val_print(ERROR, "\n       DLME Coverage Gap Before Descriptor %u at 0x%llx",
                i, (unsigned long long)address);
      return ACS_STATUS_FAIL;
    }

    region_size = (region->size_type & DRTM_MEM_PROT_MAX_4KB_PAGES) * DRTM_SIZE_4K;
    /* Skip descriptors lying entirely before the next byte needing coverage. */
    if (address - region->start_addr >= region_size)
      continue;

    region_type = (region->size_type >> DRTM_MEM_PROT_SHIFT_REGION_TYPE) &
                    DRTM_MEM_PROT_REGION_TYPE_MASK;
    /* Later non-overlapping descriptors cannot replace this range with the required type. */
    if (region_type != type) {
      val_print(ERROR, "\n       DLME Coverage Descriptor %u Type Invalid: %u (Expected %u)",
                i, region_type, type);
      return ACS_STATUS_FAIL;
    }

    covered = region_size - (address - region->start_addr);
    if (covered >= size)
      return ACS_STATUS_PASS;

    /* Continue checking the uncovered tail of the DLME range. */
    address += covered;
    size -= covered;
  }
  val_print(ERROR, "\n       DLME Coverage Incomplete at 0x%llx: %llu Bytes Remaining",
            (unsigned long long)address, (unsigned long long)size);
  return ACS_STATUS_FAIL;
}

/* R314050/R314090: subregions must fit within the DLME region and DLME data. */
static uint32_t validate_dlme_layout(DRTM_PARAMETERS *params)
{
  uint64_t data_address, remaining, offset;
  uint64_t sizes[6];

  data_address = params->dlme_region_address + params->dlme_data_offset;
  dlme_data_header = (DRTM_DLME_DATA_HDR *)data_address;
  /* R314050: all DLME data subregions must be within the DLME region. */
  if (dlme_data_header->size < sizeof(DRTM_DLME_DATA_HDR) ||
      dlme_data_header->size > dlme_data_header->dlme_data_size ||
      dlme_data_header->dlme_data_size > params->dlme_region_size - params->dlme_data_offset) {
    val_print(ERROR, "\n       DLME Data Header Size Invalid");
    return ACS_STATUS_FAIL;
  }

  sizes[0] = dlme_data_header->protected_regions_size;
  sizes[1] = dlme_data_header->address_map_size;
  sizes[2] = dlme_data_header->drtm_event_log_size;
  sizes[3] = dlme_data_header->tcb_hash_table_size;
  sizes[4] = dlme_data_header->acpi_table_region_size;
  sizes[5] = dlme_data_header->implementation_region_size;
  remaining = dlme_data_header->dlme_data_size - dlme_data_header->size;
  /* R314090: every subregion size must fit within the declared DLME data. */
  for (uint32_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
    if (sizes[i] > remaining) {
      val_print(ERROR, "\n       DLME Subregion %u Size Exceeds Remaining Data: %llu > %llu",
                i, (unsigned long long)sizes[i], (unsigned long long)remaining);
      return ACS_STATUS_FAIL;
    }
    remaining -= sizes[i];
  }
  /* DLME data subregions are consecutive, with no padding. */
  if (remaining != 0) {
    val_print(ERROR, "\n       DLME Data Contains %llu Unaccounted Bytes",
              (unsigned long long)remaining);
    return ACS_STATUS_FAIL;
  }

  offset = dlme_data_header->size;
  prot_region = (DRTM_MEMORY_REGION_DESCRIPTOR_TABLE *)(data_address + offset);
  offset += sizes[0];
  addr_map = (DRTM_MEMORY_REGION_DESCRIPTOR_TABLE *)(data_address + offset);
  offset += sizes[1] + sizes[2];
  tcb_hash_table = (DRTM_TCB_HASH_TABLE *)(data_address + offset);
  acpi_region_address = data_address + offset + sizes[3];
  return ACS_STATUS_PASS;
}

/* R314140: ACPI description-table checksums must sum to zero. */
static uint32_t validate_acpi_checksum(uint64_t address, uint32_t length)
{
  uint8_t checksum = 0;
  uint8_t *table = (uint8_t *)address;

  for (uint32_t i = 0; i < length; i++)
    checksum = (uint8_t)(checksum + table[i]);
  if (checksum != 0) {
    val_print(ERROR, "\n       ACPI Table Checksum Invalid at 0x%llx",
              (unsigned long long)address);
    return ACS_STATUS_FAIL;
  }
  return ACS_STATUS_PASS;
}

/* R314140: the ACPI region must start with an XSDT containing ACPI table addresses. */
static uint32_t validate_acpi_region(uint64_t address, uint64_t size)
{
  uint32_t signature, length, table_length;
  uint64_t table_address, offset;

  if (size < ACPI_HEADER_SIZE) {
    val_print(ERROR, "\n       ACPI Region Too Small for XSDT Header: %llu Bytes",
              (unsigned long long)size);
    return ACS_STATUS_FAIL;
  }
  val_memcpy(&signature, (void *)address, sizeof(signature));
  val_memcpy(&length, (void *)(address + ACPI_HEADER_LEN_OFFSET), sizeof(length));
  if (signature != ACS_ACPI_SIGNATURE('X', 'S', 'D', 'T') ||
      length < ACPI_HEADER_SIZE || length > size ||
      (length - ACPI_HEADER_SIZE) % sizeof(uint64_t) != 0) {
    val_print(ERROR, "\n       XSDT Signature or Length Invalid: Signature=0x%08x, Length=%u",
              signature, length);
    return ACS_STATUS_FAIL;
  }

  if (((uint8_t *)address)[8] != 1 ||
      validate_acpi_checksum(address, length) != ACS_STATUS_PASS) {
    val_print(ERROR, "\n       XSDT Revision or Checksum Invalid");
    return ACS_STATUS_FAIL;
  }

  for (uint32_t i = 0; i < (length - ACPI_HEADER_SIZE) / sizeof(uint64_t); i++) {
    val_memcpy(&table_address, (void *)(address + ACPI_HEADER_SIZE + i * sizeof(uint64_t)),
               sizeof(table_address));
    if (table_address < address) {
      val_print(ERROR, "\n       XSDT Entry %u Address Below ACPI Region: 0x%llx",
                i, (unsigned long long)table_address);
      return ACS_STATUS_FAIL;
    }
    offset = table_address - address;
    if (offset < length || offset > size || ACPI_HEADER_SIZE > size - offset) {
      val_print(ERROR, "\n       XSDT Entry %u Address or Table Header Bounds Invalid", i);
      return ACS_STATUS_FAIL;
    }
    val_memcpy(&table_length, (void *)(table_address + ACPI_HEADER_LEN_OFFSET),
               sizeof(table_length));
    if (table_length < ACPI_HEADER_SIZE || table_length > size - offset) {
      val_print(ERROR, "\n       ACPI Table Length Invalid at XSDT Entry %u: %u", i, table_length);
      return ACS_STATUS_FAIL;
    }
    if (validate_acpi_checksum(table_address, table_length) != ACS_STATUS_PASS) {
      val_print(ERROR, "\n       ACPI Table Checksum Failed at XSDT Entry %u", i);
      return ACS_STATUS_FAIL;
    }
  }
  return ACS_STATUS_PASS;
}

static void print_dlme_data_header(DRTM_DLME_DATA_HDR *dlme_data_header)
{
  val_print(DEBUG, "\n       DLME Data Header");
  val_print(DEBUG, "\n       Revision                  = 0x%08lx",
                                                dlme_data_header->revision);
  val_print(DEBUG, "\n       Size                      = %d Bytes",
                                                dlme_data_header->size);
  val_print(DEBUG, "\n       DLME_data_size            = %d Bytes",
                                                dlme_data_header->dlme_data_size);
  val_print(DEBUG, "\n       Protected Regions Size    = %d Bytes",
                                                dlme_data_header->protected_regions_size);
  val_print(DEBUG, "\n       Address Map Size          = %d Bytes",
                                                dlme_data_header->address_map_size);
  val_print(DEBUG, "\n       DRTM Event Log Size       = %d Bytes",
                                                dlme_data_header->drtm_event_log_size);
  val_print(DEBUG, "\n       TCB Hash Table Size       = %d Bytes",
                                                dlme_data_header->tcb_hash_table_size);
  val_print(DEBUG, "\n       ACPI Table Region Size    = %d Bytes",
                                                dlme_data_header->acpi_table_region_size);
  val_print(DEBUG, "\n       Implementation Region Size= %d Bytes",
                                                dlme_data_header->implementation_region_size);
}

static void print_protected_region_info(void)
{
  val_print(DEBUG, "\n       Protected Region");
  val_print(DEBUG, "\n       Revision          : 0x%08lx",
                                            prot_region->header.revision);
  val_print(DEBUG, "\n       Number of Regions : 0x%08lx",
                                            prot_region->header.num_regions);
  for (uint32_t i = 0; i < prot_region->header.num_regions; i++) {
    val_print(DEBUG, "\n       Region           : 0x%lx", i);
    val_print(DEBUG, "\n       Start Address    : 0x%08lx",
                                            prot_region->regions[i].start_addr);
    val_print(DEBUG, "\n       Region Size/Type : 0x%08lx",
                                            prot_region->regions[i].size_type);
  }
}

static void print_address_map_info(void)
{
  val_print(DEBUG, "\n       Address Map");
  val_print(DEBUG, "\n       Revision          : 0x%08lx",
                                            addr_map->header.revision);
  val_print(DEBUG, "\n       Number of Regions : 0x%08lx",
                                            addr_map->header.num_regions);
  for (uint32_t i = 0; i < addr_map->header.num_regions; i++) {
    val_print(DEBUG, "\n       Region           : 0x%lx", i);
    val_print(DEBUG, "\n       Start Address    : 0x%08lx",
                                            addr_map->regions[i].start_addr);
    val_print(DEBUG, "\n       Region Size/Type : 0x%08lx",
                                            addr_map->regions[i].size_type);
  }
}

static void print_dlme_data_info(void)
{
  uint32_t xsdt_len, num_acpi_entries, signature, digest_size;
  uint64_t next_table_addr;
  uint8_t *entry_address;
  uint32_t hash_id;

  print_dlme_data_header(dlme_data_header);

  print_protected_region_info();

  print_address_map_info();

  if (dlme_data_header->tcb_hash_table_size != 0) {
    val_print(DEBUG, "\n       TCB Hash Table");
    val_print(DEBUG, "\n       Revision          : 0x%08lx",
                                            tcb_header.revision);
    val_print(DEBUG, "\n       Number of Hashes  : 0x%08lx",
                                            tcb_header.num_hashes);
    val_print(DEBUG, "\n       Hash Algorithm    : 0x%08lx",
                                            tcb_header.hash_algo);
    digest_size = val_drtm_get_digest_size(tcb_header.hash_algo);
    entry_address = (uint8_t *)tcb_hash_table + sizeof(DRTM_TCB_HASH_TABLE_HDR);
    for (uint32_t i = 0; i < tcb_header.num_hashes; i++) {
      val_memcpy(&hash_id, entry_address, sizeof(hash_id));
      val_print(DEBUG, "\n       HASH Index : 0x%lx", i);
      val_print(DEBUG, "\n       HASH ID    : 0x%08lx", hash_id);
      for (uint32_t j = 0; j < digest_size; j = j+4) {
        val_print(DEBUG, "\n       HASH Val   : ");
        val_print(DEBUG, "%02x ", entry_address[sizeof(hash_id) + j]);
        val_print(DEBUG, "%02x ", entry_address[sizeof(hash_id) + j+1]);
        val_print(DEBUG, "%02x ", entry_address[sizeof(hash_id) + j+2]);
        val_print(DEBUG, "%02x ", entry_address[sizeof(hash_id) + j+3]);
      }
      entry_address += sizeof(hash_id) + digest_size;
    }
  }

  if (dlme_data_header->acpi_table_region_size != 0) {
    /* Print the XSDT Address and Present Tables */
    val_print(DEBUG, "\n       ACPI Tables");
    val_memcpy(&signature, (void *)acpi_region_address, sizeof(signature));
    val_print(DEBUG, "\n       Signature : %08x", signature);
    /* Print all Present ACPI Tables */
    PRINT_ACPI_NAME_FROM_SIGNATURE(signature);
    val_memcpy(&xsdt_len, (void *)(acpi_region_address + ACPI_HEADER_LEN_OFFSET),
               sizeof(xsdt_len));
    num_acpi_entries = (xsdt_len - ACPI_HEADER_SIZE) >> 3;
    for (uint32_t i = 0; i < num_acpi_entries; i++) {
      val_memcpy(&next_table_addr,
                 (void *)(acpi_region_address + ACPI_HEADER_SIZE + i * sizeof(uint64_t)),
                 sizeof(next_table_addr));
      val_memcpy(&signature, (void *)next_table_addr, sizeof(signature));
      PRINT_ACPI_NAME_FROM_SIGNATURE(signature);
    }
  }
  val_print(DEBUG, "\n\n");

}

static
void
payload(uint32_t num_pe)
{

  /* This test will verify the DRTM Dynamic Launch
   * Input parameter will be 64 bit address of DRTM Parameters
   * */
  uint32_t index = val_pe_get_index_mpid(val_pe_get_mpid());
  int64_t  status;

  DRTM_PARAMETERS *drtm_params;
  uint64_t drtm_params_size = DRTM_SIZE_4K;
  uint64_t region_size;
  DRTM_MEMORY_REGION *region, *prev_region;
  uint64_t prev_region_size;
  uint32_t region_type, prev_region_type;
  uint32_t test_fails = 0;
  uint32_t digest_size;
  uint32_t recorded_hashes, hash_id;
  uint8_t *hash_address;

  /* Allocate Memory For DRTM Parameters 4KB Aligned */
  drtm_params = (DRTM_PARAMETERS *)((uint64_t)val_aligned_alloc(DRTM_SIZE_4K, drtm_params_size));
  if (!drtm_params) {
    val_print(ERROR, "\n    Failed to allocate memory for DRTM Params");
    val_set_status(index, RESULT_FAIL(1));
    return;
  }

  status = val_drtm_init_drtm_params(drtm_params);
  if (status != ACS_STATUS_PASS) {
    val_print(ERROR, "\n       DRTM Init Params failed err=%d", status);
    val_set_status(index, RESULT_FAIL(2));
    goto free_drtm_params;
  }

  /* Invoke DRTM Dynamic Launch, This will return only in case of error */
  status = val_drtm_dynamic_launch(drtm_params);
  /* This will return only in fail*/
  if (status != DRTM_ACS_SUCCESS) {
    val_print(ERROR, "\n       DRTM Dynamic Launch failed");
    val_set_status(index, RESULT_FAIL(3));
    goto free_dlme_region;
  }

  status = val_drtm_unprotect_memory();
  if (status != DRTM_ACS_SUCCESS) {
    val_print(ERROR, "\n       DRTM Unprotect Memory failed err=%d", status);
    val_set_status(index, RESULT_FAIL(4));
    goto free_dlme_region;
  }

  /* Check DL return values after DLME Image launch */
  status = val_drtm_check_dl_result(drtm_params->dlme_region_address,
                                    drtm_params->dlme_data_offset);
  if (status != ACS_STATUS_PASS) {
    val_print(ERROR, "\n       DRTM check DL result failed");
    val_set_status(index, RESULT_FAIL(5));
    goto free_dlme_region;
  }

  /* R314050/R314090: subregions must be within the DLME region and declared DLME data. */
  if (validate_dlme_layout(drtm_params) != ACS_STATUS_PASS) {
    val_print(ERROR, "\n       Invalid DLME Data Header or Subregion Bounds");
    val_set_status(index, RESULT_FAIL(6));
    goto free_dlme_region;
  }

  /* R314060 : Check if Event Log size is not zero */
  if (dlme_data_header->drtm_event_log_size <= 0) {
    val_print(ERROR, "\n       DLME Data Event Log Size is incorrect");
    val_set_status(index, RESULT_FAIL(7));
    goto free_dlme_region;
  }

  /* R314060/R45270: the DCE must populate the protected-regions table.
   * R314110: protected regions must use the MEMORY_REGION_DESCRIPTOR_TABLE format.
   */
  if (dlme_data_header->protected_regions_size < sizeof(DRTM_MEMORY_REGION_HDR) ||
      prot_region->header.revision != 1 || prot_region->header.reserved != 0 ||
      prot_region->header.num_regions == 0 ||
      prot_region->header.num_regions >
          (dlme_data_header->protected_regions_size - sizeof(DRTM_MEMORY_REGION_HDR)) /
          sizeof(DRTM_MEMORY_REGION)) {
    val_print(ERROR, "\n       Protected regions table missing or invalid");
    val_set_status(index, RESULT_FAIL(8));
    goto free_dlme_region;
  }

  /* R45160: complete DMA protection requires one region at address 0 with maximum size. */
  if (((drtm_params->launch_features & DRTM_LAUNCH_FEATURES_MASK_MEM_PROTECTION) >>
       DRTM_LAUNCH_FEATURES_SHIFT_MEM_PROTECTION) == DRTM_LAUNCH_FEAT_MEM_PROT_ALL_SUPP) {
    if ((prot_region->header.num_regions != 1) ||
        (prot_region->regions[0].start_addr != 0) ||
        (prot_region->regions[0].size_type & DRTM_MEM_PROT_MAX_4KB_PAGES) !=
            DRTM_MEM_PROT_MAX_4KB_PAGES) {
      val_print(ERROR, "\n       Protected region wrongly populated");
      val_set_status(index, RESULT_FAIL(9));
      goto free_dlme_region;
    }
  }

  /* R314060/R45260: the DCE must populate the address-map table.
   * R314100: the address map must use the MEMORY_REGION_DESCRIPTOR_TABLE format.
   */
  if (dlme_data_header->address_map_size < sizeof(DRTM_MEMORY_REGION_HDR) ||
      addr_map->header.revision != 1 || addr_map->header.reserved != 0 ||
      addr_map->header.num_regions == 0 ||
      addr_map->header.num_regions >
          (dlme_data_header->address_map_size - sizeof(DRTM_MEMORY_REGION_HDR)) /
          sizeof(DRTM_MEMORY_REGION)) {
    val_print(ERROR, "\n       Address map table missing or invalid");
    val_set_status(index, RESULT_FAIL(10));
    goto free_dlme_region;
  }

  for (uint32_t i = 0; i < prot_region->header.num_regions; i++) {
    region = &prot_region->regions[i];
    /* R314110: protected regions must use type 0. */
    region_type = (region->size_type >> DRTM_MEM_PROT_SHIFT_REGION_TYPE) &
                    DRTM_MEM_PROT_REGION_TYPE_MASK;
    if (region_type != DRTM_REGION_TYPE_NORMAL) {
      val_print(ERROR, "\n       Protected Memory Region Type Invalid: %u", region_type);
      val_set_status(index, RESULT_FAIL(11));
      test_fails++;
    }

    /* R314110: Table 11 reserves bits [63:57] and encodes sizes in 4KB pages. */
    region_size = (region->size_type & DRTM_MEM_PROT_MAX_4KB_PAGES) *
                    DRTM_SIZE_4K;
    if (region_size == 0 ||
        region_size - 1 > DRTM_UINT64_MAX - region->start_addr ||
        (region->size_type >> 57) != 0) {
      val_print(ERROR, "\n       Protected Memory Region Size or Reserved Bits Invalid");
      val_set_status(index, RESULT_FAIL(12));
      test_fails++;
    }

    /* R313010: protected region addresses must be 4KB aligned. */
    if (!(DRTM_IS_4KB_ALIGNED(region->start_addr))) {
      val_print(ERROR, "\n       Protected Memory Regions Not 4KB Aligned");
      val_set_status(index, RESULT_FAIL(13));
      test_fails++;
    }

    if (i == 0)
      continue;

    prev_region = &prot_region->regions[i - 1];
    /* R314120: protected descriptors must be sorted by ascending address. */
    if (region->start_addr < prev_region->start_addr) {
      val_print(ERROR, "\n       Protected Regions Memory Regions Not Sorted");
      val_set_status(index, RESULT_FAIL(14));
      test_fails++;
    }

    prev_region_size = (prev_region->size_type &
                         DRTM_MEM_PROT_MAX_4KB_PAGES) * DRTM_SIZE_4K;
    /* R314110: the descriptor-table format also requires non-overlapping regions. */
    if (region->start_addr >= prev_region->start_addr &&
        region->start_addr - prev_region->start_addr <
            prev_region_size) {
      val_print(ERROR, "\n       Protected Memory Regions Overlap");
      val_set_status(index, RESULT_FAIL(15));
      test_fails++;
    }
    /* R314120: adjacent protected regions must be coalesced. */
    if (region->start_addr >= prev_region->start_addr &&
        region->start_addr - prev_region->start_addr ==
            prev_region_size) {
      val_print(ERROR, "\n       Protected Memory Regions Not Coalesced");
      val_set_status(index, RESULT_FAIL(16));
      test_fails++;
    }
  }

  for (uint32_t i = 0; i < addr_map->header.num_regions; i++) {
    region = &addr_map->regions[i];
    /* R314100: normal memory must use type 1, types 5-7 are reserved. */
    region_type = (region->size_type >> DRTM_MEM_PROT_SHIFT_REGION_TYPE) &
                    DRTM_MEM_PROT_REGION_TYPE_MASK;
    if (region_type < DRTM_REGION_TYPE_NORMAL_CACHEABLE ||
        region_type > DRTM_REGION_TYPE_RESERVED) {
      val_print(ERROR, "\n       Address Map Memory Region Type Invalid: %u", region_type);
      val_set_status(index, RESULT_FAIL(17));
      test_fails++;
    }

    /* R314100: Table 11 encodes sizes in 4KB pages and reserves bits [63:57]. */
    region_size = (region->size_type & DRTM_MEM_PROT_MAX_4KB_PAGES) *
                    DRTM_SIZE_4K;
    if (region_size == 0 ||
        region_size - 1 > DRTM_UINT64_MAX - region->start_addr ||
        (region->size_type >> 57) != 0) {
      val_print(ERROR, "\n       Address Map Memory Region Size or Reserved Bits Invalid");
      val_set_status(index, RESULT_FAIL(18));
      test_fails++;
    }

    /* R313010: address-map region addresses must be 4KB aligned. */
    if (!(DRTM_IS_4KB_ALIGNED(region->start_addr))) {
      val_print(ERROR, "\n       Address Map Memory Regions Not 4KB Aligned");
      val_set_status(index, RESULT_FAIL(19));
      test_fails++;
    }

    if (i == 0)
      continue;

    prev_region = &addr_map->regions[i - 1];
    /* R314120: address-map descriptors must be sorted by ascending address. */
    if (region->start_addr < prev_region->start_addr) {
      val_print(ERROR, "\n       Address Map Memory Regions Not Sorted");
      val_set_status(index, RESULT_FAIL(20));
      test_fails++;
    }

    prev_region_type = (prev_region->size_type >> DRTM_MEM_PROT_SHIFT_REGION_TYPE) &
                         DRTM_MEM_PROT_REGION_TYPE_MASK;
    prev_region_size = (prev_region->size_type &
                         DRTM_MEM_PROT_MAX_4KB_PAGES) * DRTM_SIZE_4K;
    /* R314100: the descriptor-table format also requires non-overlapping regions. */
    if (region->start_addr >= prev_region->start_addr &&
        region->start_addr - prev_region->start_addr <
            prev_region_size) {
      val_print(ERROR, "\n       Address Map Memory Regions Overlap");
      val_set_status(index, RESULT_FAIL(21));
      test_fails++;
    }
    /* R314120: adjacent regions with matching type and applicable cacheability
     * attributes must be coalesced.
     */
    if (region->start_addr >= prev_region->start_addr &&
        region->start_addr - prev_region->start_addr ==
            prev_region_size &&
        region_type == prev_region_type &&
        (region_type != DRTM_REGION_TYPE_NORMAL_CACHEABLE ||
         ((region->size_type >> DRTM_MEM_PROT_SHIFT_CACHEABILITY_ATTR) &
          DRTM_MEM_PROT_CACHEABILITY_MASK) ==
         ((prev_region->size_type >> DRTM_MEM_PROT_SHIFT_CACHEABILITY_ATTR) &
          DRTM_MEM_PROT_CACHEABILITY_MASK))) {
      val_print(ERROR, "\n       Address Map Memory Regions Not Coalesced");
      val_set_status(index, RESULT_FAIL(22));
      test_fails++;
    }
  }

  if (test_fails == 0) {
    /* R314100: normal memory in the address map must use region type 1. */
    if (validate_region_coverage(addr_map, addr_map->header.num_regions,
                                 drtm_params->dlme_region_address,
                                 drtm_params->dlme_region_size,
                                 DRTM_REGION_TYPE_NORMAL_CACHEABLE) != ACS_STATUS_PASS) {
      val_print(ERROR, "\n       Address Map Does Not Cover DLME Region");
      val_set_status(index, RESULT_FAIL(23));
      test_fails++;
    }
    /* R314110: in region mode, the protected ranges must include the DLME region.
     * R45160: complete DMA protection is represented by a maximum-size region at 0x0.
     */
    if (((drtm_params->launch_features & DRTM_LAUNCH_FEATURES_MASK_MEM_PROTECTION) >>
         DRTM_LAUNCH_FEATURES_SHIFT_MEM_PROTECTION) ==
            DRTM_LAUNCH_FEAT_MEM_PROT_REGION_SUPP &&
        validate_region_coverage(prot_region, prot_region->header.num_regions,
                                 drtm_params->dlme_region_address,
                                 drtm_params->dlme_region_size,
                                 DRTM_REGION_TYPE_NORMAL) != ACS_STATUS_PASS) {
      val_print(ERROR, "\n       Protected Regions Do Not Cover DLME Region");
      val_set_status(index, RESULT_FAIL(24));
      test_fails++;
    }
  }

  /* R314150: the TCB hash table and ACPI region must not both be present. */
  if ((dlme_data_header->tcb_hash_table_size != 0) &&
      (dlme_data_header->acpi_table_region_size != 0)) {
    val_print(ERROR, "\n       TCB Hash Table & ACPI Table Region Check Failed");
    val_set_status(index, RESULT_FAIL(25));
    test_fails++;
  }

  /* R314130 Part 5 : TCB hash table, if present, must be formatted as a TCB_HASH_TABLE */
  if (dlme_data_header->tcb_hash_table_size != 0) {
    /* R314130: the header and digest-sized entries must fit within the TCB_HASH_TABLE. */
    if (dlme_data_header->tcb_hash_table_size < sizeof(DRTM_TCB_HASH_TABLE_HDR)) {
      val_print(ERROR, "\n       TCB Hash Table Header Truncated");
      val_set_status(index, RESULT_FAIL(26));
      goto free_dlme_region;
    }
    val_memcpy(&tcb_header, tcb_hash_table, sizeof(tcb_header));
    digest_size = val_drtm_get_digest_size(tcb_header.hash_algo);
    if (tcb_header.revision != 1 || tcb_header.reserved != 0 ||
        tcb_header.num_hashes == 0 || tcb_header.hash_algo == 0 ||
        (digest_size != 0 && tcb_header.num_hashes >
            (dlme_data_header->tcb_hash_table_size - sizeof(DRTM_TCB_HASH_TABLE_HDR)) /
            (sizeof(uint32_t) + digest_size))) {
      val_print(ERROR, "\n       TCB_HASH_TABLE Not Correctly Formatted");
      val_set_status(index, RESULT_FAIL(27));
      goto free_dlme_region;
    }
    if (digest_size == 0) {
      val_print(WARN, "\n       Unsupported TCB digest algorithm 0x%x",
                tcb_header.hash_algo);
      if (test_fails == 0)
        val_set_status(index, RESULT_SKIP(1));
      goto free_dlme_region;
    }
    /* R315040: SET_TCB_HASH entries must not exceed the advertised DRTM_FEATURES limit.
     * Table 6 excludes implementation supplied entries from this limit.
     */
    recorded_hashes = 0;
    hash_address = (uint8_t *)tcb_hash_table + sizeof(DRTM_TCB_HASH_TABLE_HDR);
    for (uint32_t i = 0; i < tcb_header.num_hashes; i++) {
      val_memcpy(&hash_id, hash_address, sizeof(hash_id));
      if (hash_id & (1U << 31)) /* Source of Entry: DRTM_SET_TCB_HASH. */
        recorded_hashes++;
      hash_address += sizeof(hash_id) + digest_size;
    }
    /* Feature-ID queries succeed only when their return status is positive. */
    if (recorded_hashes != 0 &&
        (g_drtm_features.tcb_hash_features.status <= DRTM_ACS_SUCCESS ||
         recorded_hashes > VAL_EXTRACT_BITS(g_drtm_features.tcb_hash_features.value, 0, 7))) {
      val_print(ERROR, "\n       TCB Hash Feature Status or Recorded Hash Count Invalid");
      val_set_status(index, RESULT_FAIL(28));
      test_fails++;
    }
  }

  /* R314140 Part 6 : ACPI tables region, if present, must start with an XSDT table at */
  /*                  offset 0 which contains the physical addresses of all the other  */
  /*                  ACPI tables in the region                                        */
  if (dlme_data_header->acpi_table_region_size != 0) {
    if (validate_acpi_region(acpi_region_address,
                             dlme_data_header->acpi_table_region_size) != ACS_STATUS_PASS) {
      val_print(ERROR, "\n       ACPI XSDT Table Check Failed");
      val_set_status(index, RESULT_FAIL(29));
      test_fails++;
    }
  }

  if (test_fails == 0) {
    print_dlme_data_info();
    val_set_status(index, RESULT_PASS);
  }

free_dlme_region:
  if (drtm_params->mem_prot_table_address != 0)
    val_memory_free_aligned((void *)drtm_params->mem_prot_table_address);
  val_memory_free_aligned((void *)drtm_params->dlme_region_address);
free_drtm_params:
  val_memory_free_aligned((void *)drtm_params);

  return;
}

uint32_t dl005_entry(uint32_t num_pe)
{

  uint32_t status = ACS_STATUS_FAIL;

  status = val_initialize_test(TEST_NUM, TEST_DESC, num_pe);

  if (status != ACS_STATUS_SKIP)
  /* execute payload, which will execute relevant functions on current and other PEs */
      payload(num_pe);

  /* get the result from all PE and check for failure */
  status = val_check_for_error(TEST_NUM, num_pe, TEST_RULE);

  val_report_status(0, ACS_END(TEST_NUM), NULL);

  return status;
}
