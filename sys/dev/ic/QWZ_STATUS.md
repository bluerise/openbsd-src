# QWZ Driver Status and Development Plan

## Overview

The qwz driver for OpenBSD implements support for Qualcomm ath12k-based
802.11be (Wi-Fi 7) wireless chipsets. It is based on Linux's ath12k driver
and follows the same architectural pattern as OpenBSD's qwx driver (ath11k).

## Current Status

### Implementation Complete (~27,600 lines)

The driver currently contains a substantial implementation:

- **Core Driver**: `sys/dev/ic/qwz.c` (23,572 lines)
- **PCI Attachment**: `sys/dev/pci/if_qwz_pci.c` (4,020 lines)  
- **Headers**: `sys/dev/ic/qwzvar.h`, `sys/dev/ic/qwzreg.h`

### Supported Hardware

- ✅ **WCN7850** (PCI ID 0x1107) - Wi-Fi 7, PCIe, MHI-based
- ⚠️  **QCN9274** (PCI ID 0x1109) - Wi-Fi 7, PCIe, static window mapping
  - PCI device ID added, full support requires additional implementation

### Functional Components

#### Fully Implemented
- PCI device probing and attachment
- Basic device initialization and reset
- **QMI**: Qualcomm MSM Interface for firmware communication
- **MHI**: Modem Host Interface for PCIe (WCN7850)
- **CE**: Copy Engine for DMA transfers
- **HAL**: Hardware Abstraction Layer
- **DP**: Data Path with TX/RX ring management
- **WMI**: Wireless Management Interface
- **HTC**: Host-Target Communication
- **QRTR**: Qualcomm Remote Transport for control messages
- Basic net80211 integration (scan, authentication, association)
- Hardware crypto support (with limitations)

#### Partially Implemented
- Station (STA) mode - functional but with known issues
- Firmware loading via loadfirmware(9)
- Power management - basic support only
- Security - works for WPA2/CCMP, issues with others

#### Not Implemented
- Access Point (AP) mode
- Monitor mode  
- Multi-Link Operation (MLO)
- Advanced Wi-Fi 7 features (320 MHz channels, enhanced puncturing)
- Full QCN9274 support (static window mapping path)
- Advanced power management

### Known Issues

**Hardware Crypto Issues** (firmware 0x1106196e on WCN6855):

1. **Broadcast/Multicast frames** not received on encrypted networks
   unless using HW crypto with CCMP group key
   - Breaks ARP and IPv6 on some configurations
   - Never received with TKIP group cipher

2. **WEP keys** crash firmware when added to hardware
   - Workaround: Use software crypto (but broadcast issues persist)

3. **WPA1 group key** handshake message not received with HW crypto
   - Workaround: Use software crypto (but broadcast issues persist)

**Working Configurations**:
- Unencrypted networks
- WPA2-only networks with CCMP (WPA1 disabled)

**Code Quality Issues**:
- 83 TODO/FIXME/XXX markers throughout codebase
- 5+ functions returning ENOTSUP (not implemented)
- Multiple "derive pdev ID somehow?" comments
- Several hardcoded magic numbers need #defines

## Architecture Differences: WCN7850 vs QCN9274

### WCN7850 (Current)
- **Interface**: PCIe with MHI (Modem Host Interface)
- **Window Mapping**: Dynamic, managed by MHI
- **Communication**: MHI channels for data/control
- **Firmware Loading**: Via MHI channels
- **Power Management**: MHI state machine (M0/M1/M2/M3)
- **Interrupts**: MSI/MSI-X via MHI events

### QCN9274 (To Be Added)
- **Interface**: PCIe with static window mapping
- **Window Mapping**: Static, AHB-like register access
- **Communication**: Direct register-based CE access
- **Firmware Loading**: Direct memory writes, no MHI
- **Power Management**: Simpler, register-based
- **Interrupts**: Direct MSI/MSI-X, no MHI wrapper

**Impact**: QCN9274 requires a parallel implementation path, essentially
a second variant of the driver.

## Required Work for QCN9274 Support

### 1. Register Definitions
- Add QCN9274-specific register offsets (`qcn9274_regs`)
- Define memory windows for static mapping
- Add WCSS register space definitions

### 2. Hardware Abstraction
- Implement `qwz_pci_ops_qcn9274` (static window operations)
- Add `hal_qcn9274_ops` (QCN9274-specific HAL)
- Implement static window read/write functions
- Add window switching logic

### 3. Copy Engine Configuration  
- Define `ath12k_target_ce_config_wlan_qcn9274`
- Configure CE pipes for static window mode
- Set up service-to-CE mappings
- Initialize CE rings without MHI

### 4. Ring Configuration
- Add `ath12k_hw_ring_mask_qcn9274`
- Configure interrupt assignments
- Set up SRNG (Shared Ring) parameters

### 5. Firmware Loading
- Implement non-MHI firmware load path
- Add QCN9274 firmware file definitions
- Handle board data differently
- Implement calibration data loading

### 6. Device Initialization
- Add QCN9274 hardware detection
- Configure static windows at attach
- Initialize CE without MHI
- Set up interrupts directly

### 7. Hardware Parameters
Add to `ath12k_hw_params[]`:
```c
{
    .name = "qcn9274 hw2.0",
    .hw_rev = ATH12K_HW_QCN9274_HW20,
    .fw = {
        .dir = "qcn9274-hw2.0",
        .board_size = 256 * 1024,
        .cal_offset = 256 * 1024,
    },
    .max_radios = 3,  /* QCN9274 can support multiple radios */
    .single_pdev_only = false,
    .internal_sleep_clock = false,
    /* ... QCN9274-specific params ... */
}
```

### 8. Testing Requirements
- QCN9274 hardware required
- Test firmware loading
- Verify register access
- Test STA mode connectivity  
- Verify crypto operations
- Test power management

**Estimated Effort**: 2-3 weeks development + 1 week testing

## Incremental Improvement Plan

### Phase 1: Fix WCN7850 Issues (1-2 weeks)
- [ ] Investigate and fix broadcast/multicast reception issues
- [ ] Add better error handling for crypto failures
- [ ] Resolve remaining ENOTSUP functions
- [ ] Clean up TODO comments with proper implementations
- [ ] Add human-readable constants for magic numbers
- [ ] Test thoroughly on WCN7850 hardware

### Phase 2: Code Cleanup (1 week)
- [ ] Add comprehensive comments for complex algorithms
- [ ] Improve error messages and debugging
- [ ] Standardize code style (KNF compliance)
- [ ] Add function documentation
- [ ] Remove dead code and unused definitions

### Phase 3: QCN9274 Support (2-3 weeks)
- [ ] Implement static window mapping layer
- [ ] Add QCN9274 register definitions
- [ ] Port CE initialization for static windows
- [ ] Implement QCN9274 firmware loading
- [ ] Add QCN9274 hardware parameters
- [ ] Test on real QCN9274 hardware

### Phase 4: Additional Features (1-2 months)
- [ ] Implement AP mode support
- [ ] Add monitor mode
- [ ] Implement advanced power management
- [ ] Add Wi-Fi 7 specific features (MLO, etc.)
- [ ] Performance optimization

## Firmware Requirements

### WCN7850
Firmware files expected in `/etc/firmware/qwz/wcn7850-hw2.0/`:
- `amss.bin` - Main firmware
- `m3.bin` - M3 firmware
- `board-2.bin` - Board data
- Optional: `caldata.bin` - Calibration data

### QCN9274 (Future)
Firmware files expected in `/etc/firmware/qwz/qcn9274-hw2.0/`:
- `amss.bin`
- `m3.bin`  
- `board-2.bin`
- Device-specific calibration data

## References

### Linux ath12k
- Path: `drivers/net/wireless/ath/ath12k/`
- Key files for reference:
  - `core.c`, `core.h` - Core initialization
  - `pci.c`, `pci.h` - PCI attachment
  - `hal.c`, `hal.h` - Hardware abstraction
  - `dp.c`, `dp.h` - Data path
  - `ce.c`, `ce.h` - Copy engine
  - `qmi.c`, `qmi.h` - QMI interface
  - `mhi.c`, `mhi.h` - MHI interface
  - `hw.c`, `hw.h` - Hardware parameters

### OpenBSD qwx Driver
- Similar architecture for ath11k
- Good reference for OpenBSD integration patterns
- Files: `sys/dev/ic/qwx.c`, `sys/dev/pci/if_qwx_pci.c`

## Development Status

**Current State**: Commented out in kernel configs  
**Reason**: Incomplete/testing, crypto issues  
**Target**: Enable in GENERIC when WCN7850 issues resolved

## Recommendations

1. **Focus on WCN7850 first**: Resolve known issues before adding QCN9274
2. **Incremental approach**: Fix one subsystem at a time
3. **Hardware access critical**: Need real hardware for meaningful testing
4. **Upstream coordination**: Monitor Linux ath12k for fixes/improvements
5. **Documentation**: Add inline comments for complex firmware interactions

## Conclusion

The qwz driver is a substantial implementation (~27K lines) that provides
a foundation for ath12k support on OpenBSD. WCN7850 support is largely
complete but needs refinement to resolve crypto/broadcast issues.

QCN9274 support requires significant additional work (~3-5K lines) due
to architectural differences (static windows vs MHI), but the PCI device
ID has been added to enable future implementation.

**Realistic Timeline**:
- WCN7850 production-ready: 1-2 months
- QCN9274 support: +2-3 months (with hardware)
- Full Wi-Fi 7 features: +3-6 months

This is a long-term driver development effort that requires dedicated
resources and hardware access for proper testing and validation.
