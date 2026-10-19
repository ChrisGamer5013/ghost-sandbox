/*
   Ghost Sandbox — Hardware Profile
   TOML-based hardware identity configuration.
*/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── Top-Level Profile ──────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareProfile {
    #[serde(default)]
    pub identity: IdentityProfile,
    #[serde(default)]
    pub cpu: CpuProfile,
    #[serde(default)]
    pub gpu: GpuProfile,
    #[serde(default)]
    pub motherboard: MotherboardProfile,
    #[serde(default)]
    pub storage: StorageProfile,
    #[serde(default)]
    pub network: NetworkProfile,
    #[serde(default)]
    pub memory: MemoryProfile,
    #[serde(default)]
    pub pcie: PcieProfile,
    #[serde(default)]
    pub monitor: MonitorProfile,
    #[serde(default)]
    pub tpm: TpmProfile,
}

impl Default for HardwareProfile {
    fn default() -> Self {
        Self {
            identity: IdentityProfile::default(),
            cpu: CpuProfile::default(),
            gpu: GpuProfile::default(),
            motherboard: MotherboardProfile::default(),
            storage: StorageProfile::default(),
            network: NetworkProfile::default(),
            memory: MemoryProfile::default(),
            pcie: PcieProfile::default(),
            monitor: MonitorProfile::default(),
            tpm: TpmProfile::default(),
        }
    }
}

impl HardwareProfile {
    pub fn load_from_file(path: &str) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read profile: {}", e))?;
        toml::from_str(&contents)
            .map_err(|e| format!("Failed to parse profile: {}", e))
    }
    
    pub fn save_to_file(&self, path: &str) -> Result<(), String> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize profile: {}", e))?;
        std::fs::write(path, contents)
            .map_err(|e| format!("Failed to write profile: {}", e))
    }
}

// ─── System Identity ────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityProfile {
    pub computer_name: String,
    pub user_name: String,
    pub machine_guid: String,
    pub volume_serial: String,
    pub windows_product_id: String,
}

impl Default for IdentityProfile {
    fn default() -> Self {
        Self {
            computer_name: "WORKSTATION-7X".into(),
            user_name: "Developer".into(),
            machine_guid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".into(),
            volume_serial: "1234-ABCD".into(),
            windows_product_id: "00330-80000-00000-AA123".into(),
        }
    }
}

// ─── CPU ────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuProfile {
    pub manufacturer: String,
    pub brand_string: String,
    pub family: u32,
    pub model: u32,
    pub stepping: u32,
    pub cores_physical: u32,
    pub cores_logical: u32,
    pub base_clock_mhz: u32,
    pub max_clock_mhz: u32,
    pub l1_cache_kb: u32,
    pub l2_cache_kb: u32,
    pub l3_cache_kb: u32,
    pub socket: String,
    pub architecture: String,
    #[serde(default)]
    pub features: CpuFeatures,
    #[serde(default)]
    pub cpuid: HashMap<String, CpuidLeaf>,
}

impl Default for CpuProfile {
    fn default() -> Self {
        Self {
            manufacturer: "GenuineIntel".into(),
            brand_string: "Intel(R) Core(TM) i9-14900K".into(),
            family: 6,
            model: 183,
            stepping: 1,
            cores_physical: 24,
            cores_logical: 32,
            base_clock_mhz: 3200,
            max_clock_mhz: 6000,
            l1_cache_kb: 2048,
            l2_cache_kb: 32768,
            l3_cache_kb: 36864,
            socket: "LGA1700".into(),
            architecture: "x86_64".into(),
            features: CpuFeatures::default(),
            cpuid: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuidLeaf {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuFeatures {
    #[serde(rename = "SSE", default = "default_true")]
    pub sse: bool,
    #[serde(rename = "SSE2", default = "default_true")]
    pub sse2: bool,
    #[serde(rename = "SSE3", default = "default_true")]
    pub sse3: bool,
    #[serde(rename = "SSSE3", default = "default_true")]
    pub ssse3: bool,
    #[serde(rename = "SSE4_1", default = "default_true")]
    pub sse4_1: bool,
    #[serde(rename = "SSE4_2", default = "default_true")]
    pub sse4_2: bool,
    #[serde(rename = "AVX", default = "default_true")]
    pub avx: bool,
    #[serde(rename = "AVX2", default = "default_true")]
    pub avx2: bool,
    #[serde(rename = "AVX512F", default)]
    pub avx512f: bool,
    #[serde(rename = "AVX512BW", default)]
    pub avx512bw: bool,
    #[serde(rename = "AVX512VL", default)]
    pub avx512vl: bool,
    #[serde(rename = "FMA", default = "default_true")]
    pub fma: bool,
    #[serde(rename = "AES_NI", default = "default_true")]
    pub aes_ni: bool,
    #[serde(rename = "POPCNT", default = "default_true")]
    pub popcnt: bool,
    #[serde(rename = "RDRAND", default = "default_true")]
    pub rdrand: bool,
    #[serde(rename = "RDSEED", default = "default_true")]
    pub rdseed: bool,
    #[serde(rename = "BMI1", default = "default_true")]
    pub bmi1: bool,
    #[serde(rename = "BMI2", default = "default_true")]
    pub bmi2: bool,
    #[serde(rename = "ADX", default = "default_true")]
    pub adx: bool,
    #[serde(rename = "SHA", default = "default_true")]
    pub sha: bool,
    #[serde(rename = "CLMUL", default = "default_true")]
    pub clmul: bool,
    #[serde(rename = "F16C", default = "default_true")]
    pub f16c: bool,
    #[serde(rename = "MOVBE", default = "default_true")]
    pub movbe: bool,
    #[serde(rename = "LZCNT", default = "default_true")]
    pub lzcnt: bool,
    #[serde(rename = "ABM", default = "default_true")]
    pub abm: bool,
    #[serde(rename = "TSX", default)]
    pub tsx: bool,
    #[serde(rename = "SGX", default)]
    pub sgx: bool,
    #[serde(rename = "VAES", default = "default_true")]
    pub vaes: bool,
    #[serde(rename = "VPCLMULQDQ", default = "default_true")]
    pub vpclmulqdq: bool,
    #[serde(rename = "AVX_VNNI", default = "default_true")]
    pub avx_vnni: bool,
}

fn default_true() -> bool { true }

impl Default for CpuFeatures {
    fn default() -> Self {
        Self {
            sse: true, sse2: true, sse3: true, ssse3: true,
            sse4_1: true, sse4_2: true, avx: true, avx2: true,
            avx512f: false, avx512bw: false, avx512vl: false,
            fma: true, aes_ni: true, popcnt: true, rdrand: true,
            rdseed: true, bmi1: true, bmi2: true, adx: true,
            sha: true, clmul: true, f16c: true, movbe: true,
            lzcnt: true, abm: true, tsx: false, sgx: false,
            vaes: true, vpclmulqdq: true, avx_vnni: true,
        }
    }
}

// ─── GPU ────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuProfile {
    pub name: String,
    pub vendor: String,
    pub vendor_id: u32,
    pub device_id: u32,
    pub subsystem_id: u32,
    pub revision: u32,
    pub driver_version: String,
    pub vram_mb: u32,
    pub shared_memory_mb: u32,
    pub pcie_gen: u32,
    pub pcie_width: u32,
    #[serde(default)]
    pub vulkan: VulkanProfile,
    #[serde(default)]
    pub directx: DirectXProfile,
}

impl Default for GpuProfile {
    fn default() -> Self {
        Self {
            name: "NVIDIA GeForce RTX 4090".into(),
            vendor: "NVIDIA".into(),
            vendor_id: 0x10DE,
            device_id: 0x2684,
            subsystem_id: 0x16F11043,
            revision: 0xA1,
            driver_version: "560.94".into(),
            vram_mb: 24576,
            shared_memory_mb: 16384,
            pcie_gen: 4,
            pcie_width: 16,
            vulkan: VulkanProfile::default(),
            directx: DirectXProfile::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulkanProfile {
    pub api_version: String,
    pub driver_id: u32,
    pub driver_version_raw: u32,
    pub device_type: u32,
}

impl Default for VulkanProfile {
    fn default() -> Self {
        Self {
            api_version: "1.3.280".into(),
            driver_id: 4,
            driver_version_raw: 0x22800000,
            device_type: 2,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectXProfile {
    pub feature_level: String,
    pub shader_model: String,
    pub ray_tracing_tier: String,
    pub variable_rate_shading_tier: u32,
    pub mesh_shader_tier: u32,
}

impl Default for DirectXProfile {
    fn default() -> Self {
        Self {
            feature_level: "12_2".into(),
            shader_model: "6.7".into(),
            ray_tracing_tier: "1_1".into(),
            variable_rate_shading_tier: 2,
            mesh_shader_tier: 1,
        }
    }
}

// ─── Motherboard ────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MotherboardProfile {
    pub manufacturer: String,
    pub product: String,
    pub serial: String,
    pub version: String,
    pub bios_vendor: String,
    pub bios_version: String,
    pub bios_date: String,
    pub bios_mode: String,
    pub secure_boot: bool,
}

impl Default for MotherboardProfile {
    fn default() -> Self {
        Self {
            manufacturer: "ASUS".into(),
            product: "ROG MAXIMUS Z790 HERO".into(),
            serial: "MB-123456789".into(),
            version: "Rev 1.xx".into(),
            bios_vendor: "American Megatrends Inc.".into(),
            bios_version: "2403".into(),
            bios_date: "04/15/2024".into(),
            bios_mode: "UEFI".into(),
            secure_boot: true,
        }
    }
}

// ─── Storage ────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProfile {
    #[serde(default)]
    pub drives: Vec<DriveProfile>,
}

impl Default for StorageProfile {
    fn default() -> Self {
        Self {
            drives: vec![
                DriveProfile {
                    model: "Samsung SSD 990 PRO 2TB".into(),
                    serial: "S6XNNG0W123456".into(),
                    firmware: "4B2QJXD7".into(),
                    drive_type: "NVMe".into(),
                    interface: "PCIe Gen4 x4".into(),
                    capacity_gb: 2000,
                    rpm: 0,
                    smart_temperature_c: 38,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DriveProfile {
    pub model: String,
    pub serial: String,
    pub firmware: String,
    #[serde(rename = "type")]
    pub drive_type: String,
    pub interface: String,
    pub capacity_gb: u32,
    pub rpm: u32,
    pub smart_temperature_c: u32,
}

// ─── Network ────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProfile {
    #[serde(default)]
    pub adapters: Vec<NetworkAdapterProfile>,
}

impl Default for NetworkProfile {
    fn default() -> Self {
        Self {
            adapters: vec![
                NetworkAdapterProfile {
                    name: "Intel(R) Ethernet Controller I226-V".into(),
                    mac: "A8:B1:C2:D3:E4:F5".into(),
                    vendor_id: 0x8086,
                    device_id: 0x125C,
                    speed_mbps: 2500,
                    ipv4: "192.168.1.100".into(),
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkAdapterProfile {
    pub name: String,
    pub mac: String,
    pub vendor_id: u32,
    pub device_id: u32,
    pub speed_mbps: u32,
    pub ipv4: String,
}

// ─── Memory ─────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProfile {
    pub total_gb: u32,
    pub speed_mhz: u32,
    #[serde(rename = "type")]
    pub mem_type: String,
    pub channels: u32,
    pub dimm_count: u32,
    pub manufacturer: String,
    pub part_number: String,
    pub ecc: bool,
}

impl Default for MemoryProfile {
    fn default() -> Self {
        Self {
            total_gb: 64,
            speed_mhz: 5600,
            mem_type: "DDR5".into(),
            channels: 2,
            dimm_count: 2,
            manufacturer: "G.Skill".into(),
            part_number: "F5-5600J3636C16GX2-TZ5NR".into(),
            ecc: false,
        }
    }
}

// ─── PCIe ───────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcieProfile {
    #[serde(default)]
    pub devices: Vec<PcieDeviceProfile>,
}

impl Default for PcieProfile {
    fn default() -> Self {
        Self {
            devices: vec![
                PcieDeviceProfile {
                    bus: 0, device: 2, function: 0,
                    vendor_id: 0x10DE, device_id: 0x2684,
                    class_code: 0x030000,
                    link_speed: "16.0 GT/s".into(),
                    link_width: "x16".into(),
                    bar0_size_mb: 256,
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PcieDeviceProfile {
    pub bus: u32,
    pub device: u32,
    pub function: u32,
    pub vendor_id: u32,
    pub device_id: u32,
    pub class_code: u32,
    pub link_speed: String,
    pub link_width: String,
    pub bar0_size_mb: u32,
}

// ─── Monitor ────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorProfile {
    #[serde(default)]
    pub displays: Vec<DisplayProfile>,
}

impl Default for MonitorProfile {
    fn default() -> Self {
        Self {
            displays: vec![
                DisplayProfile {
                    name: "ASUS ROG Swift PG27AQN".into(),
                    manufacturer: "AUS".into(),
                    serial: "M1LMQS123456".into(),
                    resolution_x: 2560,
                    resolution_y: 1440,
                    refresh_rate_hz: 360,
                    hdr: true,
                    color_depth: 10,
                    connector: "DisplayPort 1.4".into(),
                },
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DisplayProfile {
    pub name: String,
    pub manufacturer: String,
    pub serial: String,
    pub resolution_x: u32,
    pub resolution_y: u32,
    pub refresh_rate_hz: u32,
    pub hdr: bool,
    pub color_depth: u32,
    pub connector: String,
}

// ─── TPM ────────────────────────────────────────────────────
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmProfile {
    pub present: bool,
    pub version: String,
    pub manufacturer: String,
}

impl Default for TpmProfile {
    fn default() -> Self {
        Self {
            present: true,
            version: "2.0".into(),
            manufacturer: "IFX".into(),
        }
    }
}
