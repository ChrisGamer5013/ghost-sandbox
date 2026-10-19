use egui::{DragValue, ScrollArea, CollapsingHeader};

use crate::app::SandboxApp;
use crate::pipe_server::PipeCommand;

pub fn show(ui: &mut egui::Ui, app: &mut SandboxApp) {
    let mut state = app.state.lock().unwrap();

    ui.horizontal(|ui| {
        ui.label("Current Profile:");
        ui.text_edit_singleline(&mut state.profile_path);
        if ui.button("Load").clicked() {
            match crate::profile::HardwareProfile::load_from_file(&state.profile_path) {
                Ok(p) => {
                    state.profile = p;
                    state.status_message = format!("Loaded profile from {}", state.profile_path);
                }
                Err(e) => state.status_message = e,
            }
        }
        if ui.button("Save").clicked() {
            match state.profile.save_to_file(&state.profile_path) {
                Ok(()) => {
                    state.status_message = format!("Saved profile to {}", state.profile_path)
                }
                Err(e) => state.status_message = e,
            }
        }
    });

    ui.separator();

    ScrollArea::vertical().show(ui, |ui| {
        CollapsingHeader::new("CPU").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Manufacturer:");
                ui.text_edit_singleline(&mut state.profile.cpu.manufacturer);
                ui.label("Brand String:");
                ui.text_edit_singleline(&mut state.profile.cpu.brand_string);
            });
            ui.horizontal(|ui| {
                ui.label("Family:"); ui.add(DragValue::new(&mut state.profile.cpu.family));
                ui.label("Model:"); ui.add(DragValue::new(&mut state.profile.cpu.model));
                ui.label("Stepping:"); ui.add(DragValue::new(&mut state.profile.cpu.stepping));
            });
            ui.horizontal(|ui| {
                ui.label("Cores (Physical):"); ui.add(DragValue::new(&mut state.profile.cpu.cores_physical));
                ui.label("Cores (Logical):"); ui.add(DragValue::new(&mut state.profile.cpu.cores_logical));
            });
            ui.horizontal(|ui| {
                ui.label("Base Clock (MHz):"); ui.add(DragValue::new(&mut state.profile.cpu.base_clock_mhz));
                ui.label("Max Clock (MHz):"); ui.add(DragValue::new(&mut state.profile.cpu.max_clock_mhz));
            });
            ui.horizontal(|ui| {
                ui.label("L1 Cache (KB):"); ui.add(DragValue::new(&mut state.profile.cpu.l1_cache_kb));
                ui.label("L2 Cache (KB):"); ui.add(DragValue::new(&mut state.profile.cpu.l2_cache_kb));
                ui.label("L3 Cache (KB):"); ui.add(DragValue::new(&mut state.profile.cpu.l3_cache_kb));
            });
            
            ui.label("Features:");
            ui.horizontal_wrapped(|ui| {
                ui.checkbox(&mut state.profile.cpu.features.sse, "SSE");
                ui.checkbox(&mut state.profile.cpu.features.sse2, "SSE2");
                ui.checkbox(&mut state.profile.cpu.features.sse3, "SSE3");
                ui.checkbox(&mut state.profile.cpu.features.avx, "AVX");
                ui.checkbox(&mut state.profile.cpu.features.avx2, "AVX2");
                ui.checkbox(&mut state.profile.cpu.features.avx512f, "AVX-512F");
                ui.checkbox(&mut state.profile.cpu.features.fma, "FMA");
                ui.checkbox(&mut state.profile.cpu.features.aes_ni, "AES-NI");
            });
        });

        CollapsingHeader::new("GPU").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Name:"); ui.text_edit_singleline(&mut state.profile.gpu.name);
                ui.label("Vendor:"); ui.text_edit_singleline(&mut state.profile.gpu.vendor);
                ui.label("Driver Version:"); ui.text_edit_singleline(&mut state.profile.gpu.driver_version);
            });
            ui.horizontal(|ui| {
                ui.label("Vendor ID (Hex):"); ui.add(egui::DragValue::new(&mut state.profile.gpu.vendor_id));
                ui.label("Device ID (Hex):"); ui.add(egui::DragValue::new(&mut state.profile.gpu.device_id));
                ui.label("Subsystem ID (Hex):"); ui.add(egui::DragValue::new(&mut state.profile.gpu.subsystem_id));
            });
            ui.horizontal(|ui| {
                ui.label("VRAM (MB):"); ui.add(DragValue::new(&mut state.profile.gpu.vram_mb));
                ui.label("PCIe Gen:"); ui.add(DragValue::new(&mut state.profile.gpu.pcie_gen));
                ui.label("PCIe Width:"); ui.add(DragValue::new(&mut state.profile.gpu.pcie_width));
            });
        });

        CollapsingHeader::new("Motherboard").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Manufacturer:"); ui.text_edit_singleline(&mut state.profile.motherboard.manufacturer);
                ui.label("Product:"); ui.text_edit_singleline(&mut state.profile.motherboard.product);
                ui.label("Serial:"); ui.text_edit_singleline(&mut state.profile.motherboard.serial);
            });
            ui.horizontal(|ui| {
                ui.label("BIOS Vendor:"); ui.text_edit_singleline(&mut state.profile.motherboard.bios_vendor);
                ui.label("BIOS Version:"); ui.text_edit_singleline(&mut state.profile.motherboard.bios_version);
                ui.label("BIOS Date:"); ui.text_edit_singleline(&mut state.profile.motherboard.bios_date);
            });
            ui.checkbox(&mut state.profile.motherboard.secure_boot, "Secure Boot Enabled");
        });

        CollapsingHeader::new("Storage").show(ui, |ui| {
            let mut remove_idx = None;
            for (i, drive) in state.profile.storage.drives.iter_mut().enumerate() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Model:"); ui.text_edit_singleline(&mut drive.model);
                        ui.label("Serial:"); ui.text_edit_singleline(&mut drive.serial);
                        ui.label("Size (GB):"); ui.add(DragValue::new(&mut drive.capacity_gb));
                        if ui.button("Remove").clicked() {
                            remove_idx = Some(i);
                        }
                    });
                });
            }
            if let Some(i) = remove_idx {
                state.profile.storage.drives.remove(i);
            }
            if ui.button("Add Drive").clicked() {
                state.profile.storage.drives.push(Default::default());
            }
        });

        CollapsingHeader::new("Network").show(ui, |ui| {
            let mut remove_idx = None;
            for (i, adapter) in state.profile.network.adapters.iter_mut().enumerate() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("MAC Address:"); ui.text_edit_singleline(&mut adapter.mac);
                        ui.label("Description:"); ui.text_edit_singleline(&mut adapter.name);
                        if ui.button("Remove").clicked() {
                            remove_idx = Some(i);
                        }
                    });
                });
            }
            if let Some(i) = remove_idx {
                state.profile.network.adapters.remove(i);
            }
            if ui.button("Add Adapter").clicked() {
                state.profile.network.adapters.push(Default::default());
            }
        });

        CollapsingHeader::new("Memory").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Total (GB):"); ui.add(DragValue::new(&mut state.profile.memory.total_gb));
                ui.label("Speed (MHz):"); ui.add(DragValue::new(&mut state.profile.memory.speed_mhz));
                ui.label("Type:"); ui.text_edit_singleline(&mut state.profile.memory.mem_type);
            });
            ui.horizontal(|ui| {
                ui.label("Manufacturer:"); ui.text_edit_singleline(&mut state.profile.memory.manufacturer);
                ui.label("Part Number:"); ui.text_edit_singleline(&mut state.profile.memory.part_number);
                ui.checkbox(&mut state.profile.memory.ecc, "ECC Support");
            });
        });

        CollapsingHeader::new("PCIe").show(ui, |ui| {
            let mut remove_idx = None;
            for (i, dev) in state.profile.pcie.devices.iter_mut().enumerate() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Vendor ID:"); ui.add(egui::DragValue::new(&mut dev.vendor_id));
                        ui.label("Device ID:"); ui.add(egui::DragValue::new(&mut dev.device_id));
                        if ui.button("Remove").clicked() {
                            remove_idx = Some(i);
                        }
                    });
                });
            }
            if let Some(i) = remove_idx {
                state.profile.pcie.devices.remove(i);
            }
            if ui.button("Add PCIe Device").clicked() {
                state.profile.pcie.devices.push(Default::default());
            }
        });

        CollapsingHeader::new("Monitor").show(ui, |ui| {
            let mut remove_idx = None;
            for (i, display) in state.profile.monitor.displays.iter_mut().enumerate() {
                ui.group(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("Manufacturer:"); ui.text_edit_singleline(&mut display.manufacturer);
                        ui.label("Model:"); ui.text_edit_singleline(&mut display.name);
                        if ui.button("Remove").clicked() {
                            remove_idx = Some(i);
                        }
                    });
                });
            }
            if let Some(i) = remove_idx {
                state.profile.monitor.displays.remove(i);
            }
            if ui.button("Add Display").clicked() {
                state.profile.monitor.displays.push(Default::default());
            }
        });

        CollapsingHeader::new("TPM").show(ui, |ui| {
            ui.checkbox(&mut state.profile.tpm.present, "TPM Present");
            ui.horizontal(|ui| {
                ui.label("Version:"); ui.text_edit_singleline(&mut state.profile.tpm.version);
                ui.label("Manufacturer:"); ui.text_edit_singleline(&mut state.profile.tpm.manufacturer);
            });
        });

        CollapsingHeader::new("System Identity").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label("Computer Name:"); ui.text_edit_singleline(&mut state.profile.identity.computer_name);
                ui.label("User Name:"); ui.text_edit_singleline(&mut state.profile.identity.user_name);
            });
            ui.horizontal(|ui| {
                ui.label("Machine GUID:"); ui.text_edit_singleline(&mut state.profile.identity.machine_guid);
                ui.label("Volume Serial:"); ui.text_edit_singleline(&mut state.profile.identity.volume_serial);
            });
            ui.horizontal(|ui| {
                ui.label("Windows Product ID:"); ui.text_edit_singleline(&mut state.profile.identity.windows_product_id);
            });
        });
        
        ui.add_space(16.0);
        if ui.button("Apply Live").clicked() {
            match crate::shared_profile::publish(&state.profile, state.profile_shmem) {
                Ok(handle) => {
                    state.profile_shmem = handle;
                    match app.pipe.send_command(PipeCommand::ProfileReload) {
                        Ok(()) => {
                            state.status_message =
                                "Profile published to shared memory — shim reload requested".into()
                        }
                        Err(e) => {
                            state.status_message =
                                format!("Profile published; shim reload failed: {}", e)
                        }
                    }
                }
                Err(e) => state.status_message = format!("Publish failed: {}", e),
            }
        }
    });
}
