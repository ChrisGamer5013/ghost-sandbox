/*
   Ghost Sandbox — x86-64 Disassembler (Minimal)
   Decodes common x86-64 instructions for the memory editor view.
*/

#[derive(Debug, Clone)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: String,
    pub operands: String,
    pub is_conditional_jump: bool,
    pub is_jump: bool,
    pub is_call: bool,
    pub is_ret: bool,
}

impl Instruction {
    pub fn display(&self) -> String {
        if self.operands.is_empty() {
            self.mnemonic.clone()
        } else {
            format!("{} {}", self.mnemonic, self.operands)
        }
    }
    
    pub fn bytes_hex(&self) -> String {
        self.bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
    }
}

/// Disassemble bytes at a given address.
/// This is a simplified decoder covering the most common instructions
/// needed for the memory editor (jumps, calls, nops, movs, rets).
pub fn disassemble(data: &[u8], base_address: u64, max_instructions: usize) -> Vec<Instruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;
    
    while offset < data.len() && instructions.len() < max_instructions {
        let addr = base_address + offset as u64;
        let remaining = &data[offset..];
        
        if remaining.is_empty() { break; }
        
        let inst = decode_instruction(remaining, addr);
        offset += inst.bytes.len();
        instructions.push(inst);
    }
    
    instructions
}

fn decode_instruction(data: &[u8], addr: u64) -> Instruction {
    if data.is_empty() {
        return unknown_inst(addr, &[]);
    }
    
    let b0 = data[0];
    
    match b0 {
        // NOP
        0x90 => Instruction {
            address: addr, bytes: vec![0x90],
            mnemonic: "nop".into(), operands: String::new(),
            is_conditional_jump: false, is_jump: false, is_call: false, is_ret: false,
        },
        
        // RET
        0xC3 => Instruction {
            address: addr, bytes: vec![0xC3],
            mnemonic: "ret".into(), operands: String::new(),
            is_conditional_jump: false, is_jump: false, is_call: false, is_ret: true,
        },
        
        // RET imm16
        0xC2 if data.len() >= 3 => {
            let imm = u16::from_le_bytes([data[1], data[2]]);
            Instruction {
                address: addr, bytes: data[..3].to_vec(),
                mnemonic: "ret".into(), operands: format!("0x{:X}", imm),
                is_conditional_jump: false, is_jump: false, is_call: false, is_ret: true,
            }
        },
        
        // Short JMP (EB)
        0xEB if data.len() >= 2 => {
            let rel = data[1] as i8;
            let target = addr.wrapping_add(2).wrapping_add(rel as u64);
            Instruction {
                address: addr, bytes: data[..2].to_vec(),
                mnemonic: "jmp".into(), operands: format!("0x{:X}", target),
                is_conditional_jump: false, is_jump: true, is_call: false, is_ret: false,
            }
        },
        
        // Short JZ/JE (74)
        0x74 if data.len() >= 2 => {
            let rel = data[1] as i8;
            let target = addr.wrapping_add(2).wrapping_add(rel as u64);
            Instruction {
                address: addr, bytes: data[..2].to_vec(),
                mnemonic: "jz".into(), operands: format!("0x{:X}", target),
                is_conditional_jump: true, is_jump: true, is_call: false, is_ret: false,
            }
        },
        
        // Short JNZ/JNE (75)
        0x75 if data.len() >= 2 => {
            let rel = data[1] as i8;
            let target = addr.wrapping_add(2).wrapping_add(rel as u64);
            Instruction {
                address: addr, bytes: data[..2].to_vec(),
                mnemonic: "jnz".into(), operands: format!("0x{:X}", target),
                is_conditional_jump: true, is_jump: true, is_call: false, is_ret: false,
            }
        },
        
        // Near JMP (E9)
        0xE9 if data.len() >= 5 => {
            let rel = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            let target = addr.wrapping_add(5).wrapping_add(rel as u64);
            Instruction {
                address: addr, bytes: data[..5].to_vec(),
                mnemonic: "jmp".into(), operands: format!("0x{:X}", target),
                is_conditional_jump: false, is_jump: true, is_call: false, is_ret: false,
            }
        },
        
        // Near CALL (E8)
        0xE8 if data.len() >= 5 => {
            let rel = i32::from_le_bytes([data[1], data[2], data[3], data[4]]);
            let target = addr.wrapping_add(5).wrapping_add(rel as u64);
            Instruction {
                address: addr, bytes: data[..5].to_vec(),
                mnemonic: "call".into(), operands: format!("0x{:X}", target),
                is_conditional_jump: false, is_jump: false, is_call: true, is_ret: false,
            }
        },
        
        // INT3
        0xCC => Instruction {
            address: addr, bytes: vec![0xCC],
            mnemonic: "int3".into(), operands: String::new(),
            is_conditional_jump: false, is_jump: false, is_call: false, is_ret: false,
        },
        
        // Two-byte opcodes (0F xx)
        0x0F if data.len() >= 2 => {
            let b1 = data[1];
            match b1 {
                // Near JZ (0F 84)
                0x84 if data.len() >= 6 => {
                    let rel = i32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                    let target = addr.wrapping_add(6).wrapping_add(rel as u64);
                    Instruction {
                        address: addr, bytes: data[..6].to_vec(),
                        mnemonic: "jz".into(), operands: format!("0x{:X}", target),
                        is_conditional_jump: true, is_jump: true, is_call: false, is_ret: false,
                    }
                },
                // Near JNZ (0F 85)
                0x85 if data.len() >= 6 => {
                    let rel = i32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                    let target = addr.wrapping_add(6).wrapping_add(rel as u64);
                    Instruction {
                        address: addr, bytes: data[..6].to_vec(),
                        mnemonic: "jnz".into(), operands: format!("0x{:X}", target),
                        is_conditional_jump: true, is_jump: true, is_call: false, is_ret: false,
                    }
                },
                // Near JL (0F 8C)
                0x8C if data.len() >= 6 => {
                    let rel = i32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                    let target = addr.wrapping_add(6).wrapping_add(rel as u64);
                    Instruction {
                        address: addr, bytes: data[..6].to_vec(),
                        mnemonic: "jl".into(), operands: format!("0x{:X}", target),
                        is_conditional_jump: true, is_jump: true, is_call: false, is_ret: false,
                    }
                },
                // Near JGE (0F 8D)
                0x8D if data.len() >= 6 => {
                    let rel = i32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                    let target = addr.wrapping_add(6).wrapping_add(rel as u64);
                    Instruction {
                        address: addr, bytes: data[..6].to_vec(),
                        mnemonic: "jge".into(), operands: format!("0x{:X}", target),
                        is_conditional_jump: true, is_jump: true, is_call: false, is_ret: false,
                    }
                },
                // Near JLE (0F 8E)
                0x8E if data.len() >= 6 => {
                    let rel = i32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                    let target = addr.wrapping_add(6).wrapping_add(rel as u64);
                    Instruction {
                        address: addr, bytes: data[..6].to_vec(),
                        mnemonic: "jle".into(), operands: format!("0x{:X}", target),
                        is_conditional_jump: true, is_jump: true, is_call: false, is_ret: false,
                    }
                },
                // Near JG (0F 8F)
                0x8F if data.len() >= 6 => {
                    let rel = i32::from_le_bytes([data[2], data[3], data[4], data[5]]);
                    let target = addr.wrapping_add(6).wrapping_add(rel as u64);
                    Instruction {
                        address: addr, bytes: data[..6].to_vec(),
                        mnemonic: "jg".into(), operands: format!("0x{:X}", target),
                        is_conditional_jump: true, is_jump: true, is_call: false, is_ret: false,
                    }
                },
                _ => unknown_inst(addr, &data[..2.min(data.len())]),
            }
        },
        
        // Everything else: show as unknown with 1 byte consumed
        _ => unknown_inst(addr, &data[..1]),
    }
}

fn unknown_inst(addr: u64, bytes: &[u8]) -> Instruction {
    let _len = bytes.len().max(1);
    Instruction {
        address: addr,
        bytes: bytes.to_vec(),
        mnemonic: "db".into(),
        operands: bytes.iter().map(|b| format!("0x{:02X}", b)).collect::<Vec<_>>().join(", "),
        is_conditional_jump: false,
        is_jump: false,
        is_call: false,
        is_ret: false,
    }
}
